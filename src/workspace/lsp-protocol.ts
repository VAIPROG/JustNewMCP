import type { LspServerConfig } from "../config.ts";

const MAX_HEADER_BYTES = 4096;
const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const MAX_PENDING_MESSAGES = 32;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function record(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return;
  return value as Record<string, unknown>;
}

export function encodeLspFrame(message: unknown): Uint8Array {
  const payload = encoder.encode(JSON.stringify(message));
  if (payload.length > MAX_FRAME_BYTES)
    throw new Error("LSP message exceeds the frame limit.");
  const header = encoder.encode(`Content-Length: ${payload.length}\r\n\r\n`);
  const bytes = new Uint8Array(header.length + payload.length);
  bytes.set(header);
  bytes.set(payload, header.length);
  return bytes;
}

export class LspFrameReader {
  private readonly header = new Uint8Array(MAX_HEADER_BYTES);
  private headerLength = 0;
  private body: Uint8Array | undefined;
  private bodyLength = 0;

  push(chunk: Uint8Array, receive: (message: unknown) => void): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (this.body) {
        const length = Math.min(
          this.body.length - this.bodyLength,
          chunk.length - offset,
        );
        this.body.set(chunk.subarray(offset, offset + length), this.bodyLength);
        this.bodyLength += length;
        offset += length;
        if (this.bodyLength === this.body.length) {
          const payload = this.body;
          this.body = undefined;
          this.bodyLength = 0;
          receive(JSON.parse(decoder.decode(payload)));
        }
        continue;
      }

      if (this.headerLength === this.header.length)
        throw new Error("Oversized LSP header.");
      const byte = chunk[offset++]!;
      if (byte > 127) throw new Error("Non-ASCII LSP header.");
      this.header[this.headerLength++] = byte;
      const end = this.headerLength;
      if (
        end >= 4 &&
        this.header[end - 4] === 13 &&
        this.header[end - 3] === 10 &&
        this.header[end - 2] === 13 &&
        this.header[end - 1] === 10
      ) {
        this.body = new Uint8Array(this.contentLength(end - 4));
        this.headerLength = 0;
      }
    }
  }

  private contentLength(end: number): number {
    let length: number | undefined;
    for (const line of decoder
      .decode(this.header.subarray(0, end))
      .split("\r\n")) {
      const field = /^([A-Za-z0-9-]+):[ \t]*(.*)$/.exec(line);
      if (!field) throw new Error("Malformed LSP header.");
      const name = field[1]!.toLowerCase();
      const value = field[2]!.trim();
      if (name === "content-length") {
        if (length !== undefined || !/^\d+$/.test(value))
          throw new Error("Invalid LSP Content-Length.");
        length = Number(value);
      }
      if (name === "content-type") {
        const charset = /(?:^|;)\s*charset\s*=\s*([^;]+)/i
          .exec(value)?.[1]
          ?.trim();
        if (charset && !/^"?utf-?8"?$/i.test(charset))
          throw new Error("Unsupported LSP encoding.");
      }
    }
    if (length === undefined || length < 1 || length > MAX_FRAME_BYTES) {
      throw new Error("Invalid LSP Content-Length.");
    }
    return length;
  }
}

type ServerProcess = Bun.Subprocess<"pipe", "pipe", "ignore">;
type Pending = {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
};

const children = new Set<ServerProcess>();
function stopChildren(): void {
  for (const child of children) signal(child, "SIGKILL");
}

function signal(child: ServerProcess, name: "SIGTERM" | "SIGKILL"): void {
  if (process.platform !== "win32") {
    try {
      process.kill(-child.pid, name);
      return;
    } catch {
      // The process group may already have exited.
    }
  }
  try {
    if (child.exitCode === null && child.signalCode === null) child.kill(name);
  } catch {
    // A child may exit between the check and the signal.
  }
}

async function waitForExit(
  exited: Promise<number>,
  milliseconds: number,
): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      exited.then(
        () => true,
        () => true,
      ),
      new Promise<false>((resolve) => {
        timer = setTimeout(() => resolve(false), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export class LspConnection {
  private readonly child: ServerProcess;
  private readonly pending = new Map<number, Pending>();
  private readonly stopped = new AbortController();
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private writeTail = Promise.resolve();
  private writes = 0;
  private nextId = 1;
  private failure: Error | undefined;
  private closing = false;
  private closePromise?: Promise<void>;

  constructor(
    private readonly config: LspServerConfig,
    workspaceRoot: string,
    private readonly notifyServerMessage: (
      method: string,
      params: unknown,
    ) => void,
    private readonly workspaceFolder: { uri: string; name: string },
  ) {
    const env = Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => !key.toUpperCase().startsWith("JUSTNEWMCP_"),
      ),
    );
    this.child = Bun.spawn([config.command, ...config.args], {
      cwd: workspaceRoot,
      stdin: "pipe",
      stdout: "pipe",
      stderr: "ignore",
      detached: process.platform !== "win32",
      env,
    });
    this.reader = this.child.stdout.getReader();
    if (children.size === 0) process.on("exit", stopChildren);
    children.add(this.child);
    const onExit = () => {
      if (process.platform !== "win32") signal(this.child, "SIGKILL");
      children.delete(this.child);
      if (children.size === 0) process.off("exit", stopChildren);
      this.fail(new Error("Language server exited."));
      void this.reader.cancel().catch(() => {});
    };
    void this.child.exited.then(onExit, onExit);
    void this.readMessages();
  }

  get usable(): boolean {
    return !this.closing && !this.failure;
  }

  get stopSignal(): AbortSignal {
    return this.stopped.signal;
  }

  request(
    method: string,
    params?: unknown,
    timeout = this.config.requestTimeoutMs,
  ): Promise<unknown> {
    if (this.failure) return Promise.reject(this.failure);
    if (this.closing && method !== "shutdown")
      return Promise.reject(new Error("Language server is shutting down."));
    if (this.pending.size >= MAX_PENDING_MESSAGES)
      return Promise.reject(new Error("Too many pending LSP requests."));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => this.fail(new Error(`LSP request timed out: ${method}.`)),
        timeout,
      );
      this.pending.set(id, { resolve, reject, timer });
      void this.write({ jsonrpc: "2.0", id, method, params }, timeout).catch(
        (err) => {
          this.fail(err);
        },
      );
    });
  }

  notify(
    method: string,
    params?: unknown,
    timeout = this.config.requestTimeoutMs,
  ): Promise<void> {
    if (this.closing && method !== "exit")
      return Promise.reject(new Error("Language server is shutting down."));
    return this.write({ jsonrpc: "2.0", method, params }, timeout);
  }

  close(graceful = false): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closing = true;
    this.stopped.abort();
    this.rejectPending(new Error("Language server is shutting down."));
    this.closePromise = this.stop(graceful);
    return this.closePromise;
  }

  private async stop(graceful: boolean): Promise<void> {
    const { exited, stdin } = this.child;
    if (graceful && !this.failure) {
      try {
        await this.request("shutdown", undefined, 1000);
        await this.notify("exit", undefined, 250);
        void Promise.resolve(stdin.end()).catch(() => {});
        if (await waitForExit(exited, 250)) return;
      } catch {
        // Continue with signal-based shutdown when the server stops responding.
      }
    }
    signal(this.child, "SIGTERM");
    if (await waitForExit(exited, 250)) return;
    signal(this.child, "SIGKILL");
    await exited.catch(() => {});
  }

  private fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    this.rejectPending(error);
    void this.close();
  }

  private rejectPending(error: Error): void {
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    this.pending.clear();
  }

  private async write(message: unknown, timeout: number): Promise<void> {
    if (this.failure) throw this.failure;
    if (this.writes >= MAX_PENDING_MESSAGES)
      throw new Error("Too many queued LSP messages.");
    const frame = encodeLspFrame(message);
    this.writes++;
    const send = this.writeTail.then(async () => {
      if (this.failure) throw this.failure;
      await this.child.stdin.write(frame);
      await this.child.stdin.flush();
    });
    this.writeTail = send.catch(() => {});
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        send,
        new Promise<never>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error("Language server stdin timed out.")),
            timeout,
          );
        }),
      ]);
    } catch {
      const error =
        this.failure ?? new Error("Unable to write to language server stdin.");
      this.fail(error);
      throw error;
    } finally {
      clearTimeout(timer);
      this.writes--;
    }
  }

  private async readMessages(): Promise<void> {
    const frames = new LspFrameReader();
    try {
      for (;;) {
        const { done, value } = await this.reader.read();
        if (done) {
          if (!this.closing)
            this.fail(new Error("Language server closed stdout."));
          break;
        }
        frames.push(value, (message) => this.dispatch(message));
      }
    } catch {
      this.fail(new Error("Language server sent an invalid LSP message."));
    } finally {
      this.reader.releaseLock();
    }
  }

  private dispatch(payload: unknown): void {
    if (this.failure) return;
    const message = record(payload);
    if (!message || message.jsonrpc !== "2.0")
      throw new Error("Invalid JSON-RPC version.");
    const { id, method, params, result, error } = message;
    if (typeof method === "string") {
      if (id === undefined) this.notifyServerMessage(method, params);
      else if (typeof id === "number" || typeof id === "string")
        this.reply(id, method, params);
      else throw new Error("Invalid JSON-RPC request ID.");
      return;
    }
    if (typeof id !== "number" || "result" in message === "error" in message) {
      throw new Error("Invalid JSON-RPC response.");
    }
    const pending = this.pending.get(id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(id);
    if (error !== undefined) {
      const code = record(error)?.code;
      pending.reject(
        new Error(
          Number.isSafeInteger(code)
            ? `Language server request failed (code ${code}).`
            : "Language server request failed.",
        ),
      );
    } else {
      pending.resolve(result);
    }
  }

  private reply(id: number | string, method: string, params: unknown): void {
    let result: unknown;
    switch (method) {
      case "workspace/configuration": {
        const items = record(params)?.items;
        result =
          Array.isArray(items) && items.length <= 256
            ? items.map(() => null)
            : null;
        break;
      }
      case "workspace/workspaceFolders":
        result = [this.workspaceFolder];
        break;
      case "window/workDoneProgress/create":
      case "workspace/diagnostic/refresh":
        result = null;
        break;
      case "workspace/applyEdit":
        result = { applied: false };
        break;
      default:
        void this.write(
          {
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: "Method not supported" },
          },
          this.config.requestTimeoutMs,
        ).catch((err) => this.fail(err));
        return;
    }
    void this.write(
      { jsonrpc: "2.0", id, result },
      this.config.requestTimeoutMs,
    ).catch((err) => this.fail(err));
  }
}
