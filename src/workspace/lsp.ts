import { constants, statSync } from "node:fs";
import { open } from "node:fs/promises";
import { basename, extname, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { LspServerSchema, type LspServerConfig } from "../config.ts";
import { LspConnection, record } from "./lsp-protocol.ts";
import {
  assertWorkspaceAnchored,
  INTERNAL_PROTECTED_PATTERNS,
  isPathDenied,
  isPathInsideRoot,
  resolveInsideRoots,
} from "./paths.ts";

const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_OPEN_DOCUMENTS = 64;
const MAX_DIAGNOSTIC_FILES = 128;
const MAX_DIAGNOSTICS_PER_FILE = 200;
const MAX_CACHED_DIAGNOSTICS = 2000;
const MAX_PARALLEL_OPERATIONS = 16;
const MAX_INSPECTED_LOCATIONS = 5000;

interface Position {
  line: number;
  character: number;
}

interface Location extends Position {
  path: string;
  endLine: number;
  endCharacter: number;
}

export interface LspDiagnostic extends Position {
  path: string;
  severity?: "error" | "warning" | "information" | "hint";
  code?: string | number;
  source?: string;
  message: string;
}

interface Document {
  uri: string;
  version: number;
  mtime: number;
  hash: bigint;
  end: Position;
}

interface DiagnosticReport {
  version?: number;
  resultId?: string;
  items: Omit<LspDiagnostic, "path">[];
}

const severityNames = ["error", "warning", "information", "hint"] as const;

function position(value: unknown): Position | undefined {
  const pos = record(value);
  const line = pos?.line;
  const character = pos?.character;
  if (
    typeof line !== "number" ||
    !Number.isSafeInteger(line) ||
    line < 0 ||
    line >= 2 ** 31 ||
    typeof character !== "number" ||
    !Number.isSafeInteger(character) ||
    character < 0 ||
    character >= 2 ** 31
  )
    return;
  return { line, character };
}

function diagnosticText(value: string, limit: number): string {
  // URI fields never reach this function. Remove file references embedded in display strings too.
  return value
    .slice(0, limit * 2)
    .replace(
      /file:\/\/[^\s<>"']+|(?:[A-Za-z]:[\\/]|\\\\|(?<![:/\w])\/)[^\s<>"']+/gi,
      "[path]",
    )
    .slice(0, limit);
}

function normalizeDiagnostics(input: unknown): DiagnosticReport["items"] {
  if (!Array.isArray(input)) return [];
  const items: DiagnosticReport["items"] = [];
  for (const entry of input.slice(0, MAX_DIAGNOSTICS_PER_FILE)) {
    const item = record(entry);
    const start = position(record(item?.range)?.start);
    if (!item || !start || typeof item.message !== "string") continue;
    const severity =
      typeof item.severity === "number"
        ? severityNames[item.severity - 1]
        : undefined;
    const code =
      typeof item.code === "string"
        ? diagnosticText(item.code, 100)
        : Number.isSafeInteger(item.code)
          ? (item.code as number)
          : undefined;
    const source =
      typeof item.source === "string"
        ? diagnosticText(item.source, 100)
        : undefined;
    items.push({
      line: start.line + 1,
      character: start.character + 1,
      severity,
      code,
      source,
      message: diagnosticText(item.message, 1500),
    });
  }
  return items;
}

class WorkspaceFiles {
  constructor(
    readonly root: string,
    private readonly denied: string[],
  ) {}

  resolve(input: string): string {
    const candidate = resolve(this.root, input);
    if (!isPathInsideRoot(candidate, this.root)) {
      throw new Error("File is outside the active workspace.");
    }
    if (isPathDenied(candidate, this.denied)) {
      throw new Error("File is blocked by workspace security policy.");
    }
    assertWorkspaceAnchored(this.root, [this.root]);
    const { resolvedPath } = resolveInsideRoots(
      candidate,
      [this.root],
      process.platform,
      this.denied,
    );
    return resolvedPath;
  }

  fromUri(value: unknown): string | undefined {
    if (
      typeof value !== "string" ||
      value.length > 16_384 ||
      !/^file:\/\//i.test(value)
    )
      return;
    try {
      const uri = new URL(value);
      if (
        uri.protocol !== "file:" ||
        uri.search ||
        uri.hash ||
        uri.username ||
        uri.password
      )
        return;
      const path = this.resolve(fileURLToPath(uri));
      if (statSync(path).isFile()) return path;
    } catch {
      // Ignore invalid, missing, denied, or out-of-workspace server locations.
    }
  }

  relative(path: string): string {
    return relative(this.root, path)
      .split(process.platform === "win32" ? "\\" : "/")
      .join("/");
  }

  async read(
    path: string,
  ): Promise<{ text: string; mtime: number; hash: bigint }> {
    const flags =
      process.platform === "win32"
        ? constants.O_RDONLY
        : constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
    const file = await open(path, flags);
    try {
      const before = await file.stat();
      if (!before.isFile()) throw new Error("LSP requires a regular file.");
      if (before.size > MAX_DOCUMENT_BYTES)
        throw new Error("File exceeds the LSP document size limit.");
      const data = Buffer.alloc(before.size + 1);
      let offset = 0;
      while (offset < data.length) {
        const { bytesRead } = await file.read(
          data,
          offset,
          data.length - offset,
          offset,
        );
        if (!bytesRead) break;
        offset += bytesRead;
      }
      const current = statSync(this.resolve(path));
      if (
        current.dev !== before.dev ||
        current.ino !== before.ino ||
        current.size !== before.size ||
        current.mtimeMs !== before.mtimeMs ||
        offset !== before.size
      ) {
        throw new Error(
          "File changed while preparing the LSP document. Retry the request.",
        );
      }
      const bytes = data.subarray(0, offset);
      return {
        text: new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        mtime: before.mtimeMs,
        hash: Bun.hash(bytes),
      };
    } finally {
      await file.close();
    }
  }
}

function lastPosition(text: string): Position {
  let line = 0;
  let lineStart = 0;
  for (const newline of text.matchAll(/\r\n|\r|\n/g)) {
    line++;
    lineStart = newline.index + newline[0].length;
  }
  return { line, character: text.length - lineStart };
}

class LspSession {
  readonly connection: LspConnection;
  private readonly ready: Promise<void>;
  private initialized = false;
  private active = 0;
  private idleTimer?: ReturnType<typeof setTimeout>;
  private documentQueue = Promise.resolve();
  private readonly documents = new Map<string, Document>();
  private readonly reports = new Map<string, DiagnosticReport>();
  private cachedCount = 0;
  private nextDocumentVersion = 1;
  private readonly listeners = new Map<string, Set<() => void>>();
  private openClose = false;
  private change = 0;
  private pull = false;

  constructor(
    private readonly files: WorkspaceFiles,
    private readonly config: LspServerConfig,
  ) {
    const folder = {
      uri: pathToFileURL(files.root).href,
      name: basename(files.root),
    };
    this.connection = new LspConnection(
      config,
      files.root,
      (method, params) => {
        if (method === "textDocument/publishDiagnostics") this.publish(params);
      },
      folder,
    );
    this.connection.stopSignal.addEventListener(
      "abort",
      () => {
        clearTimeout(this.idleTimer);
        this.documents.clear();
        this.reports.clear();
        this.cachedCount = 0;
      },
      { once: true },
    );
    this.ready = this.initialize(folder).catch((error) => {
      void this.connection.close();
      throw error;
    });
  }

  async use<T>(operation: () => Promise<T>): Promise<T> {
    if (this.active >= MAX_PARALLEL_OPERATIONS)
      throw new Error("Too many active LSP operations.");
    this.active++;
    clearTimeout(this.idleTimer);
    try {
      await this.ready;
      return await operation();
    } finally {
      this.active--;
      if (this.active === 0 && this.connection.usable) {
        this.idleTimer = setTimeout(() => {
          void this.close();
        }, this.config.idleTimeoutMs);
      }
    }
  }

  close(): Promise<void> {
    clearTimeout(this.idleTimer);
    return this.connection.close(this.initialized);
  }

  async navigate(
    method: "definition" | "references",
    path: string,
    line: number,
    character: number,
    limit: number,
    includeDeclaration: boolean,
  ): Promise<Location[]> {
    const document = await this.sync(path);
    const result = await this.connection.request(`textDocument/${method}`, {
      textDocument: { uri: document.uri },
      position: { line: line - 1, character: character - 1 },
      ...(method === "references" ? { context: { includeDeclaration } } : {}),
    });
    if (this.documents.get(path)?.version !== document.version) {
      throw new Error(
        "LSP document changed during navigation. Retry the request.",
      );
    }
    const candidates = Array.isArray(result) ? result : [result];
    const locations: Location[] = [];
    for (const candidate of candidates.slice(0, MAX_INSPECTED_LOCATIONS)) {
      const value = record(candidate);
      if (!value) continue;
      const path = this.files.fromUri(value.targetUri ?? value.uri);
      const range = record(
        value.targetSelectionRange ?? value.targetRange ?? value.range,
      );
      const start = position(range?.start);
      const end = position(range?.end);
      if (
        !path ||
        !start ||
        !end ||
        end.line < start.line ||
        (end.line === start.line && end.character < start.character)
      )
        continue;
      locations.push({
        path: this.files.relative(path),
        line: start.line + 1,
        character: start.character + 1,
        endLine: end.line + 1,
        endCharacter: end.character + 1,
      });
      if (locations.length >= limit) break;
    }
    return locations;
  }

  async diagnostics(path: string, limit: number): Promise<LspDiagnostic[]> {
    const document = await this.sync(path);
    if (this.pull) {
      const previousResultId = this.reports.get(path)?.resultId;
      const result = record(
        await this.connection.request("textDocument/diagnostic", {
          textDocument: { uri: document.uri },
          previousResultId,
        }),
      );
      if (
        result?.kind === "full" &&
        this.documents.get(path)?.version === document.version
      ) {
        this.setReport(path, {
          version: document.version,
          resultId:
            typeof result.resultId === "string" &&
            result.resultId.length <= 1024
              ? result.resultId
              : undefined,
          items: normalizeDiagnostics(result.items),
        });
      }
    } else if (!this.reports.has(path)) {
      await this.waitForDiagnostics(path);
    }
    return this.cachedDiagnostics(limit, path);
  }

  cachedDiagnostics(limit: number, path?: string): LspDiagnostic[] {
    const output: LspDiagnostic[] = [];
    const entries =
      path === undefined
        ? this.reports
        : [[path, this.reports.get(path)] as const];
    for (const [filename, report] of entries) {
      if (
        !report ||
        this.files.fromUri(pathToFileURL(filename).href) !== filename
      )
        continue;
      const current = this.documents.get(filename);
      if (
        current &&
        report.version !== undefined &&
        report.version !== current.version
      )
        continue;
      for (const item of report.items) {
        output.push({ path: this.files.relative(filename), ...item });
        if (output.length >= limit) return output;
      }
    }
    return output;
  }

  private async initialize(folder: {
    uri: string;
    name: string;
  }): Promise<void> {
    const result = record(
      await this.connection.request("initialize", {
        processId: process.pid,
        rootUri: folder.uri,
        workspaceFolders: [folder],
        capabilities: {
          general: { positionEncodings: ["utf-16"] },
          workspace: { configuration: true, workspaceFolders: true },
          textDocument: {
            definition: { linkSupport: true },
            publishDiagnostics: { versionSupport: true },
            diagnostic: { relatedDocumentSupport: false },
          },
        },
      }),
    );
    const capabilities = record(result?.capabilities);
    if (!capabilities)
      throw new Error("Language server did not return capabilities.");
    if (
      capabilities.positionEncoding &&
      capabilities.positionEncoding !== "utf-16"
    ) {
      throw new Error("Language server did not negotiate UTF-16 positions.");
    }
    const sync = record(capabilities.textDocumentSync);
    this.change =
      typeof capabilities.textDocumentSync === "number"
        ? capabilities.textDocumentSync
        : typeof sync?.change === "number"
          ? sync.change
          : 0;
    this.openClose =
      sync?.openClose === true ||
      (typeof capabilities.textDocumentSync === "number" && this.change > 0);
    this.pull = Boolean(capabilities.diagnosticProvider);
    await this.connection.notify("initialized", {});
    this.initialized = true;
  }

  private sync(path: string): Promise<Document> {
    const update = this.documentQueue.then(() => this.syncDocument(path));
    this.documentQueue = update.then(
      () => {},
      () => {},
    );
    return update;
  }

  private async syncDocument(path: string): Promise<Document> {
    if (!this.connection.usable)
      throw new Error("Language server is unavailable.");
    const { text, hash, mtime } = await this.files.read(path);
    if (!this.connection.usable)
      throw new Error("Language server is unavailable.");
    const current = this.documents.get(path);
    if (current) this.documents.delete(path);
    if (current && current.mtime === mtime && current.hash === hash) {
      this.documents.set(path, current);
      return current;
    }

    if (this.documents.size >= MAX_OPEN_DOCUMENTS) {
      const [oldPath, oldDocument] = this.documents.entries().next().value!;
      this.documents.delete(oldPath);
      this.deleteReport(oldPath);
      if (this.openClose)
        await this.connection.notify("textDocument/didClose", {
          textDocument: { uri: oldDocument.uri },
        });
    }

    const document = {
      uri: pathToFileURL(path).href,
      version: this.nextDocumentVersion++,
      mtime,
      hash,
      end: lastPosition(text),
    };
    this.documents.set(path, document);
    this.deleteReport(path);
    const { uri, version } = document;
    if (current && (this.change === 1 || this.change === 2)) {
      await this.connection.notify("textDocument/didChange", {
        textDocument: { uri, version },
        contentChanges:
          this.change === 2
            ? [
                {
                  range: { start: { line: 0, character: 0 }, end: current.end },
                  text,
                },
              ]
            : [{ text }],
      });
    } else if (this.openClose) {
      if (current)
        await this.connection.notify("textDocument/didClose", {
          textDocument: { uri },
        });
      await this.connection.notify("textDocument/didOpen", {
        textDocument: {
          uri,
          languageId: this.config.languageId,
          version,
          text,
        },
      });
    }
    return document;
  }

  private publish(params: unknown): void {
    const notification = record(params);
    if (!Array.isArray(notification?.diagnostics)) return;
    const path = this.files.fromUri(notification.uri);
    if (!path || this.reports.get(path)?.resultId !== undefined) return;
    const version =
      typeof notification.version === "number"
        ? notification.version
        : undefined;
    const currentVersion = this.documents.get(path)?.version;
    if (
      version !== undefined &&
      currentVersion !== undefined &&
      version !== currentVersion
    )
      return;
    this.setReport(path, {
      version: version ?? currentVersion,
      items: normalizeDiagnostics(notification.diagnostics),
    });
  }

  private setReport(path: string, report: DiagnosticReport): void {
    this.deleteReport(path);
    this.reports.set(path, report);
    this.cachedCount += report.items.length;
    while (
      this.reports.size > MAX_DIAGNOSTIC_FILES ||
      this.cachedCount > MAX_CACHED_DIAGNOSTICS
    ) {
      this.deleteReport(this.reports.keys().next().value!);
    }
    for (const wake of this.listeners.get(path) ?? []) wake();
  }

  private deleteReport(path: string): void {
    this.cachedCount -= this.reports.get(path)?.items.length ?? 0;
    this.reports.delete(path);
  }

  private async waitForDiagnostics(path: string): Promise<void> {
    const signal = this.connection.stopSignal;
    if (signal.aborted)
      throw new Error("Language server stopped before publishing diagnostics.");
    const watchers = this.listeners.get(path) ?? new Set<() => void>();
    this.listeners.set(path, watchers);
    const ready = Promise.withResolvers<void>();
    const onStop = () =>
      ready.reject(
        new Error("Language server stopped before publishing diagnostics."),
      );
    signal.addEventListener("abort", onStop, { once: true });
    watchers.add(ready.resolve);
    const timer = setTimeout(ready.resolve, this.config.requestTimeoutMs);
    try {
      await ready.promise;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", onStop);
      watchers.delete(ready.resolve);
      if (watchers.size === 0) this.listeners.delete(path);
    }
  }
}

export class LspManager {
  private readonly byExtension = new Map<string, LspServerConfig>();
  private readonly sessions = new Map<LspServerConfig, LspSession>();
  private readonly denied: string[];
  private root?: string;
  private generation = 0;
  private closed = false;
  private teardown = Promise.resolve();

  constructor(servers: LspServerConfig[] = [], denied: string[] = []) {
    for (const entry of servers) {
      const config = LspServerSchema.parse(entry);
      for (const extension of config.extensions) {
        const key = extension.replace(/^\./, "").toLowerCase();
        if (!this.byExtension.has(key)) this.byExtension.set(key, config);
      }
    }
    this.denied = [...denied, ...INTERNAL_PROTECTED_PATTERNS];
  }

  async navigate(
    root: string,
    method: "definition" | "references",
    input: string,
    line: number,
    character: number,
    limit: number,
    includeDeclaration = true,
  ): Promise<Location[]> {
    const { session, path } = await this.documentSession(root, input);
    return session.use(() =>
      session.navigate(
        method,
        path,
        line,
        character,
        limit,
        includeDeclaration,
      ),
    );
  }

  async diagnostics(
    root: string,
    input: string | undefined,
    limit: number,
  ): Promise<LspDiagnostic[]> {
    if (input !== undefined) {
      const { session, path } = await this.documentSession(root, input);
      return session.use(() => session.diagnostics(path, limit));
    }
    if (this.root !== root || this.closed) return [];
    const items: LspDiagnostic[] = [];
    for (const session of this.sessions.values()) {
      if (!session.connection.usable) continue;
      items.push(...session.cachedDiagnostics(limit - items.length));
      if (items.length >= limit) break;
    }
    return items;
  }

  reset(): Promise<void> {
    this.generation++;
    this.root = undefined;
    this.teardown = Promise.all([
      this.teardown,
      ...Array.from(this.sessions.values(), (session) => session.close()),
    ]).then(() => {});
    this.sessions.clear();
    return this.teardown;
  }

  shutdown(): Promise<void> {
    this.closed = true;
    return this.reset();
  }

  private async documentSession(
    root: string,
    input: string,
  ): Promise<{ session: LspSession; path: string }> {
    const generation = this.generation;
    const files = new WorkspaceFiles(root, this.denied);
    const path = files.resolve(input);
    const config = this.byExtension.get(extname(path).slice(1).toLowerCase());
    if (!config)
      throw new Error(
        "No language server is configured for this file extension.",
      );

    await this.teardown;
    for (;;) {
      if (
        this.closed ||
        generation !== this.generation ||
        (this.root && this.root !== root)
      ) {
        throw new Error(
          "LSP workspace changed or the server is shutting down.",
        );
      }
      this.root = root;
      const current = this.sessions.get(config);
      if (!current) {
        const session = new LspSession(files, config);
        this.sessions.set(config, session);
        return { session, path };
      }
      if (current.connection.usable) return { session: current, path };
      await current.close();
      if (this.sessions.get(config) === current) this.sessions.delete(config);
    }
  }
}
