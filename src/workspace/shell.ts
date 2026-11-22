import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { generateRandomToken } from "../security/crypto.ts";
import { isPathInsideRoot } from "./paths.ts";

const LOGS_REL_DIR = join(".justnewmcp", "logs");
const PREVIEW_CHARS = 2000;
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;
const MAX_COMMAND_BYTES = 32 * 1024;
const POSIX = process.platform !== "win32";
const NOFOLLOW =
  POSIX && typeof fsConstants.O_NOFOLLOW === "number"
    ? fsConstants.O_NOFOLLOW
    : 0;

interface ActiveShellEntry {
  owner?: object;
  proc: Bun.Subprocess<"ignore", "pipe", "pipe">;
  abortController: AbortController;
  completion: Promise<void>;
}

const activeShellProcs = new Set<ActiveShellEntry>();

const killActiveShellsOnExit = () => {
  for (const { proc } of activeShellProcs) {
    signalProcessGroup(proc, "SIGKILL");
  }
};

export async function stopAllActiveShellProcesses(
  owner?: object,
  graceMs = 500,
): Promise<void> {
  const entries = [...activeShellProcs].filter(
    (entry) => owner === undefined || entry.owner === owner,
  );
  if (entries.length === 0) return;
  for (const { proc } of entries) {
    signalProcessGroup(proc, "SIGTERM");
  }
  await Promise.all(
    entries.map(async ({ proc, abortController, completion }) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          completion,
          new Promise<void>((resolveWait) => {
            timer = setTimeout(() => {
              signalProcessGroup(proc, "SIGKILL");
              abortController.abort();
              resolveWait();
            }, graceMs);
          }),
        ]);
        if (POSIX) {
          signalProcessGroup(proc, "SIGKILL");
        }
        abortController.abort();
        await completion;
      } finally {
        if (timer) clearTimeout(timer);
      }
    }),
  );
}

export interface RunShellInput {
  command: string;
  timeoutMs?: number;
  maxOutputChars?: number;
  allowShell: boolean;
  owner?: object;
}

export interface RunShellResult {
  shell: string;
  exitCode: number | null;
  timedOut: boolean;
  outputTruncated: boolean;
  stdout: string;
  stderr: string;
  outputFile?: string;
}

function assertNotSymlink(targetPath: string): void {
  try {
    if (lstatSync(targetPath).isSymbolicLink()) {
      throw new Error(`Log directory "${targetPath}" must not be a symlink.`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function ensureLogsDir(workspaceRoot: string): string {
  const realWorkspace = realpathSync(resolve(workspaceRoot));
  const metaDir = join(realWorkspace, ".justnewmcp");
  const logsDir = join(realWorkspace, LOGS_REL_DIR);

  assertNotSymlink(metaDir);
  assertNotSymlink(logsDir);

  mkdirSync(logsDir, { recursive: true, mode: 0o700 });

  const realLogs = realpathSync(logsDir);
  if (!isPathInsideRoot(realLogs, realWorkspace)) {
    throw new Error("Log directory resolves outside the active workspace.");
  }
  return realLogs;
}

function buildSanitizedEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (key.toUpperCase().startsWith("JUSTNEWMCP_")) continue;
    env[key] = value;
  }
  env.GIT_TERMINAL_PROMPT = "0";
  return env;
}

function resolveShellArgv(command: string): { shell: string; argv: string[] } {
  if (process.platform === "win32") {
    return {
      shell: "powershell.exe",
      argv: [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        command,
      ],
    };
  }
  const bashPath = existsSync("/bin/bash") ? "/bin/bash" : "/bin/sh";
  const flag = bashPath === "/bin/bash" ? "-lc" : "-c";
  return {
    shell: bashPath,
    argv: [bashPath, flag, command],
  };
}

function signalProcessGroup(
  proc: Bun.Subprocess<"ignore", "pipe", "pipe">,
  signal: "SIGTERM" | "SIGKILL",
): void {
  if (POSIX) {
    try {
      process.kill(-proc.pid, signal);
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ESRCH") {
        // Fall back to direct kill below
      }
    }
  }
  try {
    if (proc.exitCode === null && proc.signalCode === null) {
      proc.kill(signal);
    }
  } catch {
    // Process may have already exited
  }
}

async function readStreamBounded(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
  signal: AbortSignal,
): Promise<{ text: string; hitHardCap: boolean }> {
  if (!stream) return { text: "", hitHardCap: false };
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let hitHardCap = false;

  const onAbort = () => {
    reader.cancel().catch(() => {});
  };
  if (signal.aborted) {
    onAbort();
  } else {
    signal.addEventListener("abort", onAbort, { once: true });
  }

  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      if (total < maxBytes) {
        if (total + value.byteLength > maxBytes) {
          const remaining = maxBytes - total;
          chunks.push(value.subarray(0, remaining));
          total += remaining;
          hitHardCap = true;
        } else {
          chunks.push(value);
          total += value.byteLength;
        }
      } else {
        hitHardCap = true;
      }
    }
  } catch {
    // Stream may close abruptly after forced kill or abort
  } finally {
    signal.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { text: new TextDecoder("utf-8").decode(merged), hitHardCap };
}

export async function runShellTool(
  workspaceRoot: string,
  input: RunShellInput,
): Promise<RunShellResult> {
  if (!input.allowShell) {
    throw new Error(
      "run_shell is disabled. Set allowShell: true in config to enable.",
    );
  }
  if (!input.command.trim()) {
    throw new Error("Shell command must not be empty.");
  }
  if (input.command.includes("\0")) {
    throw new Error("Shell command must not contain NUL bytes.");
  }
  if (Buffer.byteLength(input.command, "utf8") > MAX_COMMAND_BYTES) {
    throw new Error(`Shell command exceeds ${MAX_COMMAND_BYTES} bytes.`);
  }

  const timeoutMs = Math.max(100, Math.min(input.timeoutMs ?? 30_000, 600_000));
  const maxOutputChars = Math.max(
    1024,
    Math.min(input.maxOutputChars ?? 30_000, 150_000),
  );
  const { shell, argv } = resolveShellArgv(input.command);

  const proc = Bun.spawn(argv, {
    cwd: workspaceRoot,
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: buildSanitizedEnv(),
    detached: POSIX,
  });

  let timedOut = false;
  const abortController = new AbortController();
  const completionDeferred = Promise.withResolvers<void>();
  const activeEntry: ActiveShellEntry = {
    owner: input.owner,
    proc,
    abortController,
    completion: completionDeferred.promise,
  };
  if (activeShellProcs.size === 0) {
    process.on("exit", killActiveShellsOnExit);
  }
  activeShellProcs.add(activeEntry);
  let killTimer: ReturnType<typeof setTimeout> | undefined;

  const timer = setTimeout(() => {
    timedOut = true;
    signalProcessGroup(proc, "SIGTERM");
    killTimer = setTimeout(() => {
      signalProcessGroup(proc, "SIGKILL");
      abortController.abort();
    }, 150);
  }, timeoutMs);

  const exitPromise = Promise.race([
    proc.exited,
    new Promise<null>((resolveExit) => {
      abortController.signal.addEventListener(
        "abort",
        () => {
          setTimeout(() => resolveExit(null), 150);
        },
        { once: true },
      );
    }),
  ]);

  const [stdoutRes, stderrRes, exitCode] = await Promise.all([
    readStreamBounded(proc.stdout, MAX_CAPTURE_BYTES, abortController.signal),
    readStreamBounded(proc.stderr, MAX_CAPTURE_BYTES, abortController.signal),
    exitPromise,
  ]).finally(() => {
    clearTimeout(timer);
    if (killTimer) clearTimeout(killTimer);
    if (POSIX) {
      signalProcessGroup(proc, "SIGKILL");
    }
    activeShellProcs.delete(activeEntry);
    if (activeShellProcs.size === 0) {
      process.off("exit", killActiveShellsOnExit);
    }
    completionDeferred.resolve();
  });

  const totalChars = stdoutRes.text.length + stderrRes.text.length;
  if (
    totalChars <= maxOutputChars &&
    !stdoutRes.hitHardCap &&
    !stderrRes.hitHardCap
  ) {
    return {
      shell,
      exitCode,
      timedOut,
      outputTruncated: false,
      stdout: stdoutRes.text,
      stderr: stderrRes.text,
    };
  }

  const logsDir = ensureLogsDir(workspaceRoot);
  const logName = `shell_${Date.now().toString(36)}_${generateRandomToken(6)}.log`;
  const logPath = join(logsDir, logName);
  const fullPayload = `=== STDOUT ===\n${stdoutRes.text}\n\n=== STDERR ===\n${stderrRes.text}\n`;

  const fd = openSync(
    logPath,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      fsConstants.O_TRUNC |
      NOFOLLOW,
    0o600,
  );
  try {
    if (POSIX) {
      fchmodSync(fd, 0o600);
    }
    writeFileSync(fd, fullPayload, "utf8");
  } finally {
    closeSync(fd);
  }

  return {
    shell,
    exitCode,
    timedOut,
    outputTruncated: true,
    stdout: stdoutRes.text.slice(0, PREVIEW_CHARS),
    stderr: stderrRes.text.slice(0, PREVIEW_CHARS),
    outputFile: relative(workspaceRoot, logPath).replaceAll("\\", "/"),
  };
}
