import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import type { AllowedCommandRule } from "../config.ts";
import { generateRandomToken } from "../security/crypto.ts";
import { isPathInsideRoot } from "./paths.ts";

const LOGS_REL_DIR = join(".justnewmcp", "logs");
const PREVIEW_CHARS = 2000;
const MAX_CAPTURE_BYTES = 10 * 1024 * 1024;

export interface RunAllowedCmdInput {
  command: string;
  args?: string[];
  timeoutMs?: number;
}

export interface RunAllowedCmdResult {
  command: string;
  args: string[];
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
  if (process.platform !== "win32") {
    chmodSync(logsDir, 0o700);
  }

  const realLogs = realpathSync(logsDir);
  if (!isPathInsideRoot(realLogs, realWorkspace)) {
    throw new Error("Log directory resolves outside the active workspace.");
  }
  return realLogs;
}

function matchCommandRule(
  command: string,
  args: string[],
  rules: AllowedCommandRule[],
): AllowedCommandRule {
  if (
    command.includes("/") ||
    command.includes("\\") ||
    command.includes("\0")
  ) {
    throw new Error(`Command "${command}" must be a bare executable name.`);
  }

  const candidates = rules.filter((r) =>
    process.platform === "win32"
      ? r.command.toLowerCase() === command.toLowerCase()
      : r.command === command,
  );
  if (candidates.length === 0) {
    throw new Error(`Command "${command}" is not in allowedCommands.`);
  }

  for (const rule of candidates) {
    if (rule.allowedSubcommands && rule.allowedSubcommands.length > 0) {
      const sub = args[0];
      if (!sub || !rule.allowedSubcommands.includes(sub)) {
        continue;
      }
    }

    const denied = rule.deniedArgs.some((pattern) => {
      const glob = new Bun.Glob(pattern);
      return args.some((arg) => glob.match(arg));
    });
    if (denied) {
      continue;
    }

    if (rule.allowedArgs && rule.allowedArgs.length > 0) {
      const argGlobs = rule.allowedArgs.map((p) => new Bun.Glob(p));
      const allAllowed = args.every((arg) =>
        argGlobs.some((g) => g.match(arg)),
      );
      if (!allAllowed) {
        continue;
      }
    }

    return rule;
  }

  throw new Error(
    `Arguments for command "${command}" are not permitted by allowedCommands rules.`,
  );
}

function buildSanitizedEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (key.startsWith("JUSTNEWMCP_")) continue;
    env[key] = value;
  }
  env.GIT_TERMINAL_PROMPT = "0";
  return env;
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
        // Keep draining and discarding excess bytes so the child process does not hit EPIPE
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

export async function runAllowedCmdTool(
  workspaceRoot: string,
  rules: AllowedCommandRule[],
  input: RunAllowedCmdInput,
): Promise<RunAllowedCmdResult> {
  const args = input.args ?? [];
  for (const arg of args) {
    if (arg.includes("\0")) {
      throw new Error("Command arguments must not contain NUL bytes.");
    }
  }

  const rule = matchCommandRule(input.command, args, rules);
  const timeoutMs = Math.min(input.timeoutMs ?? rule.timeoutMs, rule.timeoutMs);

  const proc = Bun.spawn([rule.command, ...args], {
    cwd: workspaceRoot,
    stdout: "pipe",
    stderr: "pipe",
    env: buildSanitizedEnv(),
  });

  let timedOut = false;
  const abortController = new AbortController();
  let killTimer: ReturnType<typeof setTimeout> | undefined;

  const timer = setTimeout(() => {
    timedOut = true;
    try {
      proc.kill("SIGTERM");
    } catch {
      // Process may have already exited
    }
    killTimer = setTimeout(() => {
      try {
        proc.kill("SIGKILL");
      } catch {
        // Process may have already exited
      }
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
  });

  const totalChars = stdoutRes.text.length + stderrRes.text.length;
  if (
    totalChars <= rule.maxOutputChars &&
    !stdoutRes.hitHardCap &&
    !stderrRes.hitHardCap
  ) {
    return {
      command: rule.command,
      args,
      exitCode,
      timedOut,
      outputTruncated: false,
      stdout: stdoutRes.text,
      stderr: stderrRes.text,
    };
  }

  const logsDir = ensureLogsDir(workspaceRoot);
  const logName = `cmd_${Date.now().toString(36)}_${generateRandomToken(6)}.log`;
  const logPath = join(logsDir, logName);
  const fullPayload = `=== STDOUT ===\n${stdoutRes.text}\n\n=== STDERR ===\n${stderrRes.text}\n`;

  writeFileSync(logPath, fullPayload, { encoding: "utf8", mode: 0o600 });
  if (process.platform !== "win32") {
    chmodSync(logPath, 0o600);
  }

  return {
    command: rule.command,
    args,
    exitCode,
    timedOut,
    outputTruncated: true,
    stdout: stdoutRes.text.slice(0, PREVIEW_CHARS),
    stderr: stderrRes.text.slice(0, PREVIEW_CHARS),
    outputFile: relative(workspaceRoot, logPath).replaceAll("\\", "/"),
  };
}
