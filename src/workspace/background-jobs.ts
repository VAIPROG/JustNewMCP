import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { assertWorkspaceAnchored } from "./paths.ts";

const MAX_RUNNING_JOBS = 10;
const MAX_COMPLETED_JOBS = 100;
const MAX_LOG_BYTES = 10 * 1024 * 1024;
const EXIT_DRAIN_MS = 500;
const POSIX = process.platform !== "win32";
const NOFOLLOW = POSIX ? constants.O_NOFOLLOW : 0;

type JobProcess = Bun.Subprocess<"ignore", "pipe", "pipe">;
type StopReason = "stopped" | "timed_out";
type JobStatus = "running" | "completed" | "failed" | StopReason;

export interface BackgroundJobMetadata {
  jobId: string;
  command: string;
  args: string[];
  pid: number;
  status: JobStatus;
  exitCode: number | null;
  startedAt: string;
  endedAt: string | null;
  logFile: string;
  outputTruncated: boolean;
}

export type BackgroundJobStart = Pick<
  BackgroundJobMetadata,
  "jobId" | "command" | "args" | "pid" | "logFile" | "startedAt"
> & { status: "running" };

interface JobRecord {
  metadata: BackgroundJobMetadata;
  workspaceRoot: string;
  name: string;
  identity: { dev: number; ino: number };
}

interface RunningJob extends JobRecord {
  proc: JobProcess;
  completion: Promise<void>;
  stopping?: Promise<void>;
  stopReason?: StopReason;
}

function checkedLogsDirectory(root: string, create: boolean): string {
  const metaDir = join(root, ".justnewmcp");
  const logsDir = join(metaDir, "logs");

  for (const dir of [metaDir, logsDir]) {
    if (create) {
      try {
        mkdirSync(dir, { mode: 0o700 });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      }
    }
    if (!lstatSync(dir).isDirectory()) {
      throw new Error(
        `Log directory "${dir}" must be a directory and must not be a symlink.`,
      );
    }
  }
  return assertWorkspaceAnchored(logsDir, [root]);
}

function sendSignal(proc: JobProcess, signal: "SIGTERM" | "SIGKILL"): void {
  if (POSIX) {
    try {
      // POSIX jobs run in their own group, so wrappers and their children receive the signal.
      process.kill(-proc.pid, signal);
      return;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
    }
  }
  if (proc.exitCode === null && proc.signalCode === null) proc.kill(signal);
}

function snapshot(record: JobRecord): BackgroundJobMetadata {
  return { ...record.metadata, args: [...record.metadata.args] };
}

async function drain(
  stream: ReadableStream<Uint8Array>,
  signal: AbortSignal,
  append: (chunk: Uint8Array) => void,
): Promise<void> {
  const reader = stream.getReader();
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      append(value);
    }
  } finally {
    signal.removeEventListener("abort", cancel);
    reader.releaseLock();
  }
}

export class BackgroundJobManager {
  private readonly running = new Map<string, RunningJob>();
  private readonly completed = new Map<string, JobRecord>();
  private closing = false;
  private readonly killOnExit = () => {
    for (const { proc } of this.running.values()) {
      try {
        sendSignal(proc, "SIGKILL");
      } catch {
        // Continue signalling other children during process teardown.
      }
    }
  };

  start(
    workspaceRoot: string,
    command: string,
    args: string[],
    timeoutMs: number,
    spawn: () => JobProcess,
  ): BackgroundJobStart {
    if (this.closing) throw new Error("The server is shutting down.");
    if (this.running.size >= MAX_RUNNING_JOBS) {
      throw new Error(
        `Background job limit reached (${MAX_RUNNING_JOBS} running jobs).`,
      );
    }

    const jobId = crypto.randomUUID();
    const name = `cmd_${jobId}.log`;
    const logPath = join(checkedLogsDirectory(workspaceRoot, true), name);
    const fd = openSync(
      logPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_TRUNC |
        NOFOLLOW,
      0o600,
    );

    let proc: JobProcess;
    let identity: JobRecord["identity"];
    try {
      if (POSIX) fchmodSync(fd, 0o600);
      const { dev, ino } = fstatSync(fd);
      identity = { dev, ino };
      proc = spawn();
    } catch (err) {
      closeSync(fd);
      try {
        unlinkSync(logPath);
      } catch {
        // Preserve the original startup error.
      }
      throw err;
    }

    const started: BackgroundJobStart = {
      jobId,
      command,
      args: [...args],
      pid: proc.pid,
      status: "running",
      logFile: `.justnewmcp/logs/${name}`,
      startedAt: new Date().toISOString(),
    };
    const metadata: BackgroundJobMetadata = {
      ...started,
      args: [...args],
      exitCode: null,
      endedAt: null,
      outputTruncated: false,
    };
    const record: JobRecord = { metadata, workspaceRoot, name, identity };
    const job: RunningJob = {
      ...record,
      proc,
      completion: this.collect(proc, fd, metadata),
    };
    if (this.running.size === 0) process.on("exit", this.killOnExit);
    this.running.set(jobId, job);
    const deadline = setTimeout(() => {
      void this.stopRunning(job, 150, "timed_out").catch(() => {
        try {
          sendSignal(proc, "SIGKILL");
        } catch {
          // Keep tracking the child so a later stop or shutdown can retry.
        }
      });
    }, timeoutMs);
    job.completion = job.completion.finally(() => {
      clearTimeout(deadline);
      metadata.status =
        job.stopReason ?? (metadata.exitCode === 0 ? "completed" : "failed");
      metadata.endedAt = new Date().toISOString();
      this.running.delete(jobId);
      if (this.running.size === 0) process.off("exit", this.killOnExit);
      this.completed.set(jobId, record);
      if (this.completed.size > MAX_COMPLETED_JOBS) {
        const oldest = this.completed.keys().next().value!;
        this.completed.delete(oldest);
      }
    });
    return started;
  }

  list(): BackgroundJobMetadata[] {
    return [...this.running.values(), ...this.completed.values()].map(snapshot);
  }

  status(jobId: string, tailChars: number, allowedRoots: string[]) {
    const record = this.requireJob(jobId);
    const root = assertWorkspaceAnchored(record.workspaceRoot, allowedRoots);
    const logPath = join(checkedLogsDirectory(root, false), record.name);
    const fd = openSync(
      logPath,
      constants.O_RDONLY | constants.O_NONBLOCK | NOFOLLOW,
    );
    try {
      const file = fstatSync(fd);
      if (
        !file.isFile() ||
        file.dev !== record.identity.dev ||
        file.ino !== record.identity.ino
      ) {
        throw new Error("Background job log file has changed.");
      }

      const length = Math.min(file.size, tailChars * 4);
      const buffer = Buffer.alloc(length);
      const count = readSync(fd, buffer, 0, length, file.size - length);
      const text = new TextDecoder().decode(buffer.subarray(0, count), {
        stream: true,
      });
      const tail = text.slice(-tailChars).replace(/^[\uDC00-\uDFFF]/, "");
      return { ...snapshot(record), tail };
    } finally {
      closeSync(fd);
    }
  }

  async stop(jobId: string, graceMs: number): Promise<BackgroundJobMetadata> {
    const record = this.requireJob(jobId);
    const job = this.running.get(jobId);
    if (job) await this.stopRunning(job, graceMs, "stopped");
    return snapshot(record);
  }

  async stopAllBackgroundJobs(): Promise<void> {
    this.closing = true;
    await Promise.all(
      [...this.running.values()].map((job) =>
        this.stopRunning(job, 2000, "stopped"),
      ),
    );
  }

  private requireJob(jobId: string): JobRecord {
    const record = this.running.get(jobId) ?? this.completed.get(jobId);
    if (!record) throw new Error(`Background job not found: ${jobId}`);
    return record;
  }

  private stopRunning(
    job: RunningJob,
    graceMs: number,
    reason: StopReason,
  ): Promise<void> {
    if (job.stopping) return job.stopping;
    if (job.proc.exitCode !== null || job.proc.signalCode !== null) {
      return job.completion;
    }
    job.stopReason = reason;
    job.stopping = this.terminate(job, graceMs).catch((err) => {
      job.stopping = undefined;
      job.stopReason = undefined;
      throw err;
    });
    return job.stopping;
  }

  private async terminate(job: RunningJob, graceMs: number): Promise<void> {
    sendSignal(job.proc, "SIGTERM");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const escalation = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        try {
          sendSignal(job.proc, "SIGKILL");
        } catch (err) {
          reject(err);
        }
      }, graceMs);
    });
    try {
      await Promise.race([job.completion, escalation]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async collect(
    proc: JobProcess,
    fd: number,
    metadata: BackgroundJobMetadata,
  ): Promise<void> {
    const abort = new AbortController();
    let written = 0;
    let logFailed = false;
    const append = (chunk: Uint8Array) => {
      const length = Math.min(chunk.byteLength, MAX_LOG_BYTES - written);
      if (length < chunk.byteLength) metadata.outputTruncated = true;
      if (logFailed) return;
      try {
        let offset = 0;
        while (offset < length) {
          const count = writeSync(fd, chunk, offset, length - offset);
          if (count === 0) throw new Error("Log write made no progress.");
          offset += count;
          written += count;
        }
      } catch {
        logFailed = true;
        metadata.outputTruncated = true;
      }
    };
    const pipes = Promise.allSettled([
      drain(proc.stdout, abort.signal, append),
      drain(proc.stderr, abort.signal, append),
    ]);

    try {
      metadata.exitCode = await proc.exited;
    } catch {
      metadata.exitCode = null;
    } finally {
      // A descendant can still hold a pipe after the allowlisted process exits.
      if (POSIX) {
        try {
          sendSignal(proc, "SIGKILL");
        } catch {
          // Still close the log and release the pipes if a group has already changed.
        }
      }
      const drainDeadline = setTimeout(() => {
        metadata.outputTruncated = true;
        abort.abort();
      }, EXIT_DRAIN_MS);
      const reads = await pipes;
      clearTimeout(drainDeadline);
      if (reads.some(({ status }) => status === "rejected"))
        metadata.outputTruncated = true;
      try {
        closeSync(fd);
      } catch {
        metadata.outputTruncated = true;
      }
    }
  }
}
