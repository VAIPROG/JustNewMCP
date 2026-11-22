import { afterEach, beforeEach, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
import { BackgroundJobManager } from "../src/workspace/background-jobs.ts";
import { runAllowedCmdTool } from "../src/workspace/cmd-runner.ts";

const bun = basename(process.execPath);
const jobMarker = "justnewmcp-background-test-child";
const longJob = 'console.log("ready"); setInterval(() => {}, 1000);';
const rules = [
  {
    command: bun,
    allowedSubcommands: ["-e"],
    deniedArgs: ["--denied"],
    timeoutMs: 60_000,
    maxOutputChars: 30_000,
  },
];
let root: string;
let jobs: BackgroundJobManager;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "justnewmcp-background-"));
  jobs = new BackgroundJobManager();
});

afterEach(async () => {
  await jobs.stopAllBackgroundJobs();
  rmSync(root, { recursive: true, force: true });
});

async function start(script: string, timeoutMs?: number) {
  const result = await runAllowedCmdTool(
    root,
    rules,
    {
      command: bun,
      args: ["-e", script, jobMarker],
      background: true,
      timeoutMs,
    },
    jobs,
  );
  if (!("jobId" in result)) throw new Error("Expected a background job.");
  return result;
}

async function waitUntil(check: () => boolean) {
  const deadline = performance.now() + 10_000;
  while (!check()) {
    if (performance.now() >= deadline)
      throw new Error("Timed out waiting for the background job.");
    await Bun.sleep(15);
  }
}

function expectExited(pid: number) {
  expect(() => process.kill(pid, 0)).toThrow();
}

test("background execution shares the allowlist and streams both pipes into a bounded live tail", async () => {
  await expect(
    runAllowedCmdTool(
      root,
      rules,
      {
        command: join(root, bun),
        background: true,
      },
      jobs,
    ),
  ).rejects.toThrow("bare executable name");
  await expect(
    runAllowedCmdTool(
      root,
      rules,
      {
        command: bun,
        args: ["-e", "", "--denied"],
        background: true,
      },
      jobs,
    ),
  ).rejects.toThrow("not permitted");

  process.env.JUSTNEWMCP_BACKGROUND_TEST = "fixture";
  try {
    const { jobId, pid, logFile, status } = await start(`
      console.log(JSON.stringify({
        arg: process.argv[1],
        sanitized: process.env.JUSTNEWMCP_BACKGROUND_TEST === undefined,
      }));
      console.error("Café ✨");
      setInterval(() => {}, 1000);
    `);
    expect(status).toBe("running");
    expect(logFile).toMatch(/^\.justnewmcp\/logs\/cmd_.*\.log$/);
    expect(jobs.list()).toEqual([
      expect.objectContaining({
        jobId,
        pid,
        status,
        exitCode: null,
        endedAt: null,
      }),
    ]);

    await waitUntil(() => {
      const { tail } = jobs.status(jobId, 4000, [root]);
      return tail.includes("Café ✨") && tail.includes(jobMarker);
    });
    const live = jobs.status(jobId, 4000, [root]);
    expect(live.status).toBe("running");
    expect(live.tail).toContain(
      JSON.stringify({ arg: jobMarker, sanitized: true }),
    );
    const shortTail = jobs.status(jobId, 7, [root]).tail;
    expect(shortTail).toBe(live.tail.slice(-7));
    if (process.platform !== "win32") {
      expect(statSync(join(root, logFile)).mode & 0o777).toBe(0o600);
    }

    const [stopped, duplicate] = await Promise.all([
      jobs.stop(jobId, 2000),
      jobs.stop(jobId, 0),
    ]);
    expect(stopped).toMatchObject({
      status: "stopped",
      endedAt: expect.any(String),
    });
    expect(duplicate).toEqual(stopped);
    expect(await jobs.stop(jobId, 0)).toEqual(stopped);
    expectExited(pid);
  } finally {
    delete process.env.JUSTNEWMCP_BACKGROUND_TEST;
  }
}, 15_000);

test.skipIf(process.platform === "win32")(
  "the server waits for background jobs when it receives SIGTERM",
  async () => {
    const fixture = fileURLToPath(
      new URL("./fixtures/background-signal-server.ts", import.meta.url),
    );
    let jobPid: number | undefined;
    const server = Bun.spawn(
      [process.execPath, fixture, root, longJob, jobMarker],
      {
        ipc(message: { status: string; pid: number }) {
          if (
            message.status === "running" &&
            Number.isSafeInteger(message.pid) &&
            message.pid > 0
          ) {
            jobPid = message.pid;
          }
        },
        stdout: "inherit",
        stderr: "inherit",
      },
    );

    try {
      await waitUntil(() => {
        if (server.exitCode !== null || server.signalCode !== null) {
          throw new Error(
            "Server fixture exited before starting a background job.",
          );
        }
        return jobPid !== undefined;
      });
      server.kill("SIGTERM");
      expect(await server.exited).toBe(143);
      expectExited(jobPid!);
      jobPid = undefined;
    } finally {
      if (server.exitCode === null && server.signalCode === null)
        server.kill("SIGTERM");
      await server.exited;
      if (jobPid !== undefined) {
        try {
          process.kill(jobPid, "SIGKILL");
        } catch {
          // The server may already have stopped the child.
        }
      }
    }
  },
  15_000,
);

test("enforces the running-job limit, permits reuse, and stops every child at shutdown", async () => {
  const active = await Promise.all(
    Array.from({ length: 10 }, () => start(longJob)),
  );
  await expect(start(longJob)).rejects.toThrow("10 running jobs");
  expect(readdirSync(join(root, ".justnewmcp", "logs"))).toHaveLength(10);
  await jobs.stop(active[0]!.jobId, 0);
  const replacement = await start(longJob);
  await jobs.stopAllBackgroundJobs();
  expect(jobs.list().every((job) => job.status === "stopped")).toBe(true);
  for (const { pid } of [...active, replacement]) expectExited(pid);
  await expect(start(longJob)).rejects.toThrow("shutting down");
}, 15_000);

test("drains past the hard log cap and preserves the command exit code", async () => {
  const { jobId, pid, logFile } = await start(`
    const chunk = Buffer.alloc(512 * 1024, "x");
    for (let i = 0; i < 24; i++) {
      const stream = i % 2 ? process.stderr : process.stdout;
      await new Promise((resolve) => stream.write(chunk, resolve));
    }
    process.exitCode = 23;
  `);
  await waitUntil(() => jobs.list()[0]?.status !== "running");
  expect(jobs.status(jobId, 30_000, [root])).toMatchObject({
    status: "failed",
    exitCode: 23,
    outputTruncated: true,
    tail: "x".repeat(30_000),
  });
  expect(statSync(join(root, logFile)).size).toBe(10 * 1024 * 1024);
  expectExited(pid);
}, 15_000);

test("escalates on POSIX when a process ignores SIGTERM", async () => {
  if (process.platform === "win32") return;
  const { jobId, pid } = await start(
    `process.on("SIGTERM", () => {}); ${longJob}`,
  );
  await waitUntil(() => jobs.status(jobId, 100, [root]).tail.includes("ready"));
  const stopped = await jobs.stop(jobId, 50);
  expect(stopped.status).toBe("stopped");
  expectExited(pid);
}, 15_000);

test("enforces the allowed command timeout for a background job", async () => {
  const { jobId, pid } = await start(longJob, 100);
  await waitUntil(() => jobs.list()[0]?.status !== "running");
  expect(jobs.status(jobId, 100, [root]).status).toBe("timed_out");
  expectExited(pid);
}, 15_000);

test("evicts the oldest completed record and keeps new jobs queryable", async () => {
  const first = await start("process.exitCode = 0;");
  await waitUntil(() => jobs.list()[0]?.status === "completed");
  for (let i = 0; i < 10; i++) {
    const batch = await Promise.all(
      Array.from({ length: 10 }, () => start("process.exitCode = 0;")),
    );
    await waitUntil(() =>
      jobs.list().every(({ status }) => status === "completed"),
    );
    expect(jobs.status(batch[0]!.jobId, 10, [root]).exitCode).toBe(0);
  }
  expect(jobs.list()).toHaveLength(100);
  expect(() => jobs.status(first.jobId, 10, [root])).toThrow("not found");
  await expect(jobs.stop(first.jobId, 0)).rejects.toThrow("not found");
}, 30_000);

test("rejects a linked log directory and reading a substituted log file", async () => {
  const outside = mkdtempSync(join(tmpdir(), "justnewmcp-background-outside-"));
  try {
    const metaDir = join(root, ".justnewmcp");
    const logsDir = join(metaDir, "logs");
    symlinkSync(outside, metaDir, "junction");
    await expect(start(longJob)).rejects.toThrow("must not be a symlink");
    rmSync(metaDir);

    mkdirSync(metaDir);
    symlinkSync(outside, logsDir, "junction");
    await expect(start(longJob)).rejects.toThrow("must not be a symlink");
    expect(readdirSync(outside)).toEqual([]);
    rmSync(logsDir);

    const { jobId, logFile, pid } = await start(longJob);
    await jobs.stop(jobId, 0);
    const log = join(root, logFile);
    const substitute = join(outside, "substitute");
    await Bun.write(substitute, "unrelated content");
    rmSync(log);
    symlinkSync(substitute, log, "file");
    expect(() => jobs.status(jobId, 100, [root])).toThrow();
    expect(readFileSync(substitute, "utf8")).toBe("unrelated content");
    expectExited(pid);
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
}, 15_000);

async function authorizedMcp(
  baseUrl: string,
  clientId: string,
  clientSecret: string,
  approvalCode: string,
) {
  const verifier = generateRandomToken(48);
  const redirectUri = "http://127.0.0.1/callback";
  const authorize = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    code_challenge: computePkceS256(verifier),
    code_challenge_method: "S256",
    response_type: "code",
  });
  const form = await fetch(`${baseUrl}/oauth/authorize?${authorize}`);
  expect(form.status).toBe(200);
  const csrf = (await form.text()).match(
    /name="csrf_token"\s+value="([^"]+)"/,
  )?.[1];
  const cookie = form.headers.get("set-cookie")?.split(";")[0];
  expect(csrf).toBeTruthy();
  expect(cookie).toBeTruthy();
  authorize.set("csrf_token", csrf!);
  authorize.set("approval_code", approvalCode);
  const approval = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: { Cookie: cookie! },
    body: authorize,
    redirect: "manual",
  });
  expect(approval.status).toBe(302);
  const code = new URL(approval.headers.get("location")!).searchParams.get(
    "code",
  );
  const tokens = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      code: code!,
      code_verifier: verifier,
    }),
  });
  expect(tokens.status).toBe(200);
  const { access_token } = (await tokens.json()) as { access_token: string };

  return async (name: string, args: Record<string, unknown> = {}) => {
    const response = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name, arguments: args },
      }),
    });
    expect(response.status).toBe(200);
    const { result } = (await response.json()) as {
      result: { isError?: boolean; content: Array<{ text: string }> };
    };
    const text = result.content[0]!.text;
    return result.isError ? { error: text } : JSON.parse(text);
  };
}

test("authenticated MCP starts and stops background commands, respects plan mode, and drains on HTTP server stop", async () => {
  const clientId = "background-fixture-client";
  const clientSecret = "background-fixture-secret";
  const approvalCode = "TEST-1234-5678";
  const running = createAppServer(
    ConfigSchema.parse({
      port: 0,
      publicUrl: "https://mcp.example.com",
      allowedRoots: [root],
      allowedCommands: rules,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: ["http://127.0.0.1/callback"],
      },
    }),
    { initialApprovalCode: approvalCode },
  );
  const baseUrl = `http://127.0.0.1:${running.server.port}`;

  try {
    const call = await authorizedMcp(
      baseUrl,
      clientId,
      clientSecret,
      approvalCode,
    );
    const command = {
      command: bun,
      args: ["-e", longJob, jobMarker],
      background: true,
    };
    expect(await call("run_allowed_cmd", command)).toMatchObject({
      error: expect.stringContaining("workspace_init"),
    });
    expect(await call("workspace_init", { path: root })).toHaveProperty(
      "workspace",
    );
    const job = await call("run_allowed_cmd", command);
    expect(typeof job.jobId).toBe("string");
    expect(typeof job.pid).toBe("number");
    expect(job.status).toBe("running");
    expect(await call("plan_enter")).toEqual({ active: true });
    expect(await call("cmd_status")).toMatchObject({
      jobs: [{ jobId: job.jobId, status: "running" }],
    });
    expect(await call("cmd_status", { job_id: job.jobId })).toMatchObject({
      jobId: job.jobId,
      tail: expect.any(String),
    });
    expect(
      await call("cmd_status", { job_id: job.jobId, tail_chars: 30_001 }),
    ).toHaveProperty("error");
    expect(await call("task_stop", { job_id: job.jobId })).toMatchObject({
      error: expect.stringContaining("read-only"),
    });
    expect(await call("run_allowed_cmd", command)).toMatchObject({
      error: expect.stringContaining("read-only"),
    });
    expect(await call("plan_exit")).toEqual({ active: false });
    expect(
      await call("task_stop", { job_id: job.jobId, grace_ms: 10_001 }),
    ).toHaveProperty("error");
    expect(await call("task_stop", { job_id: job.jobId })).toMatchObject({
      jobId: job.jobId,
      status: "stopped",
    });
    expectExited(job.pid);
    expect(running.audit.list()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "mcp.cmd.background_started",
          clientId,
          detail: job.jobId,
        }),
        expect.objectContaining({
          event: "mcp.cmd.background_stopped",
          clientId,
          detail: job.jobId,
        }),
      ]),
    );

    const second = await call("run_allowed_cmd", command);
    expect(second.status).toBe("running");
    await running.server.stop(true);
    expectExited(second.pid);
  } finally {
    await running.shutdown(true);
  }
}, 15_000);
