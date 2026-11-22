import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
import { runShellTool } from "../src/workspace/shell.ts";

async function authorizedClient(
  baseUrl: string,
  clientId: string,
  clientSecret: string,
  approvalCode: string,
) {
  const verifier = generateRandomToken(48);
  const redirectUri = "http://127.0.0.1/callback";
  const challenge = computePkceS256(verifier);
  const formRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
  );
  const csrfToken =
    (await formRes.text()).match(/name="csrf_token"\s+value="([^"]+)"/)?.[1] ??
    "";
  const cookie = formRes.headers.get("set-cookie")?.split(";")[0] ?? "";
  const approveRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookie,
    },
    body: new URLSearchParams({
      csrf_token: csrfToken,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      approval_code: approvalCode,
    }),
    redirect: "manual",
  });
  const code =
    new URL(approveRes.headers.get("location") ?? "").searchParams.get(
      "code",
    ) ?? "";
  const tokRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  const { access_token } = (await tokRes.json()) as { access_token: string };

  const request = async (method: string, params?: Record<string, unknown>) => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return (await res.json()) as {
      result?: {
        tools?: Array<{ name: string }>;
        isError?: boolean;
        content?: Array<{ text: string }>;
      };
    };
  };

  return {
    listTools: async () =>
      (await request("tools/list")).result?.tools?.map((t) => t.name) ?? [],
    call: async (name: string, args: Record<string, unknown> = {}) =>
      (await request("tools/call", { name, arguments: args })).result!,
  };
}

describe("opt-in local shell tool (run_shell)", () => {
  let baseDir: string;
  let workspaceDir: string;
  let outsideDir: string;

  beforeAll(() => {
    baseDir = realpathSync(mkdtempSync(join(tmpdir(), "justnewmcp-shell-")));
    workspaceDir = join(baseDir, "repo");
    outsideDir = join(baseDir, "outside");
    mkdirSync(workspaceDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("rejects execution when allowShell is false and runs sanitized shell commands when enabled", async () => {
    await expect(
      runShellTool(workspaceDir, { command: "echo hi", allowShell: false }),
    ).rejects.toThrow("disabled");

    process.env.JUSTNEWMCP_SHELL_SECRET = "do-not-leak";
    try {
      const cmd =
        process.platform === "win32"
          ? 'Write-Output "hello-shell"; Write-Output "secret=$env:JUSTNEWMCP_SHELL_SECRET"'
          : 'printf "hello-shell\\nsecret=%s\\n" "$JUSTNEWMCP_SHELL_SECRET"';
      const res = await runShellTool(workspaceDir, {
        command: cmd,
        allowShell: true,
      });
      expect(res.exitCode).toBe(0);
      expect(res.timedOut).toBe(false);
      expect(res.outputTruncated).toBe(false);
      expect(res.stdout).toContain("hello-shell");
      expect(res.stdout).toContain("secret=");
      expect(res.stdout).not.toContain("do-not-leak");
    } finally {
      delete process.env.JUSTNEWMCP_SHELL_SECRET;
    }
  });

  test("kills timed-out shell commands and spills oversized logs to .justnewmcp/logs with 0600 mode", async () => {
    const sleepCmd =
      process.platform === "win32" ? "Start-Sleep -Seconds 5" : "sleep 5 | cat";
    const timed = await runShellTool(workspaceDir, {
      command: sleepCmd,
      timeoutMs: 150,
      allowShell: true,
    });
    expect(timed.timedOut).toBe(true);

    const bigCmd =
      process.platform === "win32"
        ? 'Write-Output ("A" * 6000)'
        : "head -c 6000 /dev/zero | tr '\\0' 'A'";
    const spilled = await runShellTool(workspaceDir, {
      command: bigCmd,
      maxOutputChars: 1024,
      allowShell: true,
    });
    expect(spilled.outputTruncated).toBe(true);
    expect(spilled.outputFile).toMatch(/^\.justnewmcp\/logs\/shell_.*\.log$/);
    const fullLogPath = join(workspaceDir, spilled.outputFile!);
    expect(existsSync(fullLogPath)).toBe(true);
    expect(readFileSync(fullLogPath, "utf8")).toContain("A".repeat(4000));
    if (process.platform !== "win32") {
      expect(statSync(fullLogPath).mode & 0o777).toBe(0o600);
    }

    // Symlinked .justnewmcp/logs must be rejected when spilling
    const symWs = join(baseDir, "sym-shell-ws");
    mkdirSync(join(symWs, ".justnewmcp"), { recursive: true });
    symlinkSync(
      outsideDir,
      join(symWs, ".justnewmcp", "logs"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      runShellTool(symWs, {
        command: bigCmd,
        maxOutputChars: 1024,
        allowShell: true,
      }),
    ).rejects.toThrow("must not be a symlink");
  });

  test("MCP /mcp hides and rejects run_shell by default, and enforces plan mode + audit logging when opted in", async () => {
    const clientId = "shell-e2e-client";
    const clientSecret = "shell-e2e-secret-value-123456";
    const approvalCode = "SH00-1234-5678";

    // 1. Default config (allowShell: false)
    const disabledServer = createAppServer(
      ConfigSchema.parse({
        port: 0,
        publicUrl: "https://mcp.example.com",
        allowedRoots: [baseDir],
        oauth: {
          clientId,
          clientSecret,
          allowedRedirectUris: ["http://127.0.0.1/callback"],
        },
      }),
      { initialApprovalCode: approvalCode },
    );
    try {
      const client = await authorizedClient(
        `http://127.0.0.1:${disabledServer.server.port}`,
        clientId,
        clientSecret,
        approvalCode,
      );
      expect(await client.listTools()).not.toContain("run_shell");
      await client.call("workspace_init", { path: workspaceDir });
      const denied = await client.call("run_shell", { command: "echo hi" });
      expect(denied.isError).toBe(true);
      expect(denied.content?.[0]?.text).toContain("disabled");
    } finally {
      await disabledServer.shutdown(true);
    }

    // 2. Opt-in config (allowShell: true)
    const enabledServer = createAppServer(
      ConfigSchema.parse({
        port: 0,
        publicUrl: "https://mcp.example.com",
        allowedRoots: [baseDir],
        allowShell: true,
        oauth: {
          clientId,
          clientSecret,
          allowedRedirectUris: ["http://127.0.0.1/callback"],
        },
      }),
      { initialApprovalCode: approvalCode },
    );
    try {
      const client = await authorizedClient(
        `http://127.0.0.1:${enabledServer.server.port}`,
        clientId,
        clientSecret,
        approvalCode,
      );
      expect(await client.listTools()).toContain("run_shell");
      await client.call("workspace_init", { path: workspaceDir });

      // Blocked in read-only plan mode
      await client.call("plan_enter");
      const planBlocked = await client.call("run_shell", {
        command: "echo blocked",
      });
      expect(planBlocked.isError).toBe(true);
      expect(planBlocked.content?.[0]?.text).toContain("Plan mode is active");
      await client.call("plan_exit");

      // Succeeds after plan_exit and records audit event
      const okRes = await client.call("run_shell", {
        command:
          process.platform === "win32"
            ? 'Write-Output "opt-in-ok"'
            : 'echo "opt-in-ok"',
      });
      expect(okRes.isError).toBeUndefined();
      expect(okRes.content?.[0]?.text).toContain("opt-in-ok");
      expect(
        enabledServer.audit
          .list()
          .some(
            (e) => e.event === "mcp.shell.called" && e.clientId === clientId,
          ),
      ).toBe(true);
    } finally {
      await enabledServer.shutdown(true);
    }
  });
});
