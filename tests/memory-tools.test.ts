import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import { computePkceS256, generateRandomToken } from "../src/security/crypto.ts";
import { memoryReadTool, memorySearchTool, memoryWriteTool } from "../src/workspace/memory.ts";

describe("project memory tools (memory_read, memory_write, memory_search)", () => {
  let baseDir: string;
  let workspaceDir: string;
  let centralMemoryRoot: string;
  let outsideDir: string;

  beforeAll(() => {
    baseDir = mkdtempSync(join(tmpdir(), "justnewmcp-mem-"));
    workspaceDir = join(baseDir, "repo");
    centralMemoryRoot = join(baseDir, "JustNewMCP-Memory");
    outsideDir = join(baseDir, "outside");
    mkdirSync(workspaceDir, { recursive: true });
    mkdirSync(centralMemoryRoot, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    writeFileSync(join(outsideDir, "secret.md"), "OUTSIDE_SECRET\n", "utf8");
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("writes, appends, reads, and searches workspace-local memory with 0700/0600 permissions", async () => {
    const written = await memoryWriteTool(workspaceDir, undefined, {
      content: "# Project Memory\nSee how-to-use-user-machine/INDEX.md.\n",
    });
    expect(written.path).toBe("MEMORY.md");
    expect(written.mode).toBe("overwrite");

    const appended = await memoryWriteTool(workspaceDir, undefined, {
      path: "MEMORY.md",
      content: "Bun >= 1.4.0 required.\n",
      mode: "append",
    });
    expect(appended.mode).toBe("append");

    const topic = await memoryWriteTool(workspaceDir, undefined, {
      path: "how-to-use-user-machine/INDEX.md",
      content: "# Machine Guide\nUse bun test --check.\n",
    });
    expect(topic.path).toBe("how-to-use-user-machine/INDEX.md");

    if (process.platform !== "win32") {
      expect(statSync(written.memoryDir).mode & 0o777).toBe(0o700);
      expect(statSync(join(written.memoryDir, "MEMORY.md")).mode & 0o777).toBe(0o600);
      expect(statSync(join(written.memoryDir, "how-to-use-user-machine")).mode & 0o777).toBe(0o700);
    }

    const readIndex = await memoryReadTool(workspaceDir, undefined, { path: "MEMORY.md", offset: 1, limit: 10 });
    expect(readIndex.totalLines).toBe(3);
    expect(readIndex.content).toContain("3 | Bun >= 1.4.0 required.");

    const searchRes = await memorySearchTool(workspaceDir, undefined, {
      pattern: "bun test",
      caseInsensitive: true,
    });
    expect(searchRes.matches).toEqual(["how-to-use-user-machine/INDEX.md:2:Use bun test --check."]);
  });

  test("supports centralized memoryDir/<slug>/ layout", async () => {
    const res = await memoryWriteTool(workspaceDir, centralMemoryRoot, {
      path: "deploy/NOTES.md",
      content: "Deploy behind Cloudflare Tunnel.\n",
    });
    expect(res.memoryDir.startsWith(centralMemoryRoot)).toBe(true);

    const readBack = await memoryReadTool(workspaceDir, centralMemoryRoot, { path: "deploy/NOTES.md" });
    expect(readBack.content).toContain("Deploy behind Cloudflare Tunnel.");
  });

  test("rejects traversal, absolute paths, and symlink escapes inside memory directory", async () => {
    await expect(memoryReadTool(workspaceDir, undefined, { path: "../secret.md" })).rejects.toThrow("traversal");
    await expect(memoryWriteTool(workspaceDir, undefined, { path: "/tmp/evil.md", content: "x" })).rejects.toThrow(
      "relative path",
    );

    const memDir = join(workspaceDir, ".justnewmcp", "memory");
    symlinkSync(join(outsideDir, "secret.md"), join(memDir, "linked.md"));
    await expect(memoryReadTool(workspaceDir, undefined, { path: "linked.md" })).rejects.toThrow("symlink");
    await expect(memoryWriteTool(workspaceDir, undefined, { path: "linked.md", content: "pwn" })).rejects.toThrow(
      "symlink",
    );

    const search = await memorySearchTool(workspaceDir, undefined, { pattern: "OUTSIDE_SECRET" });
    expect(search.matches).toEqual([]);
  });

  test("MCP /mcp enforces plan mode blocking on memory_write while allowing memory_read and memory_search", async () => {
    const clientId = "mem-e2e-client";
    const clientSecret = "mem-e2e-secret-value-123456";
    const approvalCode = "MEM0-1234-5678";
    const redirectUri = "http://127.0.0.1/callback";
    const running = createAppServer(
      ConfigSchema.parse({
        port: 0,
        publicUrl: "https://mcp.example.com",
        allowedRoots: [baseDir],
        oauth: { clientId, clientSecret, allowedRedirectUris: [redirectUri] },
      }),
      { initialApprovalCode: approvalCode },
    );
    const baseUrl = `http://127.0.0.1:${running.server.port}`;

    try {
      const verifier = generateRandomToken(48);
      const challenge = computePkceS256(verifier);
      const formRes = await fetch(
        `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
      );
      const csrfToken = (await formRes.text()).match(/name="csrf_token"\s+value="([^"]+)"/)?.[1] ?? "";
      const cookie = formRes.headers.get("set-cookie")?.split(";")[0] ?? "";
      const approveRes = await fetch(`${baseUrl}/oauth/authorize`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie },
        body: new URLSearchParams({
          csrf_token: csrfToken,
          client_id: clientId,
          redirect_uri: redirectUri,
          code_challenge: challenge,
          approval_code: approvalCode,
        }),
        redirect: "manual",
      });
      const code = new URL(approveRes.headers.get("location") ?? "").searchParams.get("code") ?? "";
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

      const call = async (name: string, args: Record<string, unknown> = {}) => {
        const res = await fetch(`${baseUrl}/mcp`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
        });
        return ((await res.json()) as { result: { isError?: boolean; content: Array<{ text: string }> } }).result;
      };

      expect((await call("workspace_init", { path: workspaceDir })).isError).toBeUndefined();
      expect((await call("plan_enter", { summary: "Check memory" })).isError).toBeUndefined();

      // memory_write must be blocked in plan mode, while memory_read and memory_search succeed
      const blockedWrite = await call("memory_write", { path: "plan.md", content: "blocked" });
      expect(blockedWrite.isError).toBe(true);
      expect(blockedWrite.content[0]?.text).toContain("Plan mode is active");

      const allowedRead = await call("memory_read", { path: "MEMORY.md" });
      expect(allowedRead.isError).toBeUndefined();
      const allowedSearch = await call("memory_search", { pattern: "Project Memory" });
      expect(allowedSearch.isError).toBeUndefined();

      expect((await call("plan_exit")).isError).toBeUndefined();
      const okWrite = await call("memory_write", { path: "notes.md", content: "Allowed after plan_exit\n" });
      expect(okWrite.isError).toBeUndefined();
    } finally {
      running.server.stop(true);
    }
  });
});
