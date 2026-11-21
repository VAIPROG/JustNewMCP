import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_ALLOWED_REDIRECT_URIS,
  DEFAULT_DENIED_PATH_PATTERNS,
  type AppConfig,
} from "../src/config.ts";
import { createAppServer, type RunningServer } from "../src/index.ts";
import { computePkceS256, generateRandomToken } from "../src/security/crypto.ts";
import { listCheckpoints, rewindCheckpoint } from "../src/workspace/checkpoints.ts";
import {
  applyEditsTool,
  globFilesTool,
  grepFilesTool,
  readFileTool,
  writeFileTool,
} from "../src/workspace/fs-tools.ts";

describe("filesystem tools and local checkpoints", () => {
  let baseDir: string;
  let workspaceDir: string;
  let outsideDir: string;

  beforeAll(() => {
    baseDir = mkdtempSync(join(tmpdir(), "justnewmcp-fs-"));
    workspaceDir = join(baseDir, "repo");
    outsideDir = join(baseDir, "outside");
    mkdirSync(join(workspaceDir, "src"), { recursive: true });
    mkdirSync(join(workspaceDir, "node_modules", "pkg"), { recursive: true });
    mkdirSync(outsideDir, { recursive: true });

    writeFileSync(
      join(workspaceDir, "src", "app.ts"),
      "const port = 3000;\nconst host = '127.0.0.1';\nexport const addr = `${host}:${port}`;\n",
      "utf8",
    );
    writeFileSync(join(workspaceDir, ".env"), "API_KEY=secret\n", "utf8");
    writeFileSync(join(workspaceDir, "node_modules", "pkg", "index.js"), "const port = 9999;\n", "utf8");
    writeFileSync(join(workspaceDir, "binary.dat"), Buffer.from([0x00, 0xff, 0x01, 0x02]));
    writeFileSync(join(outsideDir, "secret.txt"), "OUTSIDE\n", "utf8");
    symlinkSync(outsideDir, join(workspaceDir, "escape-dir"));
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("read_file returns numbered lines and blocks binaries, .env, and symlinks outside workspace", async () => {
    const tracker = new Set<string>();
    const res = await readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
      path: "src/app.ts",
      offset: 2,
      limit: 2,
    });
    expect(res.startLine).toBe(2);
    expect(res.endLine).toBe(3);
    expect(res.content).toContain("2 | const host = '127.0.0.1';");
    expect(res.hasMore).toBe(false);

    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, { path: "binary.dat" }),
    ).rejects.toThrow("binary");
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, { path: ".env" }),
    ).rejects.toThrow("blocked by security policy");
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, { path: "escape-dir/secret.txt" }),
    ).rejects.toThrow("outside allowed workspace roots");
  });

  test("edit_file enforces read-before-edit, uniqueness, and creates rewindable checkpoints", async () => {
    const tracker = new Set<string>();
    await expect(
      applyEditsTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "src/app.ts", [
        { old_string: "3000", new_string: "8787" },
      ]),
    ).rejects.toThrow("read_file before editing");

    await readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, { path: "src/app.ts" });

    const editRes = await applyEditsTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "src/app.ts", [
      { old_string: "3000", new_string: "8787" },
    ]);
    expect(editRes.replacements).toBe(1);
    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain("const port = 8787;");

    const cps = listCheckpoints(workspaceDir, 10);
    expect(cps.some((c) => c.id === editRes.checkpointId)).toBe(true);

    const rewindRes = await rewindCheckpoint(workspaceDir, editRes.checkpointId, DEFAULT_DENIED_PATH_PATTERNS);
    expect(rewindRes.action).toBe("restored");
    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain("const port = 3000;");
  });

  test("multi_edit is atomic when a later edit fails", async () => {
    const tracker = new Set<string>();
    await readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, { path: "src/app.ts" });

    await expect(
      applyEditsTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "src/app.ts", [
        { old_string: "3000", new_string: "4000" },
        { old_string: "NON_EXISTENT", new_string: "nope" },
      ]),
    ).rejects.toThrow("old_string not found");

    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain("const port = 3000;");
  });

  test("write_file creates nested files, blocks symlink-parent escapes, and rewind deletes newly created files", async () => {
    const tracker = new Set<string>();
    await expect(
      writeFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "escape-dir/pwn.txt", "bad"),
    ).rejects.toThrow("outside the active workspace");

    await expect(
      writeFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, ".justnewmcp/checkpoints/fake.json", "{}"),
    ).rejects.toThrow("blocked by security policy");

    const written = await writeFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      "src/nested/new-file.ts",
      "export const ok = true;\n",
    );
    expect(existsSync(join(workspaceDir, "src", "nested", "new-file.ts"))).toBe(true);

    const rewind = await rewindCheckpoint(workspaceDir, written.checkpointId, DEFAULT_DENIED_PATH_PATTERNS);
    expect(rewind.action).toBe("deleted");
    expect(existsSync(join(workspaceDir, "src", "nested", "new-file.ts"))).toBe(false);
  });

  test("blocks dangling symlinks, symlinked parents to denied files, and symlinked checkpoint dirs", async () => {
    const tracker = new Set<string>();

    // 1. Dangling symlink pointing to non-existent file outside workspace
    const danglingLink = join(workspaceDir, "dangling-escape.txt");
    symlinkSync(join(outsideDir, "created-via-dangling.txt"), danglingLink);
    await expect(
      writeFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "dangling-escape.txt", "pwn"),
    ).rejects.toThrow("dangling symlink");
    expect(existsSync(join(outsideDir, "created-via-dangling.txt"))).toBe(false);

    // 2. In-workspace symlink alias to .git directory
    mkdirSync(join(workspaceDir, ".git"), { recursive: true });
    writeFileSync(join(workspaceDir, ".git", "config"), "[core]\n", "utf8");
    symlinkSync(join(workspaceDir, ".git"), join(workspaceDir, "git-alias"));
    await expect(
      writeFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, "git-alias/config", "[core]\nfsmonitor=evil\n"),
    ).rejects.toThrow("blocked by security policy");

    // 3. Symlinked .justnewmcp/checkpoints directory pointing outside workspace
    const isolatedRepo = join(baseDir, "symlink-cp-repo");
    mkdirSync(join(isolatedRepo, ".justnewmcp"), { recursive: true });
    symlinkSync(outsideDir, join(isolatedRepo, ".justnewmcp", "checkpoints"));
    await expect(
      writeFileTool(isolatedRepo, DEFAULT_DENIED_PATH_PATTERNS, tracker, "hello.txt", "hi"),
    ).rejects.toThrow("must not be a symlink");
  });

  test("glob_files and grep_files skip node_modules, .env, binaries, and symlink escapes", async () => {
    const globRes = await globFilesTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, "**/*");
    expect(globRes.files).toContain("src/app.ts");
    expect(globRes.files).not.toContain(".env");
    expect(globRes.files.some((f) => f.startsWith("node_modules/"))).toBe(false);

    const grepFiles = await grepFilesTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
      pattern: "port",
      mode: "files_with_matches",
    });
    expect(grepFiles.matches).toEqual(["src/app.ts"]);

    const grepContent = await grepFilesTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
      pattern: "host",
      contextLines: 1,
      mode: "content",
    });
    expect(grepContent.matches[0]).toContain("src/app.ts:2:const host = '127.0.0.1';");
  });

  test("end-to-end MCP /mcp HTTP call flow for write_file, read_file, edit_file, and checkpoint_rewind", async () => {
    const clientId = "fs-e2e-client";
    const clientSecret = "fs-e2e-secret-value-1234567890";
    const approvalCode = "FS00-1111-2222";
    const config: AppConfig = {
      host: "127.0.0.1",
      port: 0,
      publicUrl: "https://mcp.example.com",
      trustedProxies: ["127.0.0.1", "::1"],
      allowedRoots: [baseDir],
      deniedPathPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      maxMcpBodyBytes: 1_048_576,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        rateLimit: { maxFailures: 5, windowMs: 60_000, lockoutMs: 60_000, maxTrackedIps: 1000 },
      },
    };

    const running: RunningServer = createAppServer(config, { initialApprovalCode: approvalCode });
    const baseUrl = `http://127.0.0.1:${running.server.port}`;

    try {
      const verifier = generateRandomToken(48);
      const challenge = computePkceS256(verifier);
      const redirectUri = "https://gemini.google.com/oauth/callback";
      const getAuth = await fetch(
        `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
      );
      const csrfSid = (getAuth.headers.get("set-cookie") ?? "").match(/justnewmcp_csrf_sid=([^;]+)/)?.[1] ?? "";
      const csrfToken = (await getAuth.text()).match(/name="csrf_token"\s+value="([^"]+)"/)?.[1] ?? "";

      const postAuth = await fetch(`${baseUrl}/oauth/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: `justnewmcp_csrf_sid=${csrfSid}`,
        },
        body: new URLSearchParams({
          csrf_token: csrfToken,
          client_id: clientId,
          redirect_uri: redirectUri,
          code_challenge: challenge,
          scope: "mcp:tools",
          approval_code: approvalCode,
        }),
        redirect: "manual",
      });
      const authCode = new URL(postAuth.headers.get("location") ?? "").searchParams.get("code") ?? "";
      const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: clientSecret,
          code: authCode,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });
      const { access_token } = (await tokenRes.json()) as { access_token: string };

      const callTool = async (id: number, name: string, args: Record<string, unknown>) => {
        const res = await fetch(`${baseUrl}/mcp`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
          body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }),
        });
        const json = (await res.json()) as { result: { isError?: boolean; content: Array<{ text: string }> } };
        return json.result;
      };

      const initRes = await callTool(1, "workspace_init", { path: workspaceDir });
      expect(initRes.isError).toBeUndefined();

      const writeRes = await callTool(2, "write_file", { path: "src/e2e.ts", content: "export const v = 1;\n" });
      expect(writeRes.isError).toBeUndefined();

      const editRes = await callTool(3, "edit_file", { path: "src/e2e.ts", old_string: "1", new_string: "2" });
      expect(editRes.isError).toBeUndefined();
      const editData = JSON.parse(editRes.content[0]?.text ?? "{}") as { checkpointId: string };

      const rewindRes = await callTool(4, "checkpoint_rewind", { checkpoint_id: editData.checkpointId });
      expect(rewindRes.isError).toBeUndefined();
      expect(readFileSync(join(workspaceDir, "src", "e2e.ts"), "utf8")).toBe("export const v = 1;\n");

      // Empty file reports totalLines 0 cleanly
      await callTool(5, "write_file", { path: "src/empty.ts", content: "" });
      const emptyRead = await callTool(6, "read_file", { path: "src/empty.ts" });
      const emptyData = JSON.parse(emptyRead.content[0]?.text ?? "{}") as { totalLines: number; endLine: number };
      expect(emptyData.totalLines).toBe(0);
      expect(emptyData.endLine).toBe(0);

      // Replacing active workspace with a symlink to outsideDir after workspace_init must be rejected
      const swapRepo = join(baseDir, "swap-repo");
      const movedRepo = join(baseDir, "swap-repo-moved");
      mkdirSync(swapRepo, { recursive: true });
      writeFileSync(join(swapRepo, "ok.txt"), "ok\n", "utf8");
      const swapInit = await callTool(7, "workspace_init", { path: swapRepo });
      expect(swapInit.isError).toBeUndefined();

      renameSync(swapRepo, movedRepo);
      symlinkSync(outsideDir, swapRepo);
      const swappedRead = await callTool(8, "read_file", { path: "secret.txt" });
      expect(swappedRead.isError).toBe(true);
      expect(swappedRead.content[0]?.text).toContain("replaced by a symlink");
    } finally {
      running.server.stop(true);
    }
  });
});
