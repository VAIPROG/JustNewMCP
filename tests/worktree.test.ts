import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema, DEFAULT_DENIED_PATH_PATTERNS } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
import {
  initializeWorkspace,
  type WorkspaceState,
} from "../src/workspace/init.ts";
import {
  createWorktreeState,
  worktreeEnterTool,
  worktreeExitTool,
} from "../src/workspace/worktree.ts";

function runGitSync(cwd: string, args: string[]): string {
  const res = Bun.spawnSync(["git", ...args], {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Test User",
      GIT_AUTHOR_EMAIL: "test@example.com",
      GIT_COMMITTER_NAME: "Test User",
      GIT_COMMITTER_EMAIL: "test@example.com",
      GIT_TERMINAL_PROMPT: "0",
      GIT_CONFIG_NOSYSTEM: "1",
    },
  });
  if (res.exitCode !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed: ${res.stderr.toString().trim()}`,
    );
  }
  return res.stdout.toString().trim();
}

describe("git worktree_enter and worktree_exit tools", () => {
  let baseDir: string;
  let repoDir: string;
  let nonGitDir: string;
  let outsideDir: string;

  beforeAll(() => {
    baseDir = realpathSync(mkdtempSync(join(tmpdir(), "justnewmcp-wt-")));
    repoDir = join(baseDir, "repo");
    nonGitDir = join(baseDir, "plain-dir");
    outsideDir = join(baseDir, "outside");
    mkdirSync(repoDir, { recursive: true });
    mkdirSync(nonGitDir, { recursive: true });
    mkdirSync(outsideDir, { recursive: true });

    runGitSync(repoDir, ["init", "-b", "main"]);
    writeFileSync(join(repoDir, "README.md"), "# Test Repo\n", "utf8");
    writeFileSync(join(repoDir, ".gitignore"), ".justnewmcp/\n", "utf8");
    runGitSync(repoDir, ["add", "."]);
    runGitSync(repoDir, ["commit", "-m", "initial commit"]);
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("creates isolated worktree, switches active root, and removes cleanly on exit", async () => {
    const wsState: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const wtState = createWorktreeState();
    const readTracker = new Set<string>(["stale-entry"]);

    await initializeWorkspace(repoDir, [baseDir], wsState, {
      deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS,
    });

    const entered = await worktreeEnterTool(
      wsState.activeRoot ?? repoDir,
      [baseDir],
      wsState,
      wtState,
      readTracker,
      { deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS },
      { name: "feature-a", branch: "feat/isolated-a" },
    );

    expect(entered.createdBranch).toBe(true);
    expect(entered.branchName).toBe("feat/isolated-a");
    expect(wsState.activeRoot).toBe(entered.worktreePath);
    expect(readTracker.size).toBe(0);
    expect(existsSync(join(entered.worktreePath, "README.md"))).toBe(true);

    // Dirty worktree blocks removal without force
    writeFileSync(join(entered.worktreePath, "dirty.txt"), "wip\n", "utf8");
    await expect(
      worktreeExitTool(
        [baseDir],
        wsState,
        wtState,
        readTracker,
        { deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS },
        { action: "remove" },
      ),
    ).rejects.toThrow("uncommitted or untracked");

    // Clean worktree removes cleanly and deletes merged/unchanged branch
    rmSync(join(entered.worktreePath, "dirty.txt"));
    const exited = await worktreeExitTool(
      [baseDir],
      wsState,
      wtState,
      readTracker,
      { deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS },
      { action: "remove", deleteBranch: true },
    );

    expect(exited.action).toBe("removed");
    expect(exited.branchDeleted).toBe(true);
    expect(exited.restoredWorkspace).toBe(repoDir);
    expect(wsState.activeRoot).toBe(repoDir);
    expect(wtState.active).toBeNull();
    expect(existsSync(entered.worktreePath)).toBe(false);
  });

  test("supports keep action and rejects nested worktrees, invalid names, non-git dirs, and symlinked worktrees dir", async () => {
    const wsState: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const wtState = createWorktreeState();
    const readTracker = new Set<string>();

    // Reject non-git directory
    await initializeWorkspace(nonGitDir, [baseDir], wsState);
    await expect(
      worktreeEnterTool(
        wsState.activeRoot ?? nonGitDir,
        [baseDir],
        wsState,
        wtState,
        readTracker,
        {},
      ),
    ).rejects.toThrow("not a git repository");

    await initializeWorkspace(repoDir, [baseDir], wsState);

    // Reject option-like or traversal names and branches
    await expect(
      worktreeEnterTool(
        repoDir,
        [baseDir],
        wsState,
        wtState,
        readTracker,
        {},
        {
          name: "--evil",
        },
      ),
    ).rejects.toThrow("Invalid worktree name");
    await expect(
      worktreeEnterTool(
        repoDir,
        [baseDir],
        wsState,
        wtState,
        readTracker,
        {},
        {
          branch: "../escape",
        },
      ),
    ).rejects.toThrow("Invalid git branch name");

    const entered = await worktreeEnterTool(
      repoDir,
      [baseDir],
      wsState,
      wtState,
      readTracker,
      {},
      { name: "keep-me", branch: "feat/keep-me" },
    );

    // Nested worktree_enter must be rejected while session is active
    await expect(
      worktreeEnterTool(
        entered.worktreePath,
        [baseDir],
        wsState,
        wtState,
        readTracker,
        {},
        { name: "nested" },
      ),
    ).rejects.toThrow("Already inside worktree");

    // Exit with keep preserves directory and branch
    const kept = await worktreeExitTool(
      [baseDir],
      wsState,
      wtState,
      readTracker,
      {},
      { action: "keep" },
    );
    expect(kept.action).toBe("kept");
    expect(existsSync(entered.worktreePath)).toBe(true);
    expect(wsState.activeRoot).toBe(repoDir);

    // Clean up kept worktree
    runGitSync(repoDir, ["worktree", "remove", "--", entered.worktreePath]);
    runGitSync(repoDir, ["branch", "-d", "--", "feat/keep-me"]);

    // Reject symlinked .justnewmcp/worktrees directory
    const symRepo = join(baseDir, "sym-repo");
    mkdirSync(join(symRepo, ".justnewmcp"), { recursive: true });
    runGitSync(symRepo, ["init", "-b", "main"]);
    writeFileSync(join(symRepo, "a.txt"), "a\n", "utf8");
    runGitSync(symRepo, ["add", "a.txt"]);
    runGitSync(symRepo, ["commit", "-m", "init"]);
    symlinkSync(outsideDir, join(symRepo, ".justnewmcp", "worktrees"));

    await initializeWorkspace(symRepo, [baseDir], wsState);
    await expect(
      worktreeEnterTool(
        symRepo,
        [baseDir],
        wsState,
        wtState,
        readTracker,
        {},
        {
          name: "escape",
        },
      ),
    ).rejects.toThrow("must not be a symlink");
  });

  test("MCP /mcp enforces plan mode blocking and allows isolated file edits inside worktree", async () => {
    const clientId = "wt-e2e-client";
    const clientSecret = "wt-e2e-secret-value-123456";
    const approvalCode = "WT00-1234-5678";
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
      const csrfToken =
        (await formRes.text()).match(
          /name="csrf_token"\s+value="([^"]+)"/,
        )?.[1] ?? "";
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
      const { access_token } = (await tokRes.json()) as {
        access_token: string;
      };

      const call = async (name: string, args: Record<string, unknown> = {}) => {
        const res = await fetch(`${baseUrl}/mcp`, {
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
        return (
          (await res.json()) as {
            result: { isError?: boolean; content: Array<{ text: string }> };
          }
        ).result;
      };

      expect(
        (await call("workspace_init", { path: repoDir })).isError,
      ).toBeUndefined();

      // Plan mode must block worktree_enter
      expect((await call("plan_enter")).isError).toBeUndefined();
      const blockedEnter = await call("worktree_enter", { name: "plan-wt" });
      expect(blockedEnter.isError).toBe(true);
      expect(blockedEnter.content[0]?.text).toContain("Plan mode is active");
      expect((await call("plan_exit")).isError).toBeUndefined();

      // Enter worktree, edit file inside worktree without mutating main repo
      const enteredRes = await call("worktree_enter", {
        name: "e2e-wt",
        branch: "feat/e2e-wt",
      });
      expect(enteredRes.isError).toBeUndefined();
      const enteredData = JSON.parse(enteredRes.content[0]?.text ?? "{}") as {
        worktreePath: string;
      };

      const writeRes = await call("write_file", {
        path: "isolated.txt",
        content: "only in worktree\n",
      });
      expect(writeRes.isError).toBeUndefined();
      expect(existsSync(join(repoDir, "isolated.txt"))).toBe(false);
      expect(
        readFileSync(join(enteredData.worktreePath, "isolated.txt"), "utf8"),
      ).toBe("only in worktree\n");

      // Plan mode must also block worktree_exit
      expect((await call("plan_enter")).isError).toBeUndefined();
      const blockedExit = await call("worktree_exit", { action: "keep" });
      expect(blockedExit.isError).toBe(true);
      expect(blockedExit.content[0]?.text).toContain("Plan mode is active");
      expect((await call("plan_exit")).isError).toBeUndefined();

      // Force-remove worktree and delete branch
      const exitRes = await call("worktree_exit", {
        action: "remove",
        delete_branch: true,
        force: true,
      });
      expect(exitRes.isError).toBeUndefined();
      expect(existsSync(enteredData.worktreePath)).toBe(false);
    } finally {
      running.server.stop(true);
    }
  });
});
