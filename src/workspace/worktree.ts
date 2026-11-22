import { existsSync, lstatSync, mkdirSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { generateRandomToken } from "../security/crypto.ts";
import {
  initializeWorkspace,
  type WorkspaceInitOptions,
  type WorkspaceInitResult,
  type WorkspaceState,
} from "./init.ts";
import {
  assertWorkspaceAnchored,
  isPathInsideRoot,
  resolveInsideRoots,
} from "./paths.ts";

const GIT_TIMEOUT_MS = 30_000;
const WORKTREE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const GIT_BRANCH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const GIT_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._^~/-]{0,127}$/;

export interface ActiveWorktreeSession {
  originalWorkspace: string;
  repoRoot: string;
  worktreePath: string;
  branchName: string;
  createdBranch: boolean;
  createdAt: string;
}

export interface WorktreeState {
  active: ActiveWorktreeSession | null;
  lock: Promise<void>;
}

export function createWorktreeState(): WorktreeState {
  return {
    active: null,
    lock: Promise.resolve(),
  };
}

async function withWorktreeLock<T>(
  state: WorktreeState,
  fn: () => Promise<T>,
): Promise<T> {
  const prev = state.lock;
  let release!: () => void;
  const current = new Promise<void>((resolveLock) => {
    release = resolveLock;
  });
  state.lock = prev.then(() => current);

  await prev;
  try {
    return await fn();
  } finally {
    release();
  }
}

function buildSanitizedGitEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (key.toUpperCase().startsWith("JUSTNEWMCP_")) continue;
    env[key] = value;
  }
  env.GIT_OPTIONAL_LOCKS = "0";
  env.GIT_TERMINAL_PROMPT = "0";
  env.GIT_CONFIG_NOSYSTEM = "1";
  return env;
}

async function runGit(
  cwd: string,
  args: string[],
  timeoutMs = GIT_TIMEOUT_MS,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["git", "-c", "core.fsmonitor=false", ...args], {
    cwd,
    stdout: "pipe",
    stderr: "pipe",
    env: buildSanitizedGitEnv(),
  });

  let timedOut = false;
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
        // Ignore if already exited
      }
    }, 1000);
  }, timeoutMs);

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  clearTimeout(timer);
  if (killTimer) clearTimeout(killTimer);

  if (timedOut) {
    throw new Error(`git ${args[0] ?? ""} timed out after ${timeoutMs}ms.`);
  }
  return { exitCode, stdout: stdout.trim(), stderr: stderr.trim() };
}

function assertNotSymlink(targetPath: string): void {
  try {
    if (lstatSync(targetPath).isSymbolicLink()) {
      throw new Error(`Worktree path "${targetPath}" must not be a symlink.`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function validateWorktreeName(name?: string): string {
  if (name === undefined) {
    return `wt-${generateRandomToken(4).toLowerCase()}`;
  }
  const trimmed = name.trim();
  if (
    !WORKTREE_NAME_RE.test(trimmed) ||
    trimmed.includes("..") ||
    trimmed.endsWith(".")
  ) {
    throw new Error(
      `Invalid worktree name "${name}". Use 1-64 alphanumeric, dot, underscore, or hyphen characters.`,
    );
  }
  return trimmed;
}

function validateBranchName(branch: string): string {
  const trimmed = branch.trim();
  if (
    !GIT_BRANCH_RE.test(trimmed) ||
    trimmed.includes("..") ||
    trimmed.includes("//") ||
    trimmed.includes("@{") ||
    trimmed.endsWith("/") ||
    trimmed.endsWith(".") ||
    trimmed.endsWith(".lock")
  ) {
    throw new Error(`Invalid git branch name "${branch}".`);
  }
  return trimmed;
}

function validateBaseRef(baseRef: string): string {
  const trimmed = baseRef.trim();
  if (
    !GIT_REF_RE.test(trimmed) ||
    trimmed.includes("..") ||
    trimmed.includes("//") ||
    trimmed.includes("@{")
  ) {
    throw new Error(`Invalid git base ref "${baseRef}".`);
  }
  return trimmed;
}

export interface WorktreeEnterOptions {
  name?: string;
  branch?: string;
  baseRef?: string;
}

export interface WorktreeEnterResult {
  worktreePath: string;
  originalWorkspace: string;
  branchName: string;
  createdBranch: boolean;
  workspaceInit: WorkspaceInitResult;
}

export async function worktreeEnterTool(
  activeWorkspace: string,
  allowedRoots: string[],
  workspaceState: WorkspaceState,
  worktreeState: WorktreeState,
  readTracker: Set<string>,
  initOptions: WorkspaceInitOptions,
  opts: WorktreeEnterOptions = {},
): Promise<WorktreeEnterResult> {
  return withWorktreeLock(worktreeState, async () => {
    if (worktreeState.active) {
      throw new Error(
        `Already inside worktree "${worktreeState.active.worktreePath}" (branch "${worktreeState.active.branchName}"). Call worktree_exit first.`,
      );
    }

    const anchoredWorkspace = assertWorkspaceAnchored(
      activeWorkspace,
      allowedRoots,
    );
    const topRes = await runGit(anchoredWorkspace, [
      "rev-parse",
      "--show-toplevel",
    ]);
    if (topRes.exitCode !== 0 || !topRes.stdout) {
      throw new Error(
        `Workspace "${anchoredWorkspace}" is not a git repository.`,
      );
    }
    const { resolvedPath: canonicalRepoRoot } = resolveInsideRoots(
      topRes.stdout,
      allowedRoots,
    );

    const slug = validateWorktreeName(opts.name);
    const branchName = validateBranchName(opts.branch ?? `worktree/${slug}`);
    const baseRef = validateBaseRef(opts.baseRef ?? "HEAD");

    const metaDir = join(canonicalRepoRoot, ".justnewmcp");
    const worktreesRoot = join(metaDir, "worktrees");
    assertNotSymlink(metaDir);
    assertNotSymlink(worktreesRoot);
    mkdirSync(worktreesRoot, { recursive: true, mode: 0o700 });

    const realWorktreesRoot = realpathSync(worktreesRoot);
    if (!isPathInsideRoot(realWorktreesRoot, canonicalRepoRoot)) {
      throw new Error(
        "Worktree base directory resolves outside the repository root.",
      );
    }

    const targetWorktreePath = join(realWorktreesRoot, slug);
    assertNotSymlink(targetWorktreePath);
    if (existsSync(targetWorktreePath)) {
      throw new Error(
        `Worktree directory "${slug}" already exists. Choose a different name.`,
      );
    }

    const branchCheck = await runGit(canonicalRepoRoot, [
      "show-ref",
      "--verify",
      "--quiet",
      `refs/heads/${branchName}`,
    ]);
    const branchExists = branchCheck.exitCode === 0;

    let addRes: { exitCode: number; stdout: string; stderr: string };
    if (branchExists) {
      if (opts.baseRef !== undefined) {
        throw new Error(
          `Branch "${branchName}" already exists; omit base_ref when attaching to an existing branch.`,
        );
      }
      addRes = await runGit(canonicalRepoRoot, [
        "worktree",
        "add",
        "--",
        targetWorktreePath,
        branchName,
      ]);
    } else {
      addRes = await runGit(canonicalRepoRoot, [
        "worktree",
        "add",
        "-b",
        branchName,
        "--",
        targetWorktreePath,
        baseRef,
      ]);
    }

    if (addRes.exitCode !== 0) {
      throw new Error(
        `Failed to create git worktree: ${addRes.stderr || addRes.stdout || `exit ${addRes.exitCode}`}`,
      );
    }

    const { resolvedPath: realWorktreePath } = resolveInsideRoots(
      targetWorktreePath,
      allowedRoots,
    );
    readTracker.clear();
    const workspaceInit = await initializeWorkspace(
      realWorktreePath,
      allowedRoots,
      workspaceState,
      initOptions,
    );

    worktreeState.active = {
      originalWorkspace: anchoredWorkspace,
      repoRoot: canonicalRepoRoot,
      worktreePath: workspaceInit.workspace,
      branchName,
      createdBranch: !branchExists,
      createdAt: new Date().toISOString(),
    };

    return {
      worktreePath: workspaceInit.workspace,
      originalWorkspace: anchoredWorkspace,
      branchName,
      createdBranch: !branchExists,
      workspaceInit,
    };
  });
}

export interface WorktreeExitOptions {
  action?: "keep" | "remove";
  deleteBranch?: boolean;
  force?: boolean;
}

export interface WorktreeExitResult {
  action: "kept" | "removed";
  worktreePath: string;
  branchName: string;
  branchDeleted: boolean;
  restoredWorkspace: string;
  workspaceInit: WorkspaceInitResult;
}

export async function worktreeExitTool(
  allowedRoots: string[],
  workspaceState: WorkspaceState,
  worktreeState: WorktreeState,
  readTracker: Set<string>,
  initOptions: WorkspaceInitOptions,
  opts: WorktreeExitOptions = {},
): Promise<WorktreeExitResult> {
  return withWorktreeLock(worktreeState, async () => {
    const session = worktreeState.active;
    if (!session) {
      throw new Error("No active worktree session. Call worktree_enter first.");
    }

    const action = opts.action ?? "keep";
    const force = opts.force ?? false;
    const deleteBranch = opts.deleteBranch ?? false;

    if (action === "keep" && deleteBranch) {
      throw new Error(
        'Cannot set delete_branch: true when action is "keep". Use action: "remove".',
      );
    }

    const anchoredOriginal = assertWorkspaceAnchored(
      session.originalWorkspace,
      allowedRoots,
    );
    const anchoredRepoRoot = assertWorkspaceAnchored(
      session.repoRoot,
      allowedRoots,
    );

    if (action === "keep") {
      readTracker.clear();
      const workspaceInit = await initializeWorkspace(
        anchoredOriginal,
        allowedRoots,
        workspaceState,
        initOptions,
      );
      worktreeState.active = null;
      return {
        action: "kept",
        worktreePath: session.worktreePath,
        branchName: session.branchName,
        branchDeleted: false,
        restoredWorkspace: workspaceInit.workspace,
        workspaceInit,
      };
    }

    const anchoredWorktree = assertWorkspaceAnchored(
      session.worktreePath,
      allowedRoots,
    );

    if (!force) {
      const statusRes = await runGit(anchoredWorktree, [
        "status",
        "--porcelain",
      ]);
      if (statusRes.exitCode !== 0) {
        throw new Error(
          `Failed to inspect worktree status: ${statusRes.stderr || `exit ${statusRes.exitCode}`}`,
        );
      }
      if (statusRes.stdout.length > 0) {
        throw new Error(
          'Worktree has uncommitted or untracked changes. Commit/stash them, pass action: "keep", or pass force: true to discard.',
        );
      }
    }

    const removeArgs = force
      ? ["worktree", "remove", "--force", "--", anchoredWorktree]
      : ["worktree", "remove", "--", anchoredWorktree];
    const removeRes = await runGit(anchoredRepoRoot, removeArgs);
    if (removeRes.exitCode !== 0) {
      throw new Error(
        `Failed to remove git worktree: ${removeRes.stderr || removeRes.stdout || `exit ${removeRes.exitCode}`}`,
      );
    }

    // Restore workspace immediately after removal so activeRoot never dangles
    readTracker.clear();
    const workspaceInit = await initializeWorkspace(
      anchoredOriginal,
      allowedRoots,
      workspaceState,
      initOptions,
    );
    worktreeState.active = null;

    let branchDeleted = false;
    if (deleteBranch) {
      const branchFlag = force ? "-D" : "-d";
      const branchRes = await runGit(anchoredRepoRoot, [
        "branch",
        branchFlag,
        "--",
        session.branchName,
      ]);
      if (branchRes.exitCode !== 0) {
        throw new Error(
          `Worktree removed and workspace restored, but failed to delete branch "${session.branchName}": ${branchRes.stderr || branchRes.stdout || `exit ${branchRes.exitCode}`}`,
        );
      }
      branchDeleted = true;
    }

    return {
      action: "removed",
      worktreePath: session.worktreePath,
      branchName: session.branchName,
      branchDeleted,
      restoredWorkspace: workspaceInit.workspace,
      workspaceInit,
    };
  });
}
