import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { readMemoryPreview } from "./memory.ts";
import { resolveInsideRoots } from "./paths.ts";

export interface WorkspaceState {
  activeRoot: string | null;
  matchedAllowedRoot: string | null;
}

export interface WorkspaceInitResult {
  workspace: string;
  matchedAllowedRoot: string;
  instructionFiles: string[];
  memoryDir: string;
  memoryPreview: string | null;
  memoryTopics: string[];
  gitStatus: string | null;
}

const INSTRUCTION_CANDIDATES = ["AGENTS.md", "CLAUDE.md", "README.md"];

async function readGitStatus(workspaceDir: string): Promise<string | null> {
  if (!existsSync(join(workspaceDir, ".git"))) return null;
  try {
    const proc = Bun.spawn(
      ["git", "-c", "core.fsmonitor=false", "status", "--short", "--branch"],
      {
        cwd: workspaceDir,
        stdout: "pipe",
        stderr: "pipe",
        env: {
          ...process.env,
          GIT_TERMINAL_PROMPT: "0",
          GIT_CONFIG_NOSYSTEM: "1",
        },
      },
    );
    const stdout = await new Response(proc.stdout).text();
    const exitCode = await proc.exited;
    if (exitCode !== 0) return null;
    return stdout.trim();
  } catch {
    return null;
  }
}

export interface WorkspaceInitOptions {
  deniedPatterns?: string[];
  memoryDir?: string;
}

export async function initializeWorkspace(
  targetPath: string,
  allowedRoots: string[],
  state: WorkspaceState,
  options: WorkspaceInitOptions = {},
): Promise<WorkspaceInitResult> {
  const { resolvedPath, matchedRoot } = resolveInsideRoots(targetPath, allowedRoots);
  if (!statSync(resolvedPath).isDirectory()) {
    throw new Error(`Workspace path "${resolvedPath}" is not a directory.`);
  }

  state.activeRoot = resolvedPath;
  state.matchedAllowedRoot = matchedRoot;

  const instructionFiles = INSTRUCTION_CANDIDATES.filter((file) =>
    existsSync(join(resolvedPath, file)),
  );
  const memory = await readMemoryPreview(resolvedPath, {
    memoryRoot: options.memoryDir,
    deniedPatterns: options.deniedPatterns,
  });
  const gitStatus = await readGitStatus(resolvedPath);

  return {
    workspace: resolvedPath,
    matchedAllowedRoot: matchedRoot,
    instructionFiles,
    memoryDir: memory.memoryDir,
    memoryPreview: memory.preview,
    memoryTopics: memory.topics,
    gitStatus,
  };
}
