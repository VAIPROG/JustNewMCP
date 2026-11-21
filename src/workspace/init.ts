import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { resolveInsideRoots } from "./paths.ts";

export interface WorkspaceState {
  activeRoot: string | null;
  matchedAllowedRoot: string | null;
}

export interface WorkspaceInitResult {
  workspace: string;
  matchedAllowedRoot: string;
  instructionFiles: string[];
  memoryPreview: string | null;
  gitStatus: string | null;
}

const INSTRUCTION_CANDIDATES = ["AGENTS.md", "CLAUDE.md", "README.md"];
const MEMORY_MAX_LINES = 200;
const MEMORY_MAX_BYTES = 25 * 1024;

function readMemoryPreview(workspaceDir: string): string | null {
  const memoryPath = join(workspaceDir, ".justnewmcp", "MEMORY.md");
  if (!existsSync(memoryPath)) return null;

  const raw = readFileSync(memoryPath, "utf8");
  const lines = raw.split(/\r?\n/).slice(0, MEMORY_MAX_LINES).join("\n");
  if (Buffer.byteLength(lines, "utf8") <= MEMORY_MAX_BYTES) {
    return lines;
  }
  return Buffer.from(lines, "utf8").subarray(0, MEMORY_MAX_BYTES).toString("utf8");
}

async function readGitStatus(workspaceDir: string): Promise<string | null> {
  if (!existsSync(join(workspaceDir, ".git"))) return null;
  try {
    const proc = Bun.spawn(["git", "status", "--short", "--branch"], {
      cwd: workspaceDir,
      stdout: "pipe",
      stderr: "pipe",
    });
    const stdout = await new Response(proc.stdout).text();
    const exitCode = await proc.exited;
    if (exitCode !== 0) return null;
    return stdout.trim();
  } catch {
    return null;
  }
}

export async function initializeWorkspace(
  targetPath: string,
  allowedRoots: string[],
  state: WorkspaceState,
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
  const memoryPreview = readMemoryPreview(resolvedPath);
  const gitStatus = await readGitStatus(resolvedPath);

  return {
    workspace: resolvedPath,
    matchedAllowedRoot: matchedRoot,
    instructionFiles,
    memoryPreview,
    gitStatus,
  };
}
