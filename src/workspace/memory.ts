import { existsSync, readdirSync, realpathSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { resolveInsideRoots } from "./paths.ts";

export const MEMORY_MAX_LINES = 200;
export const MEMORY_MAX_BYTES = 25 * 1024;

export function normalizeWorkspaceSlug(workspacePath: string): string {
  const trimmed = workspacePath.trim().replace(/[/\\]+$/, "");
  const isWindowsPath = /^[A-Za-z]:[/\\]/.test(trimmed);
  const hashInput = isWindowsPath ? trimmed.replaceAll("\\", "/").toLowerCase() : trimmed;
  const shortHash = new Bun.CryptoHasher("sha256").update(hashInput, "utf8").digest("hex").slice(0, 8);

  const readable = (isWindowsPath ? trimmed.toLowerCase() : trimmed)
    .replace(/^[/\\]+/, "")
    .replace(/^([A-Za-z]):[/\\]+/, "$1--")
    .replace(/[/\\]+/g, "--")
    .replace(/[<>:"|?*\x00-\x1f\s]+/g, "_")
    .replace(/\.\.+/g, "_");
  return `${readable || "workspace"}--${shortHash}`;
}

export function resolveMemoryDirectory(
  workspaceDir: string,
  memoryRoot?: string,
): { memoryDir: string; boundaryRoot: string } {
  if (memoryRoot) {
    const realMemoryRoot = realpathSync(resolve(memoryRoot));
    const slug = normalizeWorkspaceSlug(workspaceDir);
    return {
      memoryDir: join(realMemoryRoot, slug),
      boundaryRoot: realMemoryRoot,
    };
  }
  return {
    memoryDir: join(workspaceDir, ".justnewmcp", "memory"),
    boundaryRoot: workspaceDir,
  };
}

export function listMemoryTopics(memoryDir: string, boundaryRoot: string): string[] {
  if (!existsSync(memoryDir)) return [];
  let realMemDir: string;
  try {
    realMemDir = resolveInsideRoots(memoryDir, [boundaryRoot]).resolvedPath;
  } catch {
    return [];
  }
  if (!statSync(realMemDir).isDirectory()) return [];

  const topics: string[] = [];
  for (const entry of readdirSync(realMemDir, { withFileTypes: true })) {
    if (entry.name === "MEMORY.md" || entry.name.startsWith(".")) continue;
    topics.push(entry.isDirectory() ? `${entry.name}/` : entry.name);
  }
  return topics.sort();
}

export async function readMemoryPreview(
  workspaceDir: string,
  options: { memoryRoot?: string; deniedPatterns?: string[] } = {},
): Promise<{ memoryDir: string; preview: string | null; topics: string[] }> {
  const { memoryDir, boundaryRoot } = resolveMemoryDirectory(workspaceDir, options.memoryRoot);
  const memoryPath = join(memoryDir, "MEMORY.md");
  const topics = listMemoryTopics(memoryDir, boundaryRoot);

  if (!existsSync(memoryPath)) {
    return { memoryDir, preview: null, topics };
  }

  let resolvedMemoryPath: string;
  try {
    const resolved = resolveInsideRoots(
      memoryPath,
      [boundaryRoot],
      process.platform,
      options.deniedPatterns ?? [],
    );
    resolvedMemoryPath = resolved.resolvedPath;
  } catch {
    return { memoryDir, preview: null, topics };
  }

  if (!statSync(resolvedMemoryPath).isFile()) {
    return { memoryDir, preview: null, topics };
  }

  // Bounded disk read: never load more than MEMORY_MAX_BYTES into memory
  const boundedText = await Bun.file(resolvedMemoryPath).slice(0, MEMORY_MAX_BYTES).text();
  const preview = boundedText.split(/\r?\n/).slice(0, MEMORY_MAX_LINES).join("\n");
  return { memoryDir, preview, topics };
}
