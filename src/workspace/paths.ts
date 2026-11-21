import { existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";

const INTERNAL_PROTECTED_PATTERNS = [".justnewmcp/checkpoints", ".justnewmcp/checkpoints/*"];

function normalizeForComparison(filePath: string, platform: NodeJS.Platform): string {
  return platform === "win32" ? filePath.toLowerCase() : filePath;
}

export function isPathDenied(
  filePath: string,
  deniedPatterns: string[],
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  const normalized = pathLib.normalize(filePath).replaceAll("\\", "/").toLowerCase();
  const base = pathLib.basename(filePath).toLowerCase();

  for (const pattern of deniedPatterns) {
    const cleanPattern = pattern.replaceAll("\\", "/").toLowerCase();
    if (cleanPattern.includes("/")) {
      if (
        normalized.endsWith(`/${cleanPattern}`) ||
        normalized.includes(`/${cleanPattern}/`) ||
        normalized === cleanPattern
      ) {
        return true;
      }
    } else if (new Bun.Glob(cleanPattern).match(base)) {
      return true;
    }
  }

  return false;
}

export function isPathInsideRoot(
  candidatePath: string,
  rootPath: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  const normCandidate = normalizeForComparison(pathLib.normalize(candidatePath), platform);
  const normRoot = normalizeForComparison(pathLib.normalize(rootPath), platform);
  const rel = pathLib.relative(normRoot, normCandidate);
  if (rel === "") return true;
  if (rel === ".." || rel.startsWith(`..${pathLib.sep}`)) {
    return false;
  }
  return !pathLib.isAbsolute(rel);
}

export function resolveInsideRoots(
  targetPath: string,
  allowedRoots: string[],
  platform: NodeJS.Platform = process.platform,
  deniedPatterns: string[] = [],
): { resolvedPath: string; matchedRoot: string } {
  const realTarget = realpathSync(path.resolve(targetPath));

  if (deniedPatterns.length > 0 && isPathDenied(realTarget, deniedPatterns, platform)) {
    throw new Error(`Path "${targetPath}" is blocked by security policy.`);
  }

  for (const root of allowedRoots) {
    let realRoot: string;
    try {
      realRoot = realpathSync(path.resolve(root));
    } catch {
      continue;
    }

    if (isPathInsideRoot(realTarget, realRoot, platform)) {
      return { resolvedPath: realTarget, matchedRoot: realRoot };
    }
  }

  throw new Error(`Path "${targetPath}" is outside allowed workspace roots.`);
}

export function resolveWritablePathInsideRoot(
  inputPath: string,
  workspaceRoot: string,
  deniedPatterns: string[] = [],
  platform: NodeJS.Platform = process.platform,
): string {
  const realRoot = realpathSync(path.resolve(workspaceRoot));
  const candidate = path.isAbsolute(inputPath)
    ? path.resolve(inputPath)
    : path.resolve(realRoot, inputPath);

  if (!isPathInsideRoot(candidate, realRoot, platform)) {
    throw new Error(`Path "${inputPath}" is outside the active workspace.`);
  }

  const combinedDenied = [...deniedPatterns, ...INTERNAL_PROTECTED_PATTERNS];
  if (isPathDenied(candidate, combinedDenied, platform)) {
    throw new Error(`Path "${inputPath}" is blocked by security policy.`);
  }

  // If the target exists (including dangling symlinks), resolve and verify its real target
  if (existsSync(candidate)) {
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink()) {
      const realTarget = realpathSync(candidate);
      if (!isPathInsideRoot(realTarget, realRoot, platform)) {
        throw new Error(`Symlink "${inputPath}" resolves outside the active workspace.`);
      }
      if (isPathDenied(realTarget, combinedDenied, platform)) {
        throw new Error(`Path "${inputPath}" is blocked by security policy.`);
      }
      return realTarget;
    }
    const realTarget = realpathSync(candidate);
    if (!isPathInsideRoot(realTarget, realRoot, platform)) {
      throw new Error(`Path "${inputPath}" resolves outside the active workspace.`);
    }
    return realTarget;
  }

  // For new files/dirs, walk up to the deepest existing ancestor and verify its realpath stays inside root
  let ancestor = path.dirname(candidate);
  const trailingSegments: string[] = [path.basename(candidate)];
  while (!existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    trailingSegments.unshift(path.basename(ancestor));
    ancestor = parent;
  }

  const realAncestor = realpathSync(ancestor);
  if (!isPathInsideRoot(realAncestor, realRoot, platform)) {
    throw new Error(`Parent directory of "${inputPath}" resolves outside the active workspace.`);
  }

  const finalPath = path.join(realAncestor, ...trailingSegments);
  if (!isPathInsideRoot(finalPath, realRoot, platform) || isPathDenied(finalPath, combinedDenied, platform)) {
    throw new Error(`Path "${inputPath}" is blocked by security policy.`);
  }

  return finalPath;
}
