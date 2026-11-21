import { realpathSync } from "node:fs";
import path from "node:path";

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
      if (normalized.endsWith(`/${cleanPattern}`) || normalized === cleanPattern) {
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
