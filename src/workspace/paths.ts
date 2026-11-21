import { realpathSync } from "node:fs";
import path from "node:path";

function normalizeForComparison(filePath: string, platform: NodeJS.Platform): string {
  return platform === "win32" ? filePath.toLowerCase() : filePath;
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
): { resolvedPath: string; matchedRoot: string } {
  const realTarget = realpathSync(path.resolve(targetPath));

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
