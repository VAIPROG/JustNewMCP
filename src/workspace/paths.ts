import { existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";

export const INTERNAL_PROTECTED_PATTERNS = [
  ".justnewmcp/checkpoints",
  ".justnewmcp/checkpoints/*",
  ".justnewmcp/approval-code",
  ".justnewmcp/approval-code-*",
  ".justnewmcp/oauth-tokens*",
];
const SAFE_ENV_TEMPLATES = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
  ".env.dist",
]);

export function isSafeEnvTemplatePath(
  filePath: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  const base = pathLib.basename(filePath).toLowerCase();
  return SAFE_ENV_TEMPLATES.has(base);
}

export function isEnvSecretPath(
  filePath: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  const base = pathLib.basename(filePath).toLowerCase();
  if (SAFE_ENV_TEMPLATES.has(base)) return false;
  return base === ".env" || base.startsWith(".env.");
}

function normalizeForComparison(
  filePath: string,
  platform: NodeJS.Platform,
): string {
  return platform === "win32" ? filePath.toLowerCase() : filePath;
}

export function isPathDenied(
  filePath: string,
  deniedPatterns: string[],
  platform: NodeJS.Platform = process.platform,
): boolean {
  const pathLib = platform === "win32" ? path.win32 : path.posix;
  const normalized = pathLib
    .normalize(filePath)
    .replaceAll("\\", "/")
    .toLowerCase();
  const base = pathLib.basename(filePath).toLowerCase();

  const isSafeTemplate = SAFE_ENV_TEMPLATES.has(base);

  for (const pattern of deniedPatterns) {
    const cleanPattern = pattern.replaceAll("\\", "/").toLowerCase();
    if (isSafeTemplate && cleanPattern === ".env.*") {
      continue;
    }
    if (cleanPattern.includes("/")) {
      if (
        normalized.endsWith(`/${cleanPattern}`) ||
        normalized.includes(`/${cleanPattern}/`) ||
        normalized === cleanPattern
      ) {
        return true;
      }
      if (
        cleanPattern.includes("*") ||
        cleanPattern.includes("?") ||
        cleanPattern.includes("[")
      ) {
        const cleanTrimmed = cleanPattern.replace(/^\/+/, "");
        const candidateRel = normalized.replace(/^\/+/, "");
        if (
          new Bun.Glob(cleanTrimmed).match(candidateRel) ||
          new Bun.Glob(`**/${cleanTrimmed}`).match(candidateRel)
        ) {
          return true;
        }
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
  const normCandidate = normalizeForComparison(
    pathLib.normalize(candidatePath),
    platform,
  );
  const normRoot = normalizeForComparison(
    pathLib.normalize(rootPath),
    platform,
  );
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

  if (
    deniedPatterns.length > 0 &&
    isPathDenied(realTarget, deniedPatterns, platform)
  ) {
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

export function assertWorkspaceAnchored(
  expectedCanonicalRoot: string,
  allowedRoots: string[],
  platform: NodeJS.Platform = process.platform,
): string {
  const currentReal = realpathSync(path.resolve(expectedCanonicalRoot));
  const expectedNorm = normalizeForComparison(
    path.resolve(expectedCanonicalRoot),
    platform,
  );
  const currentNorm = normalizeForComparison(currentReal, platform);
  if (currentNorm !== expectedNorm) {
    throw new Error(
      "Active workspace directory changed or was replaced by a symlink after workspace_init.",
    );
  }
  const { resolvedPath } = resolveInsideRoots(
    currentReal,
    allowedRoots,
    platform,
  );
  return resolvedPath;
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

  // Use lstatSync so dangling symlinks are detected instead of being treated as absent files
  let targetLstat: ReturnType<typeof lstatSync> | null = null;
  try {
    targetLstat = lstatSync(candidate);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }

  if (targetLstat) {
    if (targetLstat.isSymbolicLink()) {
      let realTarget: string;
      try {
        realTarget = realpathSync(candidate);
      } catch {
        throw new Error(
          `Refusing to write through dangling symlink "${inputPath}".`,
        );
      }
      if (!isPathInsideRoot(realTarget, realRoot, platform)) {
        throw new Error(
          `Symlink "${inputPath}" resolves outside the active workspace.`,
        );
      }
      if (isPathDenied(realTarget, combinedDenied, platform)) {
        throw new Error(`Path "${inputPath}" is blocked by security policy.`);
      }
      return realTarget;
    }
    const realTarget = realpathSync(candidate);
    if (!isPathInsideRoot(realTarget, realRoot, platform)) {
      throw new Error(
        `Path "${inputPath}" resolves outside the active workspace.`,
      );
    }
    if (isPathDenied(realTarget, combinedDenied, platform)) {
      throw new Error(`Path "${inputPath}" is blocked by security policy.`);
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
    throw new Error(
      `Parent directory of "${inputPath}" resolves outside the active workspace.`,
    );
  }

  const finalPath = path.join(realAncestor, ...trailingSegments);
  if (
    !isPathInsideRoot(finalPath, realRoot, platform) ||
    isPathDenied(finalPath, combinedDenied, platform)
  ) {
    throw new Error(`Path "${inputPath}" is blocked by security policy.`);
  }

  return finalPath;
}

export function canonicalizeCandidatePath(filePath: string): string {
  const abs = path.resolve(filePath);
  if (existsSync(abs)) {
    return realpathSync(abs);
  }
  const trailing: string[] = [];
  let cursor = abs;
  while (!existsSync(cursor)) {
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    trailing.unshift(path.basename(cursor));
    cursor = parent;
  }
  const realBase = existsSync(cursor) ? realpathSync(cursor) : cursor;
  return path.join(realBase, ...trailing);
}

export function assertFileOutsideAllowedRoots(
  filePath: string,
  allowedRoots: string[],
  label = "Internal file",
  platform: NodeJS.Platform = process.platform,
): string {
  const canonicalTarget = canonicalizeCandidatePath(filePath);
  for (const root of allowedRoots) {
    const canonicalRoot = existsSync(path.resolve(root))
      ? realpathSync(path.resolve(root))
      : path.resolve(root);
    if (isPathInsideRoot(canonicalTarget, canonicalRoot, platform)) {
      throw new Error(
        `${label} "${filePath}" must reside outside configured allowedRoots.`,
      );
    }
  }
  return canonicalTarget;
}
