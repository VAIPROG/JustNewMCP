import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { resolveInsideRoots } from "./paths.ts";

interface IgnoreRule {
  negated: boolean;
  dirOnly: boolean;
  matchers: Bun.Glob[];
}

const MAX_GITIGNORE_BYTES = 256 * 1024;

function compileGitignoreLine(rawLine: string): IgnoreRule | null {
  let line = rawLine.trim();
  if (!line || line.startsWith("#")) return null;

  let negated = false;
  if (line.startsWith("!")) {
    negated = true;
    line = line.slice(1);
    if (!line) return null;
  }

  let dirOnly = false;
  if (line.endsWith("/")) {
    dirOnly = true;
    line = line.replace(/\/+$/, "");
    if (!line) return null;
  }

  const anchored = line.startsWith("/");
  if (anchored) {
    line = line.slice(1);
  }
  const hasSlash = line.includes("/");

  const patterns: string[] = [];
  if (anchored || hasSlash) {
    if (dirOnly) {
      patterns.push(`${line}/**`);
    } else {
      patterns.push(line, `${line}/**`);
    }
  } else if (dirOnly) {
    patterns.push(`${line}/**`, `**/${line}/**`);
  } else {
    patterns.push(line, `**/${line}`, `${line}/**`, `**/${line}/**`);
  }

  return {
    negated,
    dirOnly,
    matchers: patterns.map((p) => new Bun.Glob(p)),
  };
}

export function loadGitignoreMatcher(
  workspaceRoot: string,
): (relPosixPath: string) => boolean {
  const gitignorePath = join(workspaceRoot, ".gitignore");
  if (!existsSync(gitignorePath)) {
    return () => false;
  }

  let resolvedPath: string;
  try {
    resolvedPath = resolveInsideRoots(gitignorePath, [
      workspaceRoot,
    ]).resolvedPath;
    const stat = statSync(resolvedPath);
    if (!stat.isFile() || stat.size > MAX_GITIGNORE_BYTES) {
      return () => false;
    }
  } catch {
    return () => false;
  }

  const rules: IgnoreRule[] = [];
  const raw = readFileSync(resolvedPath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const compiled = compileGitignoreLine(line);
    if (compiled) rules.push(compiled);
  }

  if (rules.length === 0) {
    return () => false;
  }

  return (relPosixPath: string): boolean => {
    const clean = relPosixPath.replace(/^\/+/, "");
    let ignored = false;
    for (const rule of rules) {
      if (rule.matchers.some((g) => g.match(clean))) {
        ignored = !rule.negated;
      }
    }
    return ignored;
  };
}
