import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  mkdirSync,
  openSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { createCheckpoint } from "./checkpoints.ts";
import { loadGitignoreMatcher } from "./gitignore.ts";
import {
  INTERNAL_PROTECTED_PATTERNS,
  isEnvSecretPath,
  isPathDenied,
  resolveInsideRoots,
  resolveWritablePathInsideRoot,
} from "./paths.ts";

const MAX_READ_FILE_BYTES = 2 * 1024 * 1024;
const MAX_GREP_OUTPUT_CHARS = 30_000;
const ALWAYS_IGNORED_PREFIXES = [
  ".git/",
  "node_modules/",
  ".justnewmcp/checkpoints/",
];

const utf8FatalDecoder = new TextDecoder("utf-8", { fatal: true });

function isBinaryOrInvalidUtf8(
  bytes: Uint8Array,
): { valid: true; text: string } | { valid: false; reason: string } {
  const sampleLen = Math.min(bytes.byteLength, 8192);
  for (let i = 0; i < sampleLen; i += 1) {
    if (bytes[i] === 0) {
      return {
        valid: false,
        reason: "File appears to be binary (contains NUL bytes).",
      };
    }
  }
  try {
    return { valid: true, text: utf8FatalDecoder.decode(bytes) };
  } catch {
    return {
      valid: false,
      reason:
        "File is not valid UTF-8; refusing to avoid corrupting its encoding.",
    };
  }
}

function isIgnoredRelativePath(
  relPosix: string,
  deniedPatterns: string[],
): boolean {
  for (const prefix of ALWAYS_IGNORED_PREFIXES) {
    if (relPosix.startsWith(prefix) || relPosix === prefix.slice(0, -1)) {
      return true;
    }
  }
  return isPathDenied(relPosix, deniedPatterns, "linux");
}

function resolveReadablePathInWorkspace(
  inputPath: string,
  workspaceRoot: string,
  deniedPatterns: string[],
): string {
  const candidate = resolve(workspaceRoot, inputPath);
  const combinedDenied = [...deniedPatterns, ...INTERNAL_PROTECTED_PATTERNS];
  const { resolvedPath } = resolveInsideRoots(
    candidate,
    [workspaceRoot],
    process.platform,
    combinedDenied,
  );
  if (!statSync(resolvedPath).isFile()) {
    throw new Error(`Path "${inputPath}" is not a regular file.`);
  }
  return resolvedPath;
}

export interface ReadFilePolicy {
  allowEnvReading?: boolean;
  askHumanAllowance?: boolean;
}

export interface ReadFileOptions {
  path: string;
  offset?: number;
  limit?: number;
  humanApproved?: boolean;
}

function stripEnvPatterns(deniedPatterns: string[]): string[] {
  return deniedPatterns.filter((p) => {
    const clean = p.trim().toLowerCase();
    return clean !== ".env" && clean !== ".env.*";
  });
}

export async function readFileTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  readTracker: Set<string>,
  opts: ReadFileOptions,
  policy: ReadFilePolicy = {},
): Promise<{
  path: string;
  startLine: number;
  endLine: number;
  totalLines: number;
  hasMore: boolean;
  content: string;
  usedHumanApproval?: boolean;
}> {
  let effectiveDenied = deniedPatterns;
  let usedHumanApproval = false;
  const candidateAbs = resolve(workspaceRoot, opts.path);
  let envSecret = isEnvSecretPath(candidateAbs);
  if (!envSecret) {
    try {
      const { resolvedPath: probe } = resolveInsideRoots(
        candidateAbs,
        [workspaceRoot],
        process.platform,
        [],
      );
      envSecret = isEnvSecretPath(probe);
    } catch {
      // Let resolveReadablePathInWorkspace raise the standard boundary error
    }
  }

  if (envSecret) {
    if (policy.allowEnvReading) {
      effectiveDenied = stripEnvPatterns(deniedPatterns);
    } else if (policy.askHumanAllowance) {
      if (opts.humanApproved) {
        effectiveDenied = stripEnvPatterns(deniedPatterns);
        usedHumanApproval = true;
      } else {
        throw new Error(
          `Reading "${opts.path}" requires explicit human approval. Use read_available_envs to inspect variable names without values, or ask the user to reply with "Allow" / "Я разрешаю" and retry read_file with human_approved: true.`,
        );
      }
    }
  }

  const resolvedPath = resolveReadablePathInWorkspace(
    opts.path,
    workspaceRoot,
    effectiveDenied,
  );
  const stat = statSync(resolvedPath);
  if (stat.size > MAX_READ_FILE_BYTES) {
    throw new Error(
      `File "${opts.path}" is ${stat.size} bytes (max ${MAX_READ_FILE_BYTES} bytes).`,
    );
  }

  const bytes = await Bun.file(resolvedPath).bytes();
  const decoded = isBinaryOrInvalidUtf8(bytes);
  if (!decoded.valid) {
    throw new Error(decoded.reason);
  }

  const allLines =
    decoded.text === ""
      ? []
      : decoded.text.replace(/\r?\n$/, "").split(/\r?\n/);
  const startLine = Math.max(1, opts.offset ?? 1);
  const limit = Math.max(1, Math.min(opts.limit ?? 200, 2000));
  const slice = allLines.slice(startLine - 1, startLine - 1 + limit);
  const numbered = slice
    .map((line, i) => `${String(startLine + i).padStart(4, " ")} | ${line}`)
    .join("\n");

  readTracker.add(resolvedPath);

  const endLine = slice.length > 0 ? startLine + slice.length - 1 : 0;
  return {
    path: relative(workspaceRoot, resolvedPath).replaceAll("\\", "/"),
    startLine,
    endLine,
    totalLines: allLines.length,
    hasMore: startLine - 1 + slice.length < allLines.length,
    content: numbered,
    ...(usedHumanApproval ? { usedHumanApproval: true } : {}),
  };
}

export interface EditOperation {
  old_string: string;
  new_string: string;
  replace_all?: boolean;
}

export async function applyEditsTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  readTracker: Set<string>,
  inputPath: string,
  edits: EditOperation[],
): Promise<{
  path: string;
  checkpointId: string;
  replacements: number;
}> {
  if (edits.length === 0) {
    throw new Error("At least one edit operation is required.");
  }

  const resolvedPath = resolveWritablePathInsideRoot(
    inputPath,
    workspaceRoot,
    deniedPatterns,
  );
  if (!existsSync(resolvedPath) || !statSync(resolvedPath).isFile()) {
    throw new Error(`Path "${inputPath}" is not a regular file.`);
  }
  if (!readTracker.has(resolvedPath)) {
    throw new Error(`Read "${inputPath}" with read_file before editing it.`);
  }

  const stat = statSync(resolvedPath);
  if (stat.size > MAX_READ_FILE_BYTES) {
    throw new Error(
      `File "${inputPath}" exceeds maximum editable size (${MAX_READ_FILE_BYTES} bytes).`,
    );
  }

  const bytes = await Bun.file(resolvedPath).bytes();
  const decoded = isBinaryOrInvalidUtf8(bytes);
  if (!decoded.valid) {
    throw new Error(decoded.reason);
  }

  let updated = decoded.text;
  let totalReplacements = 0;

  // Apply all edits in memory first so multi_edit is atomic on failure
  for (let i = 0; i < edits.length; i += 1) {
    const op = edits[i];
    if (!op) continue;
    if (op.old_string.length === 0) {
      throw new Error(`Edit #${i + 1}: old_string must not be empty.`);
    }
    if (op.old_string === op.new_string) {
      throw new Error(
        `Edit #${i + 1}: new_string must differ from old_string.`,
      );
    }
    const parts = updated.split(op.old_string);
    const matches = parts.length - 1;
    if (matches === 0) {
      throw new Error(
        `Edit #${i + 1}: old_string not found in "${inputPath}".`,
      );
    }
    if (matches > 1 && !op.replace_all) {
      throw new Error(
        `Edit #${i + 1}: old_string matched ${matches} times in "${inputPath}". Provide more context or set replace_all: true.`,
      );
    }
    // Use parts.join for both single and replace_all modes so $&, $$, and $' in new_string stay literal
    updated = parts.join(op.new_string);
    totalReplacements += op.replace_all ? matches : 1;
  }

  const cp = await createCheckpoint(
    workspaceRoot,
    resolvedPath,
    edits.length > 1 ? "multi_edit" : "edit_file",
  );
  await Bun.write(resolvedPath, updated);

  return {
    path: relative(workspaceRoot, resolvedPath).replaceAll("\\", "/"),
    checkpointId: cp.id,
    replacements: totalReplacements,
  };
}

export async function writeFileTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  readTracker: Set<string>,
  inputPath: string,
  content: string,
): Promise<{
  path: string;
  checkpointId: string;
  bytesWritten: number;
}> {
  // Allow writing to .env files (with pre-write checkpoint), while keeping non-env secrets blocked
  const effectiveWriteDenied = isEnvSecretPath(inputPath)
    ? stripEnvPatterns(deniedPatterns)
    : deniedPatterns;
  const targetPath = resolveWritablePathInsideRoot(
    inputPath,
    workspaceRoot,
    effectiveWriteDenied,
  );
  mkdirSync(dirname(targetPath), { recursive: true });

  const cp = await createCheckpoint(workspaceRoot, targetPath, "write_file");
  let bytesWritten: number;
  if (isEnvSecretPath(targetPath) && process.platform !== "win32") {
    const fd = openSync(
      targetPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        fsConstants.O_NOFOLLOW,
      0o600,
    );
    try {
      fchmodSync(fd, 0o600);
      writeFileSync(fd, content, "utf8");
    } finally {
      closeSync(fd);
    }
    bytesWritten = Buffer.byteLength(content, "utf8");
  } else {
    bytesWritten = await Bun.write(targetPath, content);
  }
  readTracker.add(targetPath);

  return {
    path: relative(workspaceRoot, targetPath).replaceAll("\\", "/"),
    checkpointId: cp.id,
    bytesWritten,
  };
}

export async function globFilesTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  pattern: string,
  limit = 200,
): Promise<{ files: string[]; truncated: boolean }> {
  const capped = Math.max(1, Math.min(limit, 1000));
  const isGitignored = loadGitignoreMatcher(workspaceRoot);
  const glob = new Bun.Glob(pattern);
  const candidates: Array<{ rel: string; mtimeMs: number }> = [];

  for await (const rawRel of glob.scan({
    cwd: workspaceRoot,
    onlyFiles: true,
    dot: true,
    followSymlinks: false,
  })) {
    const relPosix = rawRel.replaceAll("\\", "/");
    if (
      isIgnoredRelativePath(relPosix, deniedPatterns) ||
      isGitignored(relPosix)
    )
      continue;

    try {
      const fullPath = join(workspaceRoot, rawRel);
      const combinedDenied = [
        ...deniedPatterns,
        ...INTERNAL_PROTECTED_PATTERNS,
      ];
      const { resolvedPath } = resolveInsideRoots(
        fullPath,
        [workspaceRoot],
        process.platform,
        combinedDenied,
      );
      const stat = statSync(resolvedPath);
      if (!stat.isFile()) continue;
      candidates.push({ rel: relPosix, mtimeMs: stat.mtimeMs });
    } catch {
      continue;
    }
  }

  candidates.sort(
    (a, b) => b.mtimeMs - a.mtimeMs || a.rel.localeCompare(b.rel),
  );
  const truncated = candidates.length > capped;
  return {
    files: candidates.slice(0, capped).map((c) => c.rel),
    truncated,
  };
}

export interface GrepOptions {
  pattern: string;
  glob?: string;
  caseInsensitive?: boolean;
  contextLines?: number;
  mode?: "files_with_matches" | "content" | "count";
  maxMatches?: number;
}

export async function grepFilesTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  opts: GrepOptions,
): Promise<{
  mode: "files_with_matches" | "content" | "count";
  matches: string[];
  truncated: boolean;
}> {
  const mode = opts.mode ?? "content";
  const maxMatches = Math.max(1, Math.min(opts.maxMatches ?? 100, 500));
  const contextLines = Math.max(0, Math.min(opts.contextLines ?? 0, 5));
  const isGitignored = loadGitignoreMatcher(workspaceRoot);
  const re = new RegExp(opts.pattern, opts.caseInsensitive ? "i" : "");
  const glob = new Bun.Glob(opts.glob ?? "**/*");

  const results: string[] = [];
  let charCount = 0;
  let truncated = false;

  for await (const rawRel of glob.scan({
    cwd: workspaceRoot,
    onlyFiles: true,
    dot: true,
    followSymlinks: false,
  })) {
    const relPosix = rawRel.replaceAll("\\", "/");
    if (
      isIgnoredRelativePath(relPosix, deniedPatterns) ||
      isGitignored(relPosix)
    )
      continue;

    let resolvedPath: string;
    try {
      const fullPath = join(workspaceRoot, rawRel);
      const combinedDenied = [
        ...deniedPatterns,
        ...INTERNAL_PROTECTED_PATTERNS,
      ];
      const res = resolveInsideRoots(
        fullPath,
        [workspaceRoot],
        process.platform,
        combinedDenied,
      );
      resolvedPath = res.resolvedPath;
      const stat = statSync(resolvedPath);
      if (!stat.isFile() || stat.size > MAX_READ_FILE_BYTES) continue;
    } catch {
      continue;
    }

    const bytes = await Bun.file(resolvedPath).bytes();
    const decoded = isBinaryOrInvalidUtf8(bytes);
    if (!decoded.valid) continue;

    const lines = decoded.text.split(/\r?\n/);
    const matchedIndices: number[] = [];
    for (let i = 0; i < lines.length; i += 1) {
      if (re.test(lines[i] ?? "")) {
        matchedIndices.push(i);
      }
    }

    if (matchedIndices.length === 0) continue;

    if (mode === "files_with_matches") {
      results.push(relPosix);
      charCount += relPosix.length + 1;
    } else if (mode === "count") {
      const entry = `${relPosix}:${matchedIndices.length}`;
      results.push(entry);
      charCount += entry.length + 1;
    } else {
      for (const idx of matchedIndices) {
        const start = Math.max(0, idx - contextLines);
        const end = Math.min(lines.length - 1, idx + contextLines);
        const block = [];
        for (let ln = start; ln <= end; ln += 1) {
          const sep = ln === idx ? ":" : "-";
          block.push(`${relPosix}:${ln + 1}${sep}${lines[ln] ?? ""}`);
        }
        const entry = block.join("\n");
        if (
          charCount + entry.length > MAX_GREP_OUTPUT_CHARS ||
          results.length >= maxMatches
        ) {
          truncated = true;
          break;
        }
        results.push(entry);
        charCount += entry.length + 1;
      }
    }

    if (
      truncated ||
      results.length >= maxMatches ||
      charCount >= MAX_GREP_OUTPUT_CHARS
    ) {
      truncated = true;
      break;
    }
  }

  return { mode, matches: results, truncated };
}
