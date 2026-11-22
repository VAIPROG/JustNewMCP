import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  statSync,
  writeSync,
} from "node:fs";
import path, { join, relative, resolve } from "node:path";
import { isPathDenied, isPathInsideRoot, resolveInsideRoots } from "./paths.ts";

export const MEMORY_MAX_LINES = 200;
export const MEMORY_MAX_BYTES = 25 * 1024;
export const MAX_MEMORY_FILE_BYTES = 256 * 1024;
const MAX_MEMORY_SEARCH_CHARS = 30_000;

const utf8FatalDecoder = new TextDecoder("utf-8", { fatal: true });
const memoryWriteLocks = new Map<string, Promise<void>>();

async function withMemoryWriteLock<T>(
  lockKey: string,
  fn: () => Promise<T> | T,
): Promise<T> {
  const prev = memoryWriteLocks.get(lockKey) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolveLock) => {
    release = resolveLock;
  });
  const tail = prev.then(() => current);
  memoryWriteLocks.set(lockKey, tail);

  await prev;
  try {
    return await fn();
  } finally {
    release();
    if (memoryWriteLocks.get(lockKey) === tail) {
      memoryWriteLocks.delete(lockKey);
    }
  }
}

function readAllFromFd(fd: number, expectedSize: number): Uint8Array {
  const buf = Buffer.alloc(expectedSize);
  let offset = 0;
  while (offset < expectedSize) {
    const bytesRead = readSync(fd, buf, offset, expectedSize - offset, offset);
    if (bytesRead <= 0) break;
    offset += bytesRead;
  }
  return offset === expectedSize ? buf : buf.subarray(0, offset);
}

function writeAllToFd(fd: number, data: Buffer): void {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = writeSync(
      fd,
      data,
      offset,
      data.byteLength - offset,
      offset,
    );
    if (written <= 0) {
      throw new Error("Short write while updating memory file.");
    }
    offset += written;
  }
}

export function normalizeWorkspaceSlug(workspacePath: string): string {
  const trimmed = workspacePath.trim().replace(/[/\\]+$/, "");
  const isWindowsPath = /^[A-Za-z]:[/\\]/.test(trimmed);
  const hashInput = isWindowsPath
    ? trimmed.replaceAll("\\", "/").toLowerCase()
    : trimmed;
  const shortHash = new Bun.CryptoHasher("sha256")
    .update(hashInput, "utf8")
    .digest("hex")
    .slice(0, 8);

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

function assertNotSymlink(targetPath: string): void {
  try {
    if (lstatSync(targetPath).isSymbolicLink()) {
      throw new Error(`Memory path "${targetPath}" must not be a symlink.`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function ensureMemoryDirSafe(
  workspaceDir: string,
  memoryRoot: string | undefined,
  create: boolean,
): { memoryDir: string; boundaryRoot: string } {
  if (memoryRoot && create && !existsSync(resolve(memoryRoot))) {
    mkdirSync(resolve(memoryRoot), { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      chmodSync(resolve(memoryRoot), 0o700);
    }
  }
  const { memoryDir, boundaryRoot } = resolveMemoryDirectory(
    workspaceDir,
    memoryRoot,
  );
  const realBoundary = realpathSync(resolve(boundaryRoot));

  if (!memoryRoot) {
    assertNotSymlink(join(realBoundary, ".justnewmcp"));
  }
  assertNotSymlink(memoryDir);

  if (create) {
    mkdirSync(memoryDir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      chmodSync(memoryDir, 0o700);
    }
  }

  if (existsSync(memoryDir)) {
    const realMem = realpathSync(memoryDir);
    if (!isPathInsideRoot(realMem, realBoundary)) {
      throw new Error(
        "Memory directory resolves outside its allowed boundary.",
      );
    }
    return { memoryDir: realMem, boundaryRoot: realBoundary };
  }

  return { memoryDir, boundaryRoot: realBoundary };
}

function validateRelativeMemorySubpath(inputPath: string): string[] {
  const trimmed = inputPath.trim();
  if (!trimmed || path.isAbsolute(trimmed) || /^[A-Za-z]:/.test(trimmed)) {
    throw new Error(
      `Memory path "${inputPath}" must be a relative path inside the project memory directory.`,
    );
  }
  if (trimmed.includes("\0")) {
    throw new Error("Memory path must not contain NUL bytes.");
  }
  const segments = trimmed.replaceAll("\\", "/").split("/").filter(Boolean);
  if (segments.length === 0 || segments.some((s) => s === "." || s === "..")) {
    throw new Error(
      `Memory path "${inputPath}" contains disallowed traversal segments.`,
    );
  }
  return segments;
}

function ensureNestedDirsNoSymlinks(
  baseDir: string,
  dirSegments: string[],
): string {
  let current = baseDir;
  for (const segment of dirSegments) {
    current = join(current, segment);
    assertNotSymlink(current);
    if (!existsSync(current)) {
      mkdirSync(current, { mode: 0o700 });
      if (process.platform !== "win32") {
        chmodSync(current, 0o700);
      }
    } else if (!statSync(current).isDirectory()) {
      throw new Error(`Memory path segment "${segment}" is not a directory.`);
    }
  }
  return current;
}

function decodeUtf8Strict(bytes: Uint8Array): string {
  const sampleLen = Math.min(bytes.byteLength, 8192);
  for (let i = 0; i < sampleLen; i += 1) {
    if (bytes[i] === 0) {
      throw new Error("Memory file appears to be binary.");
    }
  }
  try {
    return utf8FatalDecoder.decode(bytes);
  } catch {
    throw new Error("Memory file is not valid UTF-8.");
  }
}

export function listMemoryTopics(
  memoryDir: string,
  boundaryRoot: string,
): string[] {
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
  const { memoryDir, boundaryRoot } = resolveMemoryDirectory(
    workspaceDir,
    options.memoryRoot,
  );
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
  const boundedText = await Bun.file(resolvedMemoryPath)
    .slice(0, MEMORY_MAX_BYTES)
    .text();
  const preview = boundedText
    .split(/\r?\n/)
    .slice(0, MEMORY_MAX_LINES)
    .join("\n");
  return { memoryDir, preview, topics };
}

export async function memoryReadTool(
  workspaceDir: string,
  memoryRoot: string | undefined,
  opts: {
    path?: string;
    offset?: number;
    limit?: number;
    deniedPatterns?: string[];
  } = {},
): Promise<{
  memoryDir: string;
  path: string;
  startLine: number;
  endLine: number;
  totalLines: number;
  hasMore: boolean;
  content: string;
}> {
  const relPath = opts.path ?? "MEMORY.md";
  const deniedPatterns = opts.deniedPatterns ?? [];
  const segments = validateRelativeMemorySubpath(relPath);
  const { memoryDir } = ensureMemoryDirSafe(workspaceDir, memoryRoot, false);

  const candidate = join(memoryDir, ...segments);
  assertNotSymlink(candidate);
  if (deniedPatterns.length > 0 && isPathDenied(candidate, deniedPatterns)) {
    throw new Error(`Memory path "${relPath}" is blocked by security policy.`);
  }
  if (!existsSync(candidate)) {
    throw new Error(`Memory file "${relPath}" not found.`);
  }

  const { resolvedPath } = resolveInsideRoots(
    candidate,
    [memoryDir],
    process.platform,
    deniedPatterns,
  );
  const stat = statSync(resolvedPath);
  if (!stat.isFile()) {
    throw new Error(`Memory path "${relPath}" is not a regular file.`);
  }
  if (stat.size > MAX_MEMORY_FILE_BYTES) {
    throw new Error(
      `Memory file "${relPath}" exceeds ${MAX_MEMORY_FILE_BYTES} bytes.`,
    );
  }

  const bytes = await Bun.file(resolvedPath).bytes();
  const text = decodeUtf8Strict(bytes);
  const allLines = text === "" ? [] : text.replace(/\r?\n$/, "").split(/\r?\n/);
  const startLine = Math.max(1, opts.offset ?? 1);
  const limit = Math.max(1, Math.min(opts.limit ?? 200, 2000));
  const slice = allLines.slice(startLine - 1, startLine - 1 + limit);
  const numbered = slice
    .map((line, i) => `${String(startLine + i).padStart(4, " ")} | ${line}`)
    .join("\n");

  const endLine = slice.length > 0 ? startLine + slice.length - 1 : 0;
  return {
    memoryDir,
    path: relative(memoryDir, resolvedPath).replaceAll("\\", "/"),
    startLine,
    endLine,
    totalLines: allLines.length,
    hasMore: startLine - 1 + slice.length < allLines.length,
    content: numbered,
  };
}

export async function memoryWriteTool(
  workspaceDir: string,
  memoryRoot: string | undefined,
  opts: {
    path?: string;
    content: string;
    mode?: "overwrite" | "append";
    deniedPatterns?: string[];
  },
): Promise<{
  memoryDir: string;
  path: string;
  mode: "overwrite" | "append";
  bytesWritten: number;
}> {
  const relPath = opts.path ?? "MEMORY.md";
  const mode = opts.mode ?? "overwrite";
  const deniedPatterns = opts.deniedPatterns ?? [];
  const segments = validateRelativeMemorySubpath(relPath);

  const incomingBytes = Buffer.byteLength(opts.content, "utf8");
  if (incomingBytes > MAX_MEMORY_FILE_BYTES) {
    throw new Error(`Memory content exceeds ${MAX_MEMORY_FILE_BYTES} bytes.`);
  }

  const plannedMemoryDir = memoryRoot
    ? join(
        existsSync(resolve(memoryRoot))
          ? realpathSync(resolve(memoryRoot))
          : resolve(memoryRoot),
        normalizeWorkspaceSlug(workspaceDir),
      )
    : join(workspaceDir, ".justnewmcp", "memory");
  const plannedTarget = join(plannedMemoryDir, ...segments);
  if (
    deniedPatterns.length > 0 &&
    isPathDenied(plannedTarget, deniedPatterns)
  ) {
    throw new Error(`Memory path "${relPath}" is blocked by security policy.`);
  }

  const normalizedLockKey =
    process.platform === "win32" ? plannedTarget.toLowerCase() : plannedTarget;

  return withMemoryWriteLock(normalizedLockKey, () => {
    // Keep all ancestor checks, openSync, optional append read, and write synchronous
    // inside the per-target lock so no await yields between directory anchoring and open.
    const { memoryDir } = ensureMemoryDirSafe(workspaceDir, memoryRoot, true);
    const candidateTarget = join(memoryDir, ...segments);
    if (
      deniedPatterns.length > 0 &&
      isPathDenied(candidateTarget, deniedPatterns)
    ) {
      throw new Error(
        `Memory path "${relPath}" is blocked by security policy.`,
      );
    }

    const parentDir = ensureNestedDirsNoSymlinks(
      memoryDir,
      segments.slice(0, -1),
    );
    const fileName = segments[segments.length - 1] ?? "MEMORY.md";
    const targetPath = join(parentDir, fileName);
    assertNotSymlink(targetPath);

    const noFollowFlag =
      process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
    const flags = fsConstants.O_RDWR | fsConstants.O_CREAT | noFollowFlag;
    const fd = openSync(targetPath, flags, 0o600);
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile()) {
        throw new Error(`Memory path "${relPath}" is not a regular file.`);
      }

      let finalContent = opts.content;
      if (mode === "append" && stat.size > 0) {
        if (stat.size > MAX_MEMORY_FILE_BYTES) {
          throw new Error(
            `Memory file "${relPath}" exceeds ${MAX_MEMORY_FILE_BYTES} bytes.`,
          );
        }
        const existingBytes = readAllFromFd(fd, stat.size);
        const existing = decodeUtf8Strict(existingBytes);
        const needsNewline = existing.length > 0 && !existing.endsWith("\n");
        finalContent = `${existing}${needsNewline ? "\n" : ""}${opts.content}`;
        if (Buffer.byteLength(finalContent, "utf8") > MAX_MEMORY_FILE_BYTES) {
          throw new Error(
            `Combined memory file would exceed ${MAX_MEMORY_FILE_BYTES} bytes.`,
          );
        }
      }

      const outBuffer = Buffer.from(finalContent, "utf8");
      if (process.platform !== "win32") {
        fchmodSync(fd, 0o600);
      }
      ftruncateSync(fd, 0);
      writeAllToFd(fd, outBuffer);

      return {
        memoryDir,
        path: relative(memoryDir, targetPath).replaceAll("\\", "/"),
        mode,
        bytesWritten: outBuffer.byteLength,
      };
    } finally {
      closeSync(fd);
    }
  });
}

export async function memorySearchTool(
  workspaceDir: string,
  memoryRoot: string | undefined,
  opts: {
    pattern: string;
    caseInsensitive?: boolean;
    maxMatches?: number;
    deniedPatterns?: string[];
  },
): Promise<{
  memoryDir: string;
  matches: string[];
  truncated: boolean;
}> {
  const deniedPatterns = opts.deniedPatterns ?? [];
  const { memoryDir } = ensureMemoryDirSafe(workspaceDir, memoryRoot, false);
  if (!existsSync(memoryDir)) {
    return { memoryDir, matches: [], truncated: false };
  }

  const maxMatches = Math.max(1, Math.min(opts.maxMatches ?? 50, 200));
  const re = new RegExp(opts.pattern, opts.caseInsensitive ? "i" : "");
  const glob = new Bun.Glob("**/*");

  const matches: string[] = [];
  let charCount = 0;
  let truncated = false;

  for await (const rawRel of glob.scan({
    cwd: memoryDir,
    onlyFiles: true,
    dot: false,
    followSymlinks: false,
  })) {
    const relPosix = rawRel.replaceAll("\\", "/");
    let resolvedPath: string;
    try {
      const fullPath = join(memoryDir, rawRel);
      assertNotSymlink(fullPath);
      resolvedPath = resolveInsideRoots(
        fullPath,
        [memoryDir],
        process.platform,
        deniedPatterns,
      ).resolvedPath;
      const stat = statSync(resolvedPath);
      if (!stat.isFile() || stat.size > MAX_MEMORY_FILE_BYTES) continue;
    } catch {
      continue;
    }

    let text: string;
    try {
      text = decodeUtf8Strict(await Bun.file(resolvedPath).bytes());
    } catch {
      continue;
    }

    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] ?? "";
      if (!re.test(line)) continue;
      const entry = `${relPosix}:${i + 1}:${line}`;
      if (
        charCount + entry.length > MAX_MEMORY_SEARCH_CHARS ||
        matches.length >= maxMatches
      ) {
        truncated = true;
        break;
      }
      matches.push(entry);
      charCount += entry.length + 1;
    }

    if (truncated) break;
  }

  return { memoryDir, matches, truncated };
}
