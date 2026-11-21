import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { generateRandomToken } from "../security/crypto.ts";
import { isEnvSecretPath, isPathInsideRoot, resolveWritablePathInsideRoot } from "./paths.ts";

export interface CheckpointMeta {
  id: string;
  createdAt: string;
  reason: string;
  relativePath: string;
  existedBefore: boolean;
  sizeBytes: number;
}

const CHECKPOINTS_REL_DIR = join(".justnewmcp", "checkpoints");
const MAX_CHECKPOINTS = 100;
const MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024;
const CHECKPOINT_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;

function assertNotSymlink(targetPath: string): void {
  try {
    if (lstatSync(targetPath).isSymbolicLink()) {
      throw new Error(`Checkpoint directory "${targetPath}" must not be a symlink.`);
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }
}

function getCheckpointsRoot(workspaceRoot: string, create = false): string {
  const realWorkspace = realpathSync(resolve(workspaceRoot));
  const metaDir = join(realWorkspace, ".justnewmcp");
  const checkpointsRoot = join(realWorkspace, CHECKPOINTS_REL_DIR);

  assertNotSymlink(metaDir);
  assertNotSymlink(checkpointsRoot);

  if (create) {
    mkdirSync(checkpointsRoot, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      chmodSync(checkpointsRoot, 0o700);
    }
  }

  if (existsSync(checkpointsRoot)) {
    const realCheckpoints = realpathSync(checkpointsRoot);
    if (!isPathInsideRoot(realCheckpoints, realWorkspace)) {
      throw new Error("Checkpoint directory resolves outside the active workspace.");
    }
    return realCheckpoints;
  }

  return checkpointsRoot;
}

function pruneOldCheckpoints(checkpointsRoot: string): void {
  if (!existsSync(checkpointsRoot)) return;
  const entries = readdirSync(checkpointsRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => {
      const metaPath = join(checkpointsRoot, d.name, "meta.json");
      let createdAt = "";
      try {
        const meta = JSON.parse(readFileSync(metaPath, "utf8")) as CheckpointMeta;
        createdAt = meta.createdAt;
      } catch {
        createdAt = "";
      }
      return { name: d.name, createdAt };
    })
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  for (const stale of entries.slice(MAX_CHECKPOINTS)) {
    rmSync(join(checkpointsRoot, stale.name), { recursive: true, force: true });
  }
}

export async function createCheckpoint(
  workspaceRoot: string,
  resolvedTargetPath: string,
  reason: string,
): Promise<CheckpointMeta> {
  const checkpointsRoot = getCheckpointsRoot(workspaceRoot, true);

  const id = `cp_${Date.now().toString(36)}_${generateRandomToken(6)}`;
  const cpDir = join(checkpointsRoot, id);
  mkdirSync(cpDir, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    chmodSync(cpDir, 0o700);
  }

  const existedBefore = existsSync(resolvedTargetPath);
  let sizeBytes = 0;

  if (existedBefore) {
    const stat = statSync(resolvedTargetPath);
    if (!stat.isFile()) {
      throw new Error(`Cannot checkpoint non-file path "${resolvedTargetPath}".`);
    }
    if (stat.size > MAX_SNAPSHOT_BYTES) {
      throw new Error(`File exceeds maximum checkpoint size of ${MAX_SNAPSHOT_BYTES} bytes.`);
    }
    sizeBytes = stat.size;
    const bytes = await Bun.file(resolvedTargetPath).bytes();
    const snapshotPath = join(cpDir, "snapshot.bin");
    writeFileSync(snapshotPath, bytes, { mode: 0o600 });
    if (process.platform !== "win32") {
      chmodSync(snapshotPath, 0o600);
    }
  }

  const meta: CheckpointMeta = {
    id,
    createdAt: new Date().toISOString(),
    reason,
    relativePath: relative(workspaceRoot, resolvedTargetPath).replaceAll("\\", "/"),
    existedBefore,
    sizeBytes,
  };

  const metaPath = join(cpDir, "meta.json");
  writeFileSync(metaPath, JSON.stringify(meta, null, 2), { encoding: "utf8", mode: 0o600 });
  if (process.platform !== "win32") {
    chmodSync(metaPath, 0o600);
  }
  pruneOldCheckpoints(checkpointsRoot);
  return meta;
}

export function listCheckpoints(workspaceRoot: string, limit = 20): CheckpointMeta[] {
  const checkpointsRoot = getCheckpointsRoot(workspaceRoot);
  if (!existsSync(checkpointsRoot)) return [];

  const capped = Math.max(1, Math.min(limit, MAX_CHECKPOINTS));
  const metas: CheckpointMeta[] = [];

  for (const entry of readdirSync(checkpointsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const metaPath = join(checkpointsRoot, entry.name, "meta.json");
    if (!existsSync(metaPath)) continue;
    try {
      metas.push(JSON.parse(readFileSync(metaPath, "utf8")) as CheckpointMeta);
    } catch {
      continue;
    }
  }

  return metas.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, capped);
}

export async function rewindCheckpoint(
  workspaceRoot: string,
  checkpointId: string,
  deniedPatterns: string[] = [],
): Promise<{ checkpointId: string; relativePath: string; action: "restored" | "deleted" }> {
  if (!CHECKPOINT_ID_RE.test(checkpointId)) {
    throw new Error(`Invalid checkpoint ID "${checkpointId}".`);
  }

  const cpDir = join(getCheckpointsRoot(workspaceRoot), checkpointId);
  assertNotSymlink(cpDir);
  const metaPath = join(cpDir, "meta.json");
  assertNotSymlink(metaPath);
  if (!existsSync(metaPath)) {
    throw new Error(`Checkpoint "${checkpointId}" not found.`);
  }

  const meta = JSON.parse(readFileSync(metaPath, "utf8")) as CheckpointMeta;
  const effectiveDenied = isEnvSecretPath(meta.relativePath)
    ? deniedPatterns.filter((p) => {
        const clean = p.trim().toLowerCase();
        return clean !== ".env" && clean !== ".env.*";
      })
    : deniedPatterns;
  const targetPath = resolveWritablePathInsideRoot(meta.relativePath, workspaceRoot, effectiveDenied);

  if (!meta.existedBefore) {
    if (existsSync(targetPath)) {
      rmSync(targetPath, { force: true });
    }
    return { checkpointId, relativePath: meta.relativePath, action: "deleted" };
  }

  const snapshotPath = join(cpDir, "snapshot.bin");
  assertNotSymlink(snapshotPath);
  if (!existsSync(snapshotPath)) {
    throw new Error(`Snapshot payload missing for checkpoint "${checkpointId}".`);
  }

  mkdirSync(dirname(targetPath), { recursive: true });
  const existedBeforeRewind = existsSync(targetPath);
  const bytes = await Bun.file(snapshotPath).bytes();
  if (!existedBeforeRewind && isEnvSecretPath(targetPath) && process.platform !== "win32") {
    writeFileSync(targetPath, bytes, { mode: 0o600 });
    chmodSync(targetPath, 0o600);
  } else {
    await Bun.write(targetPath, bytes);
  }
  return { checkpointId, relativePath: meta.relativePath, action: "restored" };
}
