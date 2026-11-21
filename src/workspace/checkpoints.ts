import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { generateRandomToken } from "../security/crypto.ts";
import { resolveWritablePathInsideRoot } from "./paths.ts";

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

function getCheckpointsRoot(workspaceRoot: string): string {
  return join(workspaceRoot, CHECKPOINTS_REL_DIR);
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
  const checkpointsRoot = getCheckpointsRoot(workspaceRoot);
  mkdirSync(checkpointsRoot, { recursive: true });

  const id = `cp_${Date.now().toString(36)}_${generateRandomToken(6)}`;
  const cpDir = join(checkpointsRoot, id);
  mkdirSync(cpDir, { recursive: true });

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
    await Bun.write(join(cpDir, "snapshot.bin"), bytes);
  }

  const meta: CheckpointMeta = {
    id,
    createdAt: new Date().toISOString(),
    reason,
    relativePath: relative(workspaceRoot, resolvedTargetPath).replaceAll("\\", "/"),
    existedBefore,
    sizeBytes,
  };

  writeFileSync(join(cpDir, "meta.json"), JSON.stringify(meta, null, 2), "utf8");
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
  const metaPath = join(cpDir, "meta.json");
  if (!existsSync(metaPath)) {
    throw new Error(`Checkpoint "${checkpointId}" not found.`);
  }

  const meta = JSON.parse(readFileSync(metaPath, "utf8")) as CheckpointMeta;
  const targetPath = resolveWritablePathInsideRoot(meta.relativePath, workspaceRoot, deniedPatterns);

  if (!meta.existedBefore) {
    if (existsSync(targetPath)) {
      rmSync(targetPath, { force: true });
    }
    return { checkpointId, relativePath: meta.relativePath, action: "deleted" };
  }

  const snapshotPath = join(cpDir, "snapshot.bin");
  if (!existsSync(snapshotPath)) {
    throw new Error(`Snapshot payload missing for checkpoint "${checkpointId}".`);
  }

  mkdirSync(dirname(targetPath), { recursive: true });
  const bytes = await Bun.file(snapshotPath).bytes();
  await Bun.write(targetPath, bytes);
  return { checkpointId, relativePath: meta.relativePath, action: "restored" };
}
