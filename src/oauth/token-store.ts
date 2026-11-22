import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  generateRandomToken,
  sha256Hex,
  timingSafeEqualStrings,
} from "../security/crypto.ts";
import { assertFileOutsideAllowedRoots } from "../workspace/paths.ts";

export interface PersistedTokenRecord {
  clientId: string;
  scope: string;
  expiresAt: number;
}

interface PersistedTokenPayload {
  version: 1;
  serverIdentity: string;
  accessTokens: Record<string, PersistedTokenRecord>;
  refreshTokens: Record<string, PersistedTokenRecord>;
}

const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

export function computeServerIdentity(
  publicUrl: string,
  clientId: string,
  clientSecret: string,
): string {
  return sha256Hex(`${publicUrl}\0${clientId}\0${sha256Hex(clientSecret)}`);
}

export function defaultTokenStorePath(serverIdentity: string): string {
  const suffix = serverIdentity.slice(0, 12);
  return join(homedir(), ".justnewmcp", `oauth-tokens-${suffix}.json`);
}

function parseTokenRecordMap(
  raw: unknown,
  now: number,
): Map<string, PersistedTokenRecord> {
  const result = new Map<string, PersistedTokenRecord>();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return result;
  }
  for (const [hash, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!SHA256_HEX_RE.test(hash)) continue;
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    const rec = value as Record<string, unknown>;
    if (
      typeof rec.clientId !== "string" ||
      typeof rec.scope !== "string" ||
      typeof rec.expiresAt !== "number" ||
      !Number.isFinite(rec.expiresAt) ||
      rec.expiresAt <= now
    ) {
      continue;
    }
    result.set(hash, {
      clientId: rec.clientId,
      scope: rec.scope,
      expiresAt: rec.expiresAt,
    });
  }
  return result;
}

function mapToPrunedRecord(
  map: Map<string, PersistedTokenRecord>,
  now: number,
): Record<string, PersistedTokenRecord> {
  const out: Record<string, PersistedTokenRecord> = {};
  for (const [hash, record] of map) {
    if (record.expiresAt > now) {
      out[hash] = {
        clientId: record.clientId,
        scope: record.scope,
        expiresAt: record.expiresAt,
      };
    }
  }
  return out;
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

export class HashedTokenStore {
  readonly filePath: string;
  private readonly lockPath: string;
  private readonly serverIdentity: string;
  private lockHeld = false;

  constructor(
    filePath: string,
    allowedRoots: string[],
    serverIdentity: string,
    platform: NodeJS.Platform = process.platform,
  ) {
    this.filePath = assertFileOutsideAllowedRoots(
      filePath,
      allowedRoots,
      "OAuth token store file",
      platform,
    );
    this.lockPath = `${this.filePath}.lock`;
    this.serverIdentity = serverIdentity;
    this.acquireLock();
  }

  private acquireLock(): void {
    mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 });
    const noFollowFlag =
      process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
    const payload = `${JSON.stringify({ pid: process.pid, startedAt: Date.now() })}\n`;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const fd = openSync(
          this.lockPath,
          fsConstants.O_WRONLY |
            fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            noFollowFlag,
          0o600,
        );
        try {
          if (process.platform !== "win32") {
            fchmodSync(fd, 0o600);
          }
          writeFileSync(fd, payload, "utf8");
        } catch (writeErr) {
          closeSync(fd);
          rmSync(this.lockPath, { force: true });
          throw writeErr;
        }
        closeSync(fd);
        this.lockHeld = true;
        return;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") {
          throw err;
        }
        const readOwnerPid = (): number | undefined => {
          try {
            const raw = readFileSync(this.lockPath, "utf8");
            const parsed = JSON.parse(raw) as { pid?: unknown };
            return typeof parsed.pid === "number" ? parsed.pid : undefined;
          } catch {
            return undefined;
          }
        };
        const existingPid = readOwnerPid();
        if (
          existingPid !== undefined &&
          existingPid !== process.pid &&
          !isProcessAlive(existingPid)
        ) {
          const reclaimPath = `${this.lockPath}.reclaim`;
          let reclaimFd: number | undefined;
          try {
            reclaimFd = openSync(
              reclaimPath,
              fsConstants.O_WRONLY |
                fsConstants.O_CREAT |
                fsConstants.O_EXCL |
                noFollowFlag,
              0o600,
            );
            const recheckedPid = readOwnerPid();
            if (recheckedPid === existingPid && !isProcessAlive(recheckedPid)) {
              rmSync(this.lockPath, { force: true });
              continue;
            }
          } catch (reclaimErr) {
            if ((reclaimErr as NodeJS.ErrnoException).code !== "EEXIST") {
              throw reclaimErr;
            }
          } finally {
            if (reclaimFd !== undefined) {
              closeSync(reclaimFd);
              rmSync(reclaimPath, { force: true });
            }
          }
        }
        throw new Error(
          `OAuth token store "${this.filePath}" is already in use by another server instance${existingPid ? ` (PID ${existingPid})` : ""}. Use a distinct oauth.tokenStorePath or set oauth.inMemoryTokens: true.`,
        );
      }
    }
  }

  close(): void {
    if (!this.lockHeld) return;
    this.lockHeld = false;
    rmSync(this.lockPath, { force: true });
  }

  load(now = Date.now()): {
    accessTokens: Map<string, PersistedTokenRecord>;
    refreshTokens: Map<string, PersistedTokenRecord>;
  } {
    const noFollowFlag =
      process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
    const nonBlockFlag =
      process.platform !== "win32" && typeof fsConstants.O_NONBLOCK === "number"
        ? fsConstants.O_NONBLOCK
        : 0;

    let fd: number;
    try {
      fd = openSync(
        this.filePath,
        fsConstants.O_RDONLY | noFollowFlag | nonBlockFlag,
      );
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        return {
          accessTokens: new Map(),
          refreshTokens: new Map(),
        };
      }
      throw err;
    }

    let text: string;
    try {
      const stats = fstatSync(fd);
      if (!stats.isFile()) {
        throw new Error(
          `OAuth token store "${this.filePath}" must be a regular file.`,
        );
      }
      text = readFileSync(fd, "utf8");
    } finally {
      closeSync(fd);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return {
        accessTokens: new Map(),
        refreshTokens: new Map(),
      };
    }

    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        accessTokens: new Map(),
        refreshTokens: new Map(),
      };
    }

    const obj = parsed as Record<string, unknown>;
    if (
      obj.version !== 1 ||
      typeof obj.serverIdentity !== "string" ||
      !timingSafeEqualStrings(obj.serverIdentity, this.serverIdentity)
    ) {
      return {
        accessTokens: new Map(),
        refreshTokens: new Map(),
      };
    }

    return {
      accessTokens: parseTokenRecordMap(obj.accessTokens, now),
      refreshTokens: parseTokenRecordMap(obj.refreshTokens, now),
    };
  }

  save(
    accessTokens: Map<string, PersistedTokenRecord>,
    refreshTokens: Map<string, PersistedTokenRecord>,
    now = Date.now(),
  ): void {
    const dir = dirname(this.filePath);
    mkdirSync(dir, { recursive: true, mode: 0o700 });

    const payload: PersistedTokenPayload = {
      version: 1,
      serverIdentity: this.serverIdentity,
      accessTokens: mapToPrunedRecord(accessTokens, now),
      refreshTokens: mapToPrunedRecord(refreshTokens, now),
    };

    const noFollowFlag =
      process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
    const tmpPath = `${this.filePath}.${process.pid}.${generateRandomToken(8)}.tmp`;
    const fd = openSync(
      tmpPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        noFollowFlag,
      0o600,
    );
    try {
      if (process.platform !== "win32") {
        fchmodSync(fd, 0o600);
      }
      writeFileSync(fd, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
      fsyncSync(fd);
    } catch (err) {
      closeSync(fd);
      rmSync(tmpPath, { force: true });
      throw err;
    }
    closeSync(fd);

    try {
      renameSync(tmpPath, this.filePath);
    } catch (err) {
      rmSync(tmpPath, { force: true });
      throw err;
    }
  }
}
