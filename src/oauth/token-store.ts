import {
  closeSync,
  constants as fsConstants,
  fchmodSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { sha256Hex } from "../security/crypto.ts";
import { assertFileOutsideAllowedRoots } from "../workspace/paths.ts";

export interface PersistedTokenRecord {
  clientId: string;
  scope: string;
  expiresAt: number;
}

interface PersistedTokenPayload {
  version: 1;
  accessTokens: Record<string, PersistedTokenRecord>;
  refreshTokens: Record<string, PersistedTokenRecord>;
}

const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

export function defaultTokenStorePath(clientId: string): string {
  const suffix = sha256Hex(clientId).slice(0, 12);
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

export class HashedTokenStore {
  readonly filePath: string;

  constructor(
    filePath: string,
    allowedRoots: string[],
    platform: NodeJS.Platform = process.platform,
  ) {
    this.filePath = assertFileOutsideAllowedRoots(
      filePath,
      allowedRoots,
      "OAuth token store file",
      platform,
    );
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
    if (obj.version !== 1) {
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
      accessTokens: mapToPrunedRecord(accessTokens, now),
      refreshTokens: mapToPrunedRecord(refreshTokens, now),
    };

    const noFollowFlag =
      process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
        ? fsConstants.O_NOFOLLOW
        : 0;
    const fd = openSync(
      this.filePath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        noFollowFlag,
      0o600,
    );
    try {
      if (process.platform !== "win32") {
        fchmodSync(fd, 0o600);
      }
      writeFileSync(fd, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
    } finally {
      closeSync(fd);
    }
  }
}
