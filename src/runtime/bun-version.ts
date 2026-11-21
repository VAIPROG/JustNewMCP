export interface Semver {
  major: number;
  minor: number;
  patch: number;
}

export function parseSemver(version: string): Semver {
  const match = version.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    throw new Error(`Invalid Bun version string: "${version}"`);
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

export function isVersionAtLeast(current: string, minimum: string): boolean {
  const a = parseSemver(current);
  const b = parseSemver(minimum);
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  return a.patch >= b.patch;
}

export function ensureBunVersion(minimum = "1.4.0"): string {
  const current = typeof Bun !== "undefined" ? Bun.version : "";
  if (!current) {
    throw new Error(`JustNewMCP requires Bun >= ${minimum}, but Bun runtime was not detected.`);
  }
  if (!isVersionAtLeast(current, minimum)) {
    throw new Error(`JustNewMCP requires Bun >= ${minimum}, found ${current}.`);
  }
  return current;
}
