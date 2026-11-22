export function isVersionAtLeast(current: string, minimum: string): boolean {
  return Bun.semver.satisfies(current.trim(), `>=${minimum.trim()}`);
}

export function ensureBunVersion(minimum = "1.4.0"): string {
  const current = typeof Bun !== "undefined" ? Bun.version : "";
  if (!current) {
    throw new Error(
      `JustNewMCP requires Bun >= ${minimum}, but Bun runtime was not detected.`,
    );
  }
  if (!isVersionAtLeast(current, minimum)) {
    throw new Error(`JustNewMCP requires Bun >= ${minimum}, found ${current}.`);
  }
  return current;
}
