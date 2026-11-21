import { describe, expect, test } from "bun:test";
import { ensureBunVersion, isVersionAtLeast } from "../src/runtime/bun-version.ts";

describe("bun version guard", () => {
  test("compares semver strings accurately", () => {
    expect(isVersionAtLeast("1.4.0", "1.4.0")).toBe(true);
    expect(isVersionAtLeast("1.4.5", "1.4.0")).toBe(true);
    expect(isVersionAtLeast("2.0.0", "1.4.0")).toBe(true);
    expect(isVersionAtLeast("1.3.9", "1.4.0")).toBe(false);
    expect(isVersionAtLeast("0.9.9", "1.4.0")).toBe(false);
  });

  test("passes on current runtime (>= 1.4.0)", () => {
    const version = ensureBunVersion("1.4.0");
    expect(isVersionAtLeast(version, "1.4.0")).toBe(true);
  });
});
