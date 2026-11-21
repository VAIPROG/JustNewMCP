import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initializeWorkspace, type WorkspaceState } from "../src/workspace/init.ts";
import { isPathInsideRoot, resolveInsideRoots } from "../src/workspace/paths.ts";

describe("workspace path boundaries and init", () => {
  let baseDir: string;
  let allowedRoot: string;
  let siblingRoot: string;
  let projectDir: string;

  beforeAll(() => {
    baseDir = mkdtempSync(join(tmpdir(), "justnewmcp-test-"));
    allowedRoot = join(baseDir, "projects");
    siblingRoot = join(baseDir, "projects-evil");
    projectDir = join(allowedRoot, "demo-app");

    mkdirSync(join(projectDir, ".justnewmcp"), { recursive: true });
    mkdirSync(siblingRoot, { recursive: true });

    writeFileSync(join(projectDir, "AGENTS.md"), "# Rules\nUse bun test.\n", "utf8");
    writeFileSync(join(projectDir, ".justnewmcp", "MEMORY.md"), "# Memory\nPort is 8787.\n", "utf8");
    symlinkSync(siblingRoot, join(allowedRoot, "escape-link"));
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("rejects sibling prefix and traversal paths", () => {
    expect(isPathInsideRoot(siblingRoot, allowedRoot)).toBe(false);
    expect(() => resolveInsideRoots(siblingRoot, [allowedRoot])).toThrow();
    expect(() => resolveInsideRoots(join(allowedRoot, "..", "projects-evil"), [allowedRoot])).toThrow();
  });

  test("rejects symlink pointing outside allowed root", () => {
    expect(() => resolveInsideRoots(join(allowedRoot, "escape-link"), [allowedRoot])).toThrow();
  });

  test("normalizes case on win32 comparisons", () => {
    expect(isPathInsideRoot("C:\\Users\\VAI\\Projects\\App", "c:\\users\\vai\\projects", "win32")).toBe(true);
    expect(isPathInsideRoot("D:\\Users\\VAI\\Projects\\App", "c:\\users\\vai\\projects", "win32")).toBe(false);
  });

  test("workspace_init sets active root and reads instructions and memory", async () => {
    const state: WorkspaceState = { activeRoot: null, matchedAllowedRoot: null };
    const result = await initializeWorkspace(projectDir, [allowedRoot], state);

    expect(state.activeRoot).toBe(result.workspace);
    expect(result.instructionFiles).toContain("AGENTS.md");
    expect(result.memoryPreview).toContain("Port is 8787.");
  });
});
