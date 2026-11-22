import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_DENIED_PATH_PATTERNS } from "../src/config.ts";
import {
  initializeWorkspace,
  type WorkspaceState,
} from "../src/workspace/init.ts";
import {
  MEMORY_MAX_BYTES,
  normalizeWorkspaceSlug,
} from "../src/workspace/memory.ts";
import {
  isPathDenied,
  isPathInsideRoot,
  resolveInsideRoots,
} from "../src/workspace/paths.ts";

describe("workspace path boundaries, memory layout, and init", () => {
  let baseDir: string;
  let allowedRoot: string;
  let siblingRoot: string;
  let centralMemoryRoot: string;
  let projectDir: string;
  let symlinkMemoryProject: string;
  let hugeMemoryProject: string;

  beforeAll(() => {
    baseDir = mkdtempSync(join(tmpdir(), "justnewmcp-test-"));
    allowedRoot = join(baseDir, "projects");
    siblingRoot = join(baseDir, "projects-evil");
    centralMemoryRoot = join(baseDir, "JustNewMCP-Memory");
    projectDir = join(allowedRoot, "demo-app");
    symlinkMemoryProject = join(allowedRoot, "symlink-memory-app");
    hugeMemoryProject = join(allowedRoot, "huge-memory-app");

    mkdirSync(
      join(projectDir, ".justnewmcp", "memory", "how-to-use-user-machine"),
      { recursive: true },
    );
    mkdirSync(join(symlinkMemoryProject, ".justnewmcp", "memory"), {
      recursive: true,
    });
    mkdirSync(join(hugeMemoryProject, ".justnewmcp", "memory"), {
      recursive: true,
    });
    mkdirSync(siblingRoot, { recursive: true });
    mkdirSync(centralMemoryRoot, { recursive: true });

    writeFileSync(
      join(projectDir, "AGENTS.md"),
      "# Rules\nUse bun test.\n",
      "utf8",
    );
    writeFileSync(join(projectDir, ".env"), "SECRET=123\n", "utf8");
    writeFileSync(
      join(projectDir, ".justnewmcp", "memory", "MEMORY.md"),
      "# Memory\nPort is 8787.\nSee how-to-use-user-machine/INDEX.md.\n",
      "utf8",
    );
    writeFileSync(
      join(
        projectDir,
        ".justnewmcp",
        "memory",
        "how-to-use-user-machine",
        "INDEX.md",
      ),
      "# Machine Guide\n",
      "utf8",
    );
    writeFileSync(
      join(siblingRoot, "outside-secret.txt"),
      "TOP_SECRET_OUTSIDE\n",
      "utf8",
    );
    symlinkSync(siblingRoot, join(allowedRoot, "escape-link"));
    symlinkSync(
      join(siblingRoot, "outside-secret.txt"),
      join(symlinkMemoryProject, ".justnewmcp", "memory", "MEMORY.md"),
    );

    // Oversized MEMORY.md (> 25 KiB) to verify bounded slice read
    writeFileSync(
      join(hugeMemoryProject, ".justnewmcp", "memory", "MEMORY.md"),
      "A".repeat(40_000),
      "utf8",
    );

    // Centralized memory directory using normalized slug of real projectDir
    const realProjectDir = realpathSync(projectDir);
    const slugDir = join(
      centralMemoryRoot,
      normalizeWorkspaceSlug(realProjectDir),
    );
    mkdirSync(join(slugDir, "deploy-notes"), { recursive: true });
    writeFileSync(
      join(slugDir, "MEMORY.md"),
      "# Central Memory\nStored outside repo.\n",
      "utf8",
    );
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("normalizes workspace paths into collision-resistant cross-platform slugs", () => {
    expect(
      normalizeWorkspaceSlug("C:\\Users\\vaiprog\\SomeCoolProject"),
    ).toMatch(/^c--users--vaiprog--somecoolproject--[0-9a-f]{8}$/);
    expect(normalizeWorkspaceSlug("/home/vaiprog/SomeCoolProject")).toMatch(
      /^home--vaiprog--SomeCoolProject--[0-9a-f]{8}$/,
    );
    // Distinct paths that share a readable prefix must never collide
    const slugSpace = normalizeWorkspaceSlug("/home/user/My App");
    const slugUnderscore = normalizeWorkspaceSlug("/home/user/My_App");
    expect(slugSpace).not.toBe(slugUnderscore);
    // Case-insensitive Windows paths resolve to the same slug
    expect(normalizeWorkspaceSlug("C:\\Users\\VAI\\App")).toBe(
      normalizeWorkspaceSlug("c:\\users\\vai\\app"),
    );
  });

  test("rejects sibling prefix and traversal paths", () => {
    expect(isPathInsideRoot(siblingRoot, allowedRoot)).toBe(false);
    expect(() => resolveInsideRoots(siblingRoot, [allowedRoot])).toThrow();
    expect(() =>
      resolveInsideRoots(join(allowedRoot, "..", "projects-evil"), [
        allowedRoot,
      ]),
    ).toThrow();
  });

  test("rejects symlink pointing outside allowed root", () => {
    expect(() =>
      resolveInsideRoots(join(allowedRoot, "escape-link"), [allowedRoot]),
    ).toThrow();
  });

  test("normalizes case and rejects cross-drive paths on win32", () => {
    expect(
      isPathInsideRoot(
        "C:\\Users\\VAI\\Projects\\App",
        "c:\\users\\vai\\projects",
        "win32",
      ),
    ).toBe(true);
    expect(
      isPathInsideRoot(
        "D:\\Users\\VAI\\Projects\\App",
        "c:\\users\\vai\\projects",
        "win32",
      ),
    ).toBe(false);
  });

  test("blocks sensitive secret paths via deniedPathPatterns", () => {
    expect(
      isPathDenied("/repo/.env", DEFAULT_DENIED_PATH_PATTERNS, "linux"),
    ).toBe(true);
    expect(
      isPathDenied(
        "/repo/.env.production",
        DEFAULT_DENIED_PATH_PATTERNS,
        "linux",
      ),
    ).toBe(true);
    expect(
      isPathDenied(
        "/repo/certs/private.key",
        DEFAULT_DENIED_PATH_PATTERNS,
        "linux",
      ),
    ).toBe(true);
    expect(
      isPathDenied("/repo/.git/config", DEFAULT_DENIED_PATH_PATTERNS, "linux"),
    ).toBe(true);
    expect(
      isPathDenied("/repo/src/index.ts", DEFAULT_DENIED_PATH_PATTERNS, "linux"),
    ).toBe(false);
    expect(() =>
      resolveInsideRoots(
        join(projectDir, ".env"),
        [allowedRoot],
        process.platform,
        DEFAULT_DENIED_PATH_PATTERNS,
      ),
    ).toThrow("blocked by security policy");
  });

  test("workspace_init loads workspace-local .justnewmcp/memory/MEMORY.md and topics", async () => {
    const state: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const result = await initializeWorkspace(projectDir, [allowedRoot], state, {
      deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS,
    });

    expect(state.activeRoot).toBe(result.workspace);
    expect(result.instructionFiles).toContain("AGENTS.md");
    expect(result.memoryPreview).toContain("Port is 8787.");
    expect(result.memoryTopics).toContain("how-to-use-user-machine/");
  });

  test("workspace_init loads centralized memoryDir/<normalized-slug>/MEMORY.md when configured", async () => {
    const state: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const result = await initializeWorkspace(projectDir, [allowedRoot], state, {
      deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      memoryDir: centralMemoryRoot,
    });

    expect(result.memoryPreview).toContain("Stored outside repo.");
    expect(result.memoryTopics).toContain("deploy-notes/");
  });

  test("workspace_init refuses to follow MEMORY.md symlink outside workspace root", async () => {
    const state: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const result = await initializeWorkspace(
      symlinkMemoryProject,
      [allowedRoot],
      state,
      {
        deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      },
    );

    expect(result.memoryPreview).toBeNull();
  });

  test("workspace_init bounds MEMORY.md disk read to 25 KiB", async () => {
    const state: WorkspaceState = {
      activeRoot: null,
      matchedAllowedRoot: null,
    };
    const result = await initializeWorkspace(
      hugeMemoryProject,
      [allowedRoot],
      state,
      {
        deniedPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      },
    );

    expect(result.memoryPreview).not.toBeNull();
    expect(Buffer.byteLength(result.memoryPreview ?? "", "utf8")).toBe(
      MEMORY_MAX_BYTES,
    );
  });
});
