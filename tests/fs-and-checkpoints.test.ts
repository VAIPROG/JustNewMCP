import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_ALLOWED_REDIRECT_URIS,
  DEFAULT_DENIED_PATH_PATTERNS,
  type AppConfig,
} from "../src/config.ts";
import {
  assertApprovalCodeFileOutsideAllowedRoots,
  createAppServer,
  type RunningServer,
} from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
import {
  listCheckpoints,
  rewindCheckpoint,
} from "../src/workspace/checkpoints.ts";
import {
  readAvailableEnvsTool,
  setEnvVarTool,
} from "../src/workspace/env-tools.ts";
import {
  applyEditsTool,
  globFilesTool,
  grepFilesTool,
  readFileTool,
  writeFileTool,
} from "../src/workspace/fs-tools.ts";

describe("filesystem tools and local checkpoints", () => {
  let baseDir: string;
  let workspaceDir: string;
  let outsideDir: string;

  beforeAll(() => {
    baseDir = mkdtempSync(join(tmpdir(), "justnewmcp-fs-"));
    workspaceDir = join(baseDir, "repo");
    outsideDir = join(baseDir, "outside");
    mkdirSync(join(workspaceDir, "src"), { recursive: true });
    mkdirSync(join(workspaceDir, "node_modules", "pkg"), { recursive: true });
    mkdirSync(outsideDir, { recursive: true });

    writeFileSync(
      join(workspaceDir, "src", "app.ts"),
      "const port = 3000;\nconst host = '127.0.0.1';\nexport const addr = `${host}:${port}`;\n",
      "utf8",
    );
    writeFileSync(join(workspaceDir, ".env"), "API_KEY=secret\n", "utf8");
    writeFileSync(
      join(workspaceDir, "node_modules", "pkg", "index.js"),
      "const port = 9999;\n",
      "utf8",
    );
    writeFileSync(
      join(workspaceDir, "binary.dat"),
      Buffer.from([0x00, 0xff, 0x01, 0x02]),
    );
    writeFileSync(join(outsideDir, "secret.txt"), "OUTSIDE\n", "utf8");
    symlinkSync(outsideDir, join(workspaceDir, "escape-dir"));
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("read_file returns numbered lines and blocks binaries, .env, and symlinks outside workspace", async () => {
    const tracker = new Set<string>();
    const res = await readFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      {
        path: "src/app.ts",
        offset: 2,
        limit: 2,
      },
    );
    expect(res.startLine).toBe(2);
    expect(res.endLine).toBe(3);
    expect(res.content).toContain("2 | const host = '127.0.0.1';");
    expect(res.hasMore).toBe(false);

    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: "binary.dat",
      }),
    ).rejects.toThrow("binary");
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: ".env",
      }),
    ).rejects.toThrow("blocked by security policy");
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: "escape-dir/secret.txt",
      }),
    ).rejects.toThrow("outside allowed workspace roots");
  });

  test("edit_file enforces read-before-edit, uniqueness, and creates rewindable checkpoints", async () => {
    const tracker = new Set<string>();
    await expect(
      applyEditsTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "src/app.ts",
        [{ old_string: "3000", new_string: "8787" }],
      ),
    ).rejects.toThrow("read_file before editing");

    await readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
      path: "src/app.ts",
    });

    const editRes = await applyEditsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      "src/app.ts",
      [{ old_string: "3000", new_string: "8787" }],
    );
    expect(editRes.replacements).toBe(1);
    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain(
      "const port = 8787;",
    );

    const cps = listCheckpoints(workspaceDir, 10);
    expect(cps.some((c) => c.id === editRes.checkpointId)).toBe(true);

    const rewindRes = await rewindCheckpoint(
      workspaceDir,
      editRes.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
    expect(rewindRes.action).toBe("restored");
    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain(
      "const port = 3000;",
    );

    // Literal replacement preserves $& and $$ tokens without JS String.replace expansion
    const dollarEdit = await applyEditsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      "src/app.ts",
      [{ old_string: "3000", new_string: "$&$$" }],
    );
    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain(
      "const port = $&$$;",
    );
    await rewindCheckpoint(
      workspaceDir,
      dollarEdit.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
  });

  test("safe .env.example is readable, .env uses read_available_envs/set_env_var, and allowEnvReading/askHumanAllowance work", async () => {
    const tracker = new Set<string>();
    writeFileSync(
      join(workspaceDir, ".env.example"),
      "API_KEY=your-key-here\nPORT=8787\n",
      "utf8",
    );

    const exampleRes = await readFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      {
        path: ".env.example",
      },
    );
    expect(exampleRes.content).toContain("API_KEY=your-key-here");

    const envs = await readAvailableEnvsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      ".env",
    );
    expect(envs.totalKeys).toBe(1);
    expect(envs.variables[0]).toEqual({
      name: "API_KEY",
      valueLength: 6,
      isEmpty: false,
      line: 1,
    });
    expect(JSON.stringify(envs)).not.toContain("secret");

    const added = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env",
        key: "APP_PORT",
        value: "9000",
      },
    );
    expect(added.action).toBe("created");
    expect(added.valueLength).toBe(4);
    const afterAdd = await readAvailableEnvsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      ".env",
    );
    expect(afterAdd.variables.map((v) => v.name)).toEqual([
      "API_KEY",
      "APP_PORT",
    ]);

    // Checkpoint directory and snapshot must have owner-only permissions on POSIX
    if (process.platform !== "win32") {
      const cpDir = join(
        workspaceDir,
        ".justnewmcp",
        "checkpoints",
        added.checkpointId,
      );
      expect(statSync(cpDir).mode & 0o777).toBe(0o700);
      expect(statSync(join(cpDir, "snapshot.bin")).mode & 0o777).toBe(0o600);
      expect(statSync(join(cpDir, "meta.json")).mode & 0o777).toBe(0o600);
    }

    // Direct read_file of the checkpoint snapshot payload must be blocked
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: `.justnewmcp/checkpoints/${added.checkpointId}/snapshot.bin`,
      }),
    ).rejects.toThrow("blocked by security policy");

    // Explicit deny rule for .env.example must still be honored
    await expect(
      readFileTool(
        workspaceDir,
        [...DEFAULT_DENIED_PATH_PATTERNS, ".env.example"],
        tracker,
        {
          path: ".env.example",
        },
      ),
    ).rejects.toThrow("blocked by security policy");

    // Windows backslash path values must round-trip without doubling backslashes
    const winPathEdit = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env",
        key: "WIN_PATH",
        value: "C:\\Users\\alice\\My App",
      },
    );
    const rawEnvAfter = readFileSync(join(workspaceDir, ".env"), "utf8");
    expect(rawEnvAfter).toContain("WIN_PATH='C:\\Users\\alice\\My App'");
    const parsedAfter = await readAvailableEnvsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      ".env",
    );
    const winVar = parsedAfter.variables.find((v) => v.name === "WIN_PATH");
    expect(winVar?.valueLength).toBe("C:\\Users\\alice\\My App".length);

    // Literal dollar signs must not expand via Bun dotenv loader
    const dollarEdit = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env",
        key: "PASS_DOLLAR",
        value: "abc$HOME",
      },
    );
    const envCheck = Bun.spawnSync(
      [
        process.execPath,
        `--env-file=${join(workspaceDir, ".env")}`,
        "-e",
        "console.log(JSON.stringify({w:process.env.WIN_PATH,d:process.env.PASS_DOLLAR}))",
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(envCheck.exitCode).toBe(0);
    const loaded = JSON.parse(envCheck.stdout.toString().trim()) as {
      w: string;
      d: string;
    };
    expect(loaded.w).toBe("C:\\Users\\alice\\My App");
    expect(loaded.d).toBe("abc$HOME");

    // Mixed single and double quotes must round-trip literally via backtick quoting
    const mixedEdit = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env",
        key: "MIXED_QUOTES",
        value: `both'and"quotes`,
      },
    );
    const mixedCheck = Bun.spawnSync(
      [
        process.execPath,
        `--env-file=${join(workspaceDir, ".env")}`,
        "-e",
        "console.log(JSON.stringify(process.env.MIXED_QUOTES))",
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(mixedCheck.exitCode).toBe(0);
    expect(JSON.parse(mixedCheck.stdout.toString().trim())).toBe(
      `both'and"quotes`,
    );
    await rewindCheckpoint(
      workspaceDir,
      mixedEdit.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );

    // Quoted value ending in backslash must be rejected explicitly
    await expect(
      setEnvVarTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
        path: ".env",
        key: "BAD_TRAIL",
        value: "ends with \\",
      }),
    ).rejects.toThrow("ending with a backslash");

    // Newly created secret .env file must be mode 0600 on POSIX
    const freshEnv = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env.fresh",
        key: "TOKEN",
        value: "abc",
      },
    );
    if (process.platform !== "win32") {
      expect(statSync(join(workspaceDir, ".env.fresh")).mode & 0o777).toBe(
        0o600,
      );
    }
    // Apostrophe + literal \new must round-trip without decoding \n into a newline
    const slashN = await setEnvVarTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        path: ".env.fresh",
        key: "WIN_QUOTE_N",
        value: "C:\\o'reilly\\new",
      },
    );
    const slashNCheck = Bun.spawnSync(
      [
        process.execPath,
        `--env-file=${join(workspaceDir, ".env.fresh")}`,
        "-e",
        "console.log(JSON.stringify(process.env.WIN_QUOTE_N))",
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(slashNCheck.exitCode).toBe(0);
    expect(JSON.parse(slashNCheck.stdout.toString().trim())).toBe(
      "C:\\o'reilly\\new",
    );

    // Deleting .env.fresh and rewinding slashN must recreate it with mode 0600 on POSIX
    rmSync(join(workspaceDir, ".env.fresh"), { force: true });
    await rewindCheckpoint(
      workspaceDir,
      slashN.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
    if (process.platform !== "win32") {
      expect(statSync(join(workspaceDir, ".env.fresh")).mode & 0o777).toBe(
        0o600,
      );
    }

    await rewindCheckpoint(
      workspaceDir,
      freshEnv.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );

    // Calling grep_files or glob_files rooted directly at .justnewmcp must still block checkpoint snapshots
    const metaDir = join(workspaceDir, ".justnewmcp");
    const grepFromMeta = await grepFilesTool(
      metaDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        pattern: "secret",
        mode: "content",
      },
    );
    expect(grepFromMeta.matches).toEqual([]);
    const globFromMeta = await globFilesTool(
      metaDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      "**/*",
    );
    expect(globFromMeta.files.some((f) => f.includes("snapshot.bin"))).toBe(
      false,
    );

    // Multiline quoted values and duplicate keys must parse and update cleanly
    writeFileSync(
      join(workspaceDir, ".env.multi"),
      'X="first\nY=embedded\nlast"\nexport\tTAB_KEY=from_tab\nDUP=old\nDUP=effective\n',
      "utf8",
    );
    const multiSummary = await readAvailableEnvsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      ".env.multi",
    );
    expect(multiSummary.variables.map((v) => v.name)).toEqual([
      "X",
      "TAB_KEY",
      "DUP",
    ]);

    // Setting Y must append a real Y without corrupting multiline X
    await setEnvVarTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
      path: ".env.multi",
      key: "Y",
      value: "real_y",
    });
    // Updating DUP must remove earlier duplicate and update effective value
    await setEnvVarTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
      path: ".env.multi",
      key: "DUP",
      value: "new_dup",
    });
    const multiCheck = Bun.spawnSync(
      [
        process.execPath,
        `--env-file=${join(workspaceDir, ".env.multi")}`,
        "-e",
        "console.log(JSON.stringify({x:process.env.X,y:process.env.Y,dup:process.env.DUP}))",
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(multiCheck.exitCode).toBe(0);
    const multiLoaded = JSON.parse(multiCheck.stdout.toString().trim()) as {
      x: string;
      y: string;
      dup: string;
    };
    expect(multiLoaded.x).toBe("first\nY=embedded\nlast");
    expect(multiLoaded.y).toBe("real_y");
    expect(multiLoaded.dup).toBe("new_dup");

    // Deleting DUP must leave it undefined
    await setEnvVarTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, {
      path: ".env.multi",
      key: "DUP",
      action: "delete",
    });
    const afterDel = await readAvailableEnvsTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      ".env.multi",
    );
    expect(afterDel.variables.map((v) => v.name)).toEqual([
      "X",
      "TAB_KEY",
      "Y",
    ]);

    await rewindCheckpoint(
      workspaceDir,
      dollarEdit.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
    await rewindCheckpoint(
      workspaceDir,
      winPathEdit.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
    await rewindCheckpoint(
      workspaceDir,
      added.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );

    const allowedRead = await readFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      { path: ".env" },
      { allowEnvReading: true },
    );
    expect(allowedRead.content).toContain("API_KEY=secret");

    await expect(
      readFileTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        { path: ".env" },
        { askHumanAllowance: true },
      ),
    ).rejects.toThrow("explicit human approval");

    const humanApprovedRead = await readFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      { path: ".env", humanApproved: true },
      { askHumanAllowance: true },
    );
    expect(humanApprovedRead.usedHumanApproval).toBe(true);
    expect(humanApprovedRead.content).toContain("API_KEY=secret");
  });

  test("multi_edit is atomic when a later edit fails", async () => {
    const tracker = new Set<string>();
    await readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
      path: "src/app.ts",
    });

    await expect(
      applyEditsTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "src/app.ts",
        [
          { old_string: "3000", new_string: "4000" },
          { old_string: "NON_EXISTENT", new_string: "nope" },
        ],
      ),
    ).rejects.toThrow("old_string not found");

    expect(readFileSync(join(workspaceDir, "src", "app.ts"), "utf8")).toContain(
      "const port = 3000;",
    );
  });

  test("write_file creates nested files, blocks symlink-parent escapes, and rewind deletes newly created files", async () => {
    const tracker = new Set<string>();
    await expect(
      writeFileTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "escape-dir/pwn.txt",
        "bad",
      ),
    ).rejects.toThrow("outside the active workspace");

    await expect(
      writeFileTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        ".justnewmcp/checkpoints/fake.json",
        "{}",
      ),
    ).rejects.toThrow("blocked by security policy");

    const written = await writeFileTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      tracker,
      "src/nested/new-file.ts",
      "export const ok = true;\n",
    );
    expect(existsSync(join(workspaceDir, "src", "nested", "new-file.ts"))).toBe(
      true,
    );

    const rewind = await rewindCheckpoint(
      workspaceDir,
      written.checkpointId,
      DEFAULT_DENIED_PATH_PATTERNS,
    );
    expect(rewind.action).toBe("deleted");
    expect(existsSync(join(workspaceDir, "src", "nested", "new-file.ts"))).toBe(
      false,
    );
  });

  test("blocks dangling symlinks, symlinked parents to denied files, and symlinked checkpoint dirs", async () => {
    const tracker = new Set<string>();

    // 1. Dangling symlink pointing to non-existent file outside workspace
    const danglingLink = join(workspaceDir, "dangling-escape.txt");
    symlinkSync(join(outsideDir, "created-via-dangling.txt"), danglingLink);
    await expect(
      writeFileTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "dangling-escape.txt",
        "pwn",
      ),
    ).rejects.toThrow("dangling symlink");
    expect(existsSync(join(outsideDir, "created-via-dangling.txt"))).toBe(
      false,
    );

    // 2. In-workspace symlink alias to .git directory
    mkdirSync(join(workspaceDir, ".git"), { recursive: true });
    writeFileSync(join(workspaceDir, ".git", "config"), "[core]\n", "utf8");
    symlinkSync(join(workspaceDir, ".git"), join(workspaceDir, "git-alias"));
    await expect(
      writeFileTool(
        workspaceDir,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "git-alias/config",
        "[core]\nfsmonitor=evil\n",
      ),
    ).rejects.toThrow("blocked by security policy");

    // 3. Symlinked .justnewmcp/checkpoints directory pointing outside workspace
    const isolatedRepo = join(baseDir, "symlink-cp-repo");
    mkdirSync(join(isolatedRepo, ".justnewmcp"), { recursive: true });
    symlinkSync(outsideDir, join(isolatedRepo, ".justnewmcp", "checkpoints"));
    await expect(
      writeFileTool(
        isolatedRepo,
        DEFAULT_DENIED_PATH_PATTERNS,
        tracker,
        "hello.txt",
        "hi",
      ),
    ).rejects.toThrow("must not be a symlink");
  });

  test("glob_files and grep_files skip node_modules, .env, binaries, and symlink escapes", async () => {
    const globRes = await globFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      "**/*",
    );
    expect(globRes.files).toContain("src/app.ts");
    expect(globRes.files).not.toContain(".env");
    expect(globRes.files.some((f) => f.startsWith("node_modules/"))).toBe(
      false,
    );

    const grepFiles = await grepFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        pattern: "port",
        mode: "files_with_matches",
      },
    );
    expect(grepFiles.matches).toEqual(["src/app.ts"]);

    const grepContent = await grepFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        pattern: "host",
        contextLines: 1,
        mode: "content",
      },
    );
    expect(grepContent.matches[0]).toContain(
      "src/app.ts:2:const host = '127.0.0.1';",
    );

    // Respect workspace .gitignore rules (including directory patterns and !negation)
    mkdirSync(join(workspaceDir, "dist"), { recursive: true });
    writeFileSync(
      join(workspaceDir, ".gitignore"),
      "private.json\ndist/\n!dist/keep.txt\n",
      "utf8",
    );
    writeFileSync(
      join(workspaceDir, "private.json"),
      '{"token":"gitignore-secret"}',
      "utf8",
    );
    writeFileSync(
      join(workspaceDir, "dist", "bundle.js"),
      "const gitignoreSecret = 1;\n",
      "utf8",
    );
    writeFileSync(
      join(workspaceDir, "dist", "keep.txt"),
      "keep-me-visible\n",
      "utf8",
    );

    const giGlob = await globFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      "**/*",
    );
    expect(giGlob.files).not.toContain("private.json");
    expect(giGlob.files).not.toContain("dist/bundle.js");
    expect(giGlob.files).toContain("dist/keep.txt");

    // Directory patterns ending with '/' return matching directories
    const dirGlob = await globFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      "*/",
    );
    expect(dirGlob.files).toContain("src/");
    expect(dirGlob.files).not.toContain("node_modules/");

    // System Volume Information and unreadable directories are skipped without EPERM/EACCES crash
    mkdirSync(join(workspaceDir, "System Volume Information"), {
      recursive: true,
    });
    writeFileSync(
      join(workspaceDir, "System Volume Information", "tracking.log"),
      "sys",
      "utf8",
    );
    const sysGlob = await globFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      "*/*",
    );
    expect(
      sysGlob.files.some((f) => f.startsWith("System Volume Information/")),
    ).toBe(false);

    const giGrep = await grepFilesTool(
      workspaceDir,
      DEFAULT_DENIED_PATH_PATTERNS,
      {
        pattern: "gitignore-secret|gitignoreSecret",
        mode: "files_with_matches",
      },
    );
    expect(giGrep.matches).toEqual([]);

    // FIFO .gitignore must not block the event loop on POSIX
    if (process.platform !== "win32") {
      const fifoWorkspace = join(baseDir, "fifo-gitignore-repo");
      mkdirSync(fifoWorkspace, { recursive: true });
      writeFileSync(join(fifoWorkspace, "ok.txt"), "hello\n", "utf8");
      const mkfifo = Bun.spawnSync([
        "mkfifo",
        join(fifoWorkspace, ".gitignore"),
      ]);
      if (mkfifo.exitCode === 0) {
        const fifoGlob = await globFilesTool(
          fifoWorkspace,
          DEFAULT_DENIED_PATH_PATTERNS,
          "**/*",
        );
        expect(fifoGlob.files).toContain("ok.txt");
      }
    }

    // .justnewmcp/approval-code must be blocked from MCP reads and rejected inside allowedRoots
    mkdirSync(join(workspaceDir, ".justnewmcp"), { recursive: true });
    writeFileSync(
      join(workspaceDir, ".justnewmcp", "approval-code"),
      "ABCD-1234-5678\n",
      "utf8",
    );
    const tracker = new Set<string>();
    writeFileSync(
      join(workspaceDir, ".justnewmcp", "approval-code-8787-1234"),
      "WXYZ-5678-1234\n",
      "utf8",
    );
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: ".justnewmcp/approval-code",
      }),
    ).rejects.toThrow("blocked by security policy");
    await expect(
      readFileTool(workspaceDir, DEFAULT_DENIED_PATH_PATTERNS, tracker, {
        path: ".justnewmcp/approval-code-8787-1234",
      }),
    ).rejects.toThrow("blocked by security policy");
    expect(() =>
      assertApprovalCodeFileOutsideAllowedRoots(
        join(workspaceDir, ".justnewmcp", "approval-code"),
        [workspaceDir],
      ),
    ).toThrow("outside configured allowedRoots");
    expect(
      assertApprovalCodeFileOutsideAllowedRoots(
        join(outsideDir, "approval-code"),
        [workspaceDir],
      ),
    ).toContain("approval-code");
  });

  test("end-to-end MCP /mcp HTTP call flow for write_file, read_file, edit_file, and checkpoint_rewind", async () => {
    const clientId = "fs-e2e-client";
    const clientSecret = "fs-e2e-secret-value-1234567890";
    const approvalCode = "FS00-1111-2222";
    const config: AppConfig = {
      host: "127.0.0.1",
      port: 0,
      publicUrl: "https://mcp.example.com",
      trustedProxies: ["127.0.0.1", "::1"],
      allowedRoots: [baseDir],
      deniedPathPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      allowEnvReading: false,
      askHumanAllowance: true,
      allowedCommands: [],
      maxMcpBodyBytes: 1_048_576,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        inMemoryTokens: true,
        rateLimit: {
          maxFailures: 5,
          windowMs: 60_000,
          lockoutMs: 60_000,
          maxTrackedIps: 1000,
        },
      },
    };

    const running: RunningServer = createAppServer(config, {
      initialApprovalCode: approvalCode,
    });
    const baseUrl = `http://127.0.0.1:${running.server.port}`;

    try {
      const verifier = generateRandomToken(48);
      const challenge = computePkceS256(verifier);
      const redirectUri = "https://gemini.google.com/oauth/callback";
      const getAuth = await fetch(
        `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
      );
      const csrfSid =
        (getAuth.headers.get("set-cookie") ?? "").match(
          /justnewmcp_csrf_sid=([^;]+)/,
        )?.[1] ?? "";
      const csrfToken =
        (await getAuth.text()).match(
          /name="csrf_token"\s+value="([^"]+)"/,
        )?.[1] ?? "";

      const postAuth = await fetch(`${baseUrl}/oauth/authorize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: `justnewmcp_csrf_sid=${csrfSid}`,
        },
        body: new URLSearchParams({
          csrf_token: csrfToken,
          client_id: clientId,
          redirect_uri: redirectUri,
          code_challenge: challenge,
          scope: "mcp:tools",
          approval_code: approvalCode,
        }),
        redirect: "manual",
      });
      const authCode =
        new URL(postAuth.headers.get("location") ?? "").searchParams.get(
          "code",
        ) ?? "";
      const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: clientSecret,
          code: authCode,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });
      const { access_token } = (await tokenRes.json()) as {
        access_token: string;
      };

      const callTool = async (
        id: number,
        name: string,
        args: Record<string, unknown>,
      ) => {
        const res = await fetch(`${baseUrl}/mcp`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${access_token}`,
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: { name, arguments: args },
          }),
        });
        const json = (await res.json()) as {
          result: { isError?: boolean; content: Array<{ text: string }> };
        };
        return json.result;
      };

      const initRes = await callTool(1, "workspace_init", {
        path: workspaceDir,
      });
      expect(initRes.isError).toBeUndefined();

      const writeRes = await callTool(2, "write_file", {
        path: "src/e2e.ts",
        content: "export const v = 1;\n",
      });
      expect(writeRes.isError).toBeUndefined();

      const editRes = await callTool(3, "edit_file", {
        path: "src/e2e.ts",
        old_string: "1",
        new_string: "2",
      });
      expect(editRes.isError).toBeUndefined();
      const editData = JSON.parse(editRes.content[0]?.text ?? "{}") as {
        checkpointId: string;
      };

      const rewindRes = await callTool(4, "checkpoint_rewind", {
        checkpoint_id: editData.checkpointId,
      });
      expect(rewindRes.isError).toBeUndefined();
      expect(readFileSync(join(workspaceDir, "src", "e2e.ts"), "utf8")).toBe(
        "export const v = 1;\n",
      );

      // Empty file reports totalLines 0 cleanly
      await callTool(5, "write_file", { path: "src/empty.ts", content: "" });
      const emptyRead = await callTool(6, "read_file", {
        path: "src/empty.ts",
      });
      const emptyData = JSON.parse(emptyRead.content[0]?.text ?? "{}") as {
        totalLines: number;
        endLine: number;
      };
      expect(emptyData.totalLines).toBe(0);
      expect(emptyData.endLine).toBe(0);

      // Replacing active workspace with a symlink to outsideDir after workspace_init must be rejected
      const swapRepo = join(baseDir, "swap-repo");
      const movedRepo = join(baseDir, "swap-repo-moved");
      mkdirSync(swapRepo, { recursive: true });
      writeFileSync(join(swapRepo, "ok.txt"), "ok\n", "utf8");
      const swapInit = await callTool(7, "workspace_init", { path: swapRepo });
      expect(swapInit.isError).toBeUndefined();

      renameSync(swapRepo, movedRepo);
      symlinkSync(outsideDir, swapRepo);
      const swappedRead = await callTool(8, "read_file", {
        path: "secret.txt",
      });
      expect(swappedRead.isError).toBe(true);
      expect(swappedRead.content[0]?.text).toContain("replaced by a symlink");
    } finally {
      running.server.stop(true);
    }
  });
});
