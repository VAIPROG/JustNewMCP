import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { AllowedCommandRule } from "../src/config.ts";
import { runAllowedCmdTool } from "../src/workspace/cmd-runner.ts";

describe("run_allowed_cmd allowlisted command runner", () => {
  let workspaceDir: string;
  const bunBin = basename(process.execPath);

  beforeAll(() => {
    workspaceDir = mkdtempSync(join(tmpdir(), "justnewmcp-cmd-"));
  });

  afterAll(() => {
    rmSync(workspaceDir, { recursive: true, force: true });
  });

  test("rejects commands not in allowlist, path-qualified commands, and denied arguments", async () => {
    const rules: AllowedCommandRule[] = [
      {
        command: "git",
        allowedSubcommands: ["status", "log"],
        deniedArgs: ["-c", "--exec-path*"],
        timeoutMs: 10_000,
        maxOutputChars: 30_000,
      },
    ];

    await expect(
      runAllowedCmdTool(workspaceDir, rules, {
        command: "rm",
        args: ["-rf", "."],
      }),
    ).rejects.toThrow("not in allowedCommands");
    await expect(
      runAllowedCmdTool(workspaceDir, rules, {
        command: "/bin/sh",
        args: ["-c", "id"],
      }),
    ).rejects.toThrow("bare executable name");
    await expect(
      runAllowedCmdTool(workspaceDir, rules, {
        command: "git",
        args: ["push"],
      }),
    ).rejects.toThrow("not permitted");
    await expect(
      runAllowedCmdTool(workspaceDir, rules, {
        command: "git",
        args: ["status", "-c", "core.fsmonitor=evil"],
      }),
    ).rejects.toThrow("not permitted");
  });

  test("runs allowlisted argv directly without shell interpolation and strips JUSTNEWMCP_* env vars", async () => {
    const rules: AllowedCommandRule[] = [
      {
        command: bunBin,
        allowedSubcommands: ["-e"],
        deniedArgs: [],
        timeoutMs: 10_000,
        maxOutputChars: 30_000,
      },
    ];

    const prevSecret = process.env.JUSTNEWMCP_CLIENT_SECRET;
    process.env.JUSTNEWMCP_CLIENT_SECRET = "top-secret-mcp-key";
    try {
      const res = await runAllowedCmdTool(workspaceDir, rules, {
        command: bunBin,
        args: [
          "-e",
          "console.log(JSON.stringify({ arg: process.argv[1], leaked: Boolean(process.env.JUSTNEWMCP_CLIENT_SECRET) }))",
          "hello && echo pwned",
        ],
      });
      expect(res.exitCode).toBe(0);
      expect(res.timedOut).toBe(false);
      expect(res.outputTruncated).toBe(false);
      const parsed = JSON.parse(res.stdout.trim()) as {
        arg: string;
        leaked: boolean;
      };
      expect(parsed.arg).toBe("hello && echo pwned");
      expect(parsed.leaked).toBe(false);
    } finally {
      if (prevSecret === undefined) delete process.env.JUSTNEWMCP_CLIENT_SECRET;
      else process.env.JUSTNEWMCP_CLIENT_SECRET = prevSecret;
    }
  });

  test("kills timed-out commands and reports timedOut: true", async () => {
    const rules: AllowedCommandRule[] = [
      {
        command: bunBin,
        allowedSubcommands: ["-e"],
        deniedArgs: [],
        timeoutMs: 5000,
        maxOutputChars: 30_000,
      },
    ];

    const started = Date.now();
    const res = await runAllowedCmdTool(workspaceDir, rules, {
      command: bunBin,
      args: ["-e", "process.on('SIGTERM', () => {}); await Bun.sleep(5000);"],
      timeoutMs: 150,
    });
    const elapsedMs = Date.now() - started;
    expect(res.timedOut).toBe(true);
    expect(elapsedMs).toBeLessThan(2000);
  });

  test("spills output exceeding maxOutputChars to .justnewmcp/logs with 0600 mode and 2K preview", async () => {
    const rules: AllowedCommandRule[] = [
      {
        command: bunBin,
        allowedSubcommands: ["-e"],
        deniedArgs: [],
        timeoutMs: 10_000,
        maxOutputChars: 4000,
      },
    ];

    const res = await runAllowedCmdTool(workspaceDir, rules, {
      command: bunBin,
      args: ["-e", "console.log('X'.repeat(6000))"],
    });
    expect(res.exitCode).toBe(0);
    expect(res.outputTruncated).toBe(true);
    expect(res.stdout.length).toBe(2000);
    expect(res.outputFile).toMatch(/^\.justnewmcp\/logs\/cmd_.*\.log$/);

    const absLog = join(workspaceDir, res.outputFile ?? "");
    expect(existsSync(absLog)).toBe(true);
    expect(readFileSync(absLog, "utf8")).toContain("X".repeat(6000));
    if (process.platform !== "win32") {
      expect(statSync(absLog).mode & 0o777).toBe(0o600);
    }
  });
});
