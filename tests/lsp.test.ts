import { afterEach, beforeEach, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ConfigSchema, LspServerSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
import {
  encodeLspFrame,
  LspFrameReader,
} from "../src/workspace/lsp-protocol.ts";
import { LspManager } from "../src/workspace/lsp.ts";

const fixture = fileURLToPath(
  new URL("./fixtures/mock-lsp-server.ts", import.meta.url),
);
const marker = "justnewmcp-mock-lsp";
const denied = ["hidden.ts"];
const source = "main.ts";
const target = "target 🧪.ts";
const initialText = "café 🧪\r\nlast 🧪";

let temp: string;
let root: string;
let outside: string;
let manager: LspManager | undefined;

function prepareWorkspace(name: string): string {
  const path = join(temp, name);
  mkdirSync(join(path, ".justnewmcp", "checkpoints"), { recursive: true });
  for (const file of [
    source,
    target,
    "hidden.ts",
    ".justnewmcp/checkpoints/private.ts",
  ]) {
    writeFileSync(join(path, file), initialText);
  }
  return realpathSync(path);
}

beforeEach(() => {
  temp = realpathSync(mkdtempSync(join(tmpdir(), "justnewmcp-lsp-")));
  outside = join(temp, "outside.ts");
  writeFileSync(outside, "outside");
  root = prepareWorkspace("project");
});

afterEach(async () => {
  await manager?.shutdown();
  manager = undefined;
  rmSync(temp, { recursive: true, force: true });
});

function serverConfig(mode = "push", idleTimeoutMs = 60_000) {
  return LspServerSchema.parse({
    languageId: "typescript",
    extensions: [".ts"],
    command: basename(process.execPath),
    args: [fixture, marker, mode, outside],
    idleTimeoutMs,
    requestTimeoutMs: 1000,
  });
}

function useManager(mode?: string, idleTimeoutMs?: number) {
  manager = new LspManager([serverConfig(mode, idleTimeoutMs)], denied);
  return manager;
}

type Trace = { event: string; pid: number; details?: unknown };
function trace(path = root): Trace[] {
  try {
    const lines = readFileSync(join(path, "lsp-trace.jsonl"), "utf8").split(
      "\n",
    );
    return lines.slice(0, -1).map((line) => JSON.parse(line) as Trace);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

async function waitFor(check: () => boolean, timeout = 4000) {
  const deadline = performance.now() + timeout;
  while (!check()) {
    if (performance.now() >= deadline)
      throw new Error("Timed out waiting for the mock language server.");
    await Bun.sleep(15);
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
    return false;
  }
}

test("LSP framing accepts byte splits and concatenated messages and rejects malformed headers and bodies", () => {
  const messages = [
    { jsonrpc: "2.0", id: 1, result: "café 🧪" },
    { jsonrpc: "2.0", id: 2, result: null },
  ];
  const input = Buffer.concat(messages.map(encodeLspFrame));
  const received: unknown[] = [];
  const frames = new LspFrameReader();
  for (let i = 0; i < input.length; i += 1) {
    frames.push(input.subarray(i, i + 1), (value) => received.push(value));
  }
  expect(received).toEqual(messages);
  for (const invalid of [
    "Content-Length: 0\r\n\r\n",
    "Content-Length: +1\r\n\r\n",
    "Content-Length: 99999999\r\n\r\n",
    "Content-Length: 2\r\ncontent-length: 3\r\n\r\n",
    "Content-Type: application/vscode-jsonrpc; charset=utf-16\r\nContent-Length: 2\r\n\r\n",
    "Content-Length: 1\r\n\r\n{",
    "a".repeat(4100),
  ]) {
    expect(() =>
      new LspFrameReader().push(Buffer.from(invalid), () => {}),
    ).toThrow();
  }
  expect(() =>
    new LspFrameReader().push(
      Buffer.concat([
        Buffer.from("Content-Length: 1\r\n\r\n"),
        Buffer.from([0xff]),
      ]),
      () => {},
    ),
  ).toThrow();
});

test("configuration defaults to no servers and rejects executable paths and invalid timeouts", () => {
  const config = ConfigSchema.parse({
    publicUrl: "http://127.0.0.1",
    allowedRoots: [root],
    oauth: { clientId: "fixture", clientSecret: generateRandomToken(32) },
  });
  expect(config.lspServers).toEqual([]);
  expect(
    LspServerSchema.parse({
      languageId: "typescript",
      extensions: ["ts"],
      command: "typescript-language-server",
    }),
  ).toMatchObject({
    args: [],
    idleTimeoutMs: 300_000,
    requestTimeoutMs: 15_000,
  });
  for (const command of [
    "/bin/tool",
    "nested/tool",
    "nested\\tool",
    "C:tool",
    "foo\0bar",
    "..",
  ]) {
    expect(
      LspServerSchema.safeParse({ ...serverConfig(), command }).success,
    ).toBe(false);
  }
  expect(
    LspServerSchema.safeParse({ ...serverConfig(), idleTimeoutMs: 4999 })
      .success,
  ).toBe(false);
  expect(
    LspServerSchema.safeParse({ ...serverConfig(), requestTimeoutMs: 120_001 })
      .success,
  ).toBe(false);
});

test("push diagnostics are Unicode-safe, versioned, bounded, and filtered", async () => {
  const lsp = useManager("incremental");
  process.env.JUSTNEWMCP_LSP_TEST = "private-test-value";
  try {
    expect(await lsp.diagnostics(root, undefined, 10)).toEqual([]);
    expect(trace()).toEqual([]);
    expect(await lsp.diagnostics(root, source, 10)).toEqual([
      {
        path: source,
        line: 1,
        character: 2,
        severity: "warning",
        source: "mock",
        code: "TS1",
        message: "🧪 café 🧪",
      },
    ]);
    await waitFor(() => trace().some(({ event }) => event === "edit"));
    expect(
      trace()
        .slice(0, 2)
        .map(({ event }) => event),
    ).toEqual(["initialize", "initialized"]);
    expect(trace().find(({ event }) => event === "config")?.details).toEqual([
      null,
    ]);
    expect(trace().find(({ event }) => event === "edit")?.details).toEqual({
      applied: false,
    });

    writeFileSync(join(root, source), "updated");
    expect((await lsp.diagnostics(root, source, 1))[0]?.message).toBe(
      "🧪 updated",
    );
    expect(await lsp.diagnostics(root, undefined, 10)).toHaveLength(1);
    expect(trace().find(({ event }) => event === "change")?.details).toEqual({
      version: 2,
      range: {
        start: { line: 0, character: 0 },
        end: { line: 1, character: 7 },
      },
    });
    await expect(lsp.diagnostics(root, "hidden.ts", 1)).rejects.toThrow(
      "blocked",
    );
    await expect(lsp.diagnostics(root, outside, 1)).rejects.toThrow("outside");
    await expect(
      lsp.diagnostics(root, ".justnewmcp/checkpoints/private.ts", 1),
    ).rejects.toThrow("blocked");
  } finally {
    delete process.env.JUSTNEWMCP_LSP_TEST;
  }
});

test("pull diagnostics are requested when advertised and optional related URI data stays private", async () => {
  const lsp = useManager("pull");
  const diagnostics = await lsp.diagnostics(root, source, 10);
  expect(diagnostics).toHaveLength(1);
  expect(diagnostics[0]?.message).toBe("pull 🧪");
  expect(diagnostics[0]).not.toHaveProperty("relatedInformation");
  expect(trace().some(({ event }) => event === "pull")).toBe(true);
  expect(await lsp.diagnostics(root, source, 10)).toEqual(diagnostics);
  expect(trace().some(({ event }) => event === "unchanged")).toBe(true);
  expect(await lsp.diagnostics(root, undefined, 10)).toEqual(diagnostics);
});

test("diagnostic responses cap results, redact embedded file URIs and reject oversized documents", async () => {
  const lsp = useManager("many");
  const diagnostics = await lsp.diagnostics(root, source, 200);
  expect(diagnostics).toHaveLength(200);
  expect(diagnostics[0]?.message).toBe("Diagnostic 0: see [path]");
  expect(await lsp.diagnostics(root, source, 3)).toEqual(
    diagnostics.slice(0, 3),
  );
  expect(await lsp.diagnostics(root, undefined, 2)).toEqual(
    diagnostics.slice(0, 2),
  );

  writeFileSync(join(root, "large.ts"), Buffer.alloc(1024 * 1024 + 1));
  await expect(lsp.diagnostics(root, "large.ts", 30)).rejects.toThrow(
    "document size limit",
  );
  expect(trace().filter(({ event }) => event === "open")).toHaveLength(1);
});

test("navigation filters malformed, denied, symlinked and outside URIs and matches out-of-order responses", async () => {
  symlinkSync(outside, join(root, "outside-link.ts"), "file");
  const lsp = useManager();
  expect(await lsp.navigate(root, "definition", source, 1, 2, 10)).toEqual([
    { path: target, line: 1, character: 2, endLine: 1, endCharacter: 3 },
  ]);
  await expect(
    lsp.navigate(root, "definition", "outside-link.ts", 1, 1, 10),
  ).rejects.toThrow("outside");
  const [definition, references] = await Promise.all([
    lsp.navigate(root, "definition", source, 2, 1, 10),
    lsp.navigate(root, "references", source, 1, 1, 10, false),
  ]);
  expect(definition).toEqual([
    { path: target, line: 1, character: 10, endLine: 1, endCharacter: 11 },
  ]);
  expect(references).toEqual([
    { path: target, line: 1, character: 3, endLine: 1, endCharacter: 4 },
  ]);
  expect(await lsp.navigate(root, "references", source, 1, 1, 1)).toHaveLength(
    1,
  );
  expect(await lsp.navigate(root, "references", source, 1, 1, 10)).toHaveLength(
    2,
  );
  await expect(
    lsp.navigate(root, "definition", source, 7, 1, 10),
  ).rejects.toThrow("Language server request failed (code -32603).");
  expect(await lsp.navigate(root, "definition", source, 1, 1, 10)).toHaveLength(
    1,
  );
  expect(trace().filter(({ event }) => event === "initialize")).toHaveLength(1);
});

test("crash, invalid framing and request timeout reject pending requests and recover on the next call", async () => {
  const lsp = useManager();
  await expect(
    lsp.navigate(root, "definition", source, 4, 1, 10),
  ).rejects.toThrow("Language server");
  await expect(
    lsp.navigate(root, "definition", source, 5, 1, 10),
  ).rejects.toThrow("invalid LSP");
  await expect(
    lsp.navigate(root, "definition", source, 6, 1, 10),
  ).rejects.toThrow("timed out");
  expect(await lsp.navigate(root, "definition", source, 1, 1, 10)).toHaveLength(
    1,
  );
  const pids = trace()
    .filter(({ event }) => event === "initialize")
    .map(({ pid }) => pid);
  expect(new Set(pids).size).toBe(4);
  expect(pids.slice(0, -1).every((pid) => !alive(pid))).toBe(true);
  await lsp.shutdown();
  expect(alive(pids[3]!)).toBe(false);
}, 15_000);

test("idle servers send shutdown and exit, then restart lazily", async () => {
  const lsp = useManager("push", 5000);
  await lsp.navigate(root, "definition", source, 1, 1, 10);
  const pid = trace()[0]!.pid;
  await waitFor(() => !alive(pid), 7500);
  expect(
    trace()
      .slice(-2)
      .map(({ event }) => event),
  ).toEqual(["shutdown", "exit"]);
  expect(await lsp.diagnostics(root, undefined, 10)).toEqual([]);
  await lsp.navigate(root, "definition", source, 1, 1, 10);
  expect(
    trace().filter(({ event }) => event === "initialize")[1]?.pid,
  ).not.toBe(pid);
}, 12_000);

test("shutdown falls back to terminating an unresponsive child", async () => {
  const lsp = useManager("unresponsive");
  await lsp.navigate(root, "definition", source, 1, 1, 10);
  const pid = trace()[0]!.pid;
  await lsp.shutdown();
  expect(trace().some(({ event }) => event === "shutdown")).toBe(true);
  expect(alive(pid)).toBe(false);
}, 10_000);

test("authenticated MCP LSP calls remain read-only in plan mode and cleanly switch workspaces", async () => {
  const second = prepareWorkspace("second");
  const clientId = "lsp-test-client";
  const clientSecret = generateRandomToken(32);
  const approvalCode = "TEST-1234-5678";
  const redirectUri = "http://127.0.0.1/callback";
  const running = createAppServer(
    ConfigSchema.parse({
      port: 0,
      publicUrl: "http://127.0.0.1",
      allowedRoots: [temp],
      deniedPathPatterns: denied,
      lspServers: [serverConfig()],
      oauth: { clientId, clientSecret, allowedRedirectUris: [redirectUri] },
    }),
    { initialApprovalCode: approvalCode },
  );

  try {
    const baseUrl = `http://127.0.0.1:${running.server.port}`;
    const verifier = generateRandomToken(48);
    const authParams = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: computePkceS256(verifier),
      code_challenge_method: "S256",
      response_type: "code",
    });
    const form = await fetch(`${baseUrl}/oauth/authorize?${authParams}`);
    expect(form.status).toBe(200);
    const csrf = (await form.text()).match(
      /name="csrf_token"\s+value="([^"]+)"/,
    )?.[1];
    const cookie = form.headers.get("set-cookie")?.split(";")[0];
    expect(csrf).toBeTruthy();
    expect(cookie).toBeTruthy();
    authParams.set("csrf_token", csrf!);
    authParams.set("approval_code", approvalCode);
    const approval = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { Cookie: cookie! },
      body: authParams,
      redirect: "manual",
    });
    expect(approval.status).toBe(302);
    const code = new URL(approval.headers.get("location")!).searchParams.get(
      "code",
    )!;
    const tokens = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        code,
        code_verifier: verifier,
      }),
    });
    expect(tokens.status).toBe(200);
    const { access_token } = (await tokens.json()) as { access_token: string };

    async function rpc(method: string, params?: Record<string, unknown>) {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${access_token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      expect(response.status).toBe(200);
      const { result } = (await response.json()) as {
        result: {
          isError?: boolean;
          content?: Array<{ text: string }>;
          tools?: Array<{ name: string }>;
        };
      };
      return result;
    }

    async function call(
      name: string,
      args: Record<string, unknown> = {},
    ): Promise<unknown> {
      const result = await rpc("tools/call", { name, arguments: args });
      const text = result.content?.[0]?.text ?? "";
      return result.isError ? { error: text } : JSON.parse(text);
    }

    expect((await rpc("tools/list")).tools?.map(({ name }) => name)).toEqual(
      expect.arrayContaining([
        "lsp_diagnostics",
        "lsp_definition",
        "lsp_references",
      ]),
    );
    await call("workspace_init", { path: root });
    expect(await call("plan_enter")).toEqual({ active: true });
    expect(
      await call("lsp_definition", { path: source, line: 1, character: 1 }),
    ).toMatchObject({ locations: [{ path: target }] });
    expect(
      await call("lsp_references", {
        path: source,
        line: 1,
        character: 1,
        max_results: 1,
      }),
    ).toMatchObject({ locations: [{ path: target }] });
    expect(
      await call("lsp_diagnostics", { path: source, max_items: 1 }),
    ).toMatchObject({ diagnostics: [{ path: source }] });
    expect(
      await call("lsp_definition", { path: source, line: 0, character: 1 }),
    ).toHaveProperty("error");
    const oldPid = trace()[0]!.pid;
    const pending = call("lsp_definition", {
      path: source,
      line: 2,
      character: 1,
    });
    await waitFor(() =>
      trace().some(({ event }) => event === "hold-definition"),
    );
    await call("workspace_init", { path: second });
    expect(await pending).toHaveProperty("error");
    expect(alive(oldPid)).toBe(false);
    expect(
      trace()
        .slice(-2)
        .map(({ event }) => event),
    ).toEqual(["shutdown", "exit"]);
    expect(await call("lsp_diagnostics")).toEqual({ diagnostics: [] });
    expect(
      await call("lsp_definition", { path: source, line: 1, character: 1 }),
    ).toMatchObject({ locations: [{ path: target }] });
    const newPid = trace(second)[0]!.pid;
    await running.server.stop(true);
    expect(alive(newPid)).toBe(false);
  } finally {
    await running.shutdown(true);
  }
}, 15_000);
