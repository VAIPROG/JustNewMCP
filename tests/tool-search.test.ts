import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";

async function authorizedClient(
  baseUrl: string,
  clientId: string,
  clientSecret: string,
  approvalCode: string,
) {
  const verifier = generateRandomToken(48);
  const redirectUri = "http://127.0.0.1/callback";
  const challenge = computePkceS256(verifier);
  const formRes = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`,
  );
  const csrfToken =
    (await formRes.text()).match(/name="csrf_token"\s+value="([^"]+)"/)?.[1] ??
    "";
  const cookie = formRes.headers.get("set-cookie")?.split(";")[0] ?? "";
  const approveRes = await fetch(`${baseUrl}/oauth/authorize`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: cookie,
    },
    body: new URLSearchParams({
      csrf_token: csrfToken,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      approval_code: approvalCode,
    }),
    redirect: "manual",
  });
  const code =
    new URL(approveRes.headers.get("location") ?? "").searchParams.get(
      "code",
    ) ?? "";
  const tokRes = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  });
  const { access_token } = (await tokRes.json()) as { access_token: string };

  const rpc = async (
    method: string,
    params?: Record<string, unknown>,
    sessionId?: string,
  ) => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${access_token}`,
        ...(sessionId ? { "Mcp-Session-Id": sessionId } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    return {
      sessionId: res.headers.get("mcp-session-id") ?? undefined,
      body: (await res.json()) as {
        result?: {
          capabilities?: { tools?: { listChanged?: boolean } };
          tools?: Array<{ name: string }>;
          isError?: boolean;
          content?: Array<{ text: string }>;
        };
      },
    };
  };

  return {
    accessToken: access_token,
    initialize: () => rpc("initialize"),
    listTools: async (sessionId?: string) =>
      (await rpc("tools/list", undefined, sessionId)).body.result?.tools?.map(
        (t) => t.name,
      ) ?? [],
    call: async (
      name: string,
      args: Record<string, unknown> = {},
      sessionId?: string,
    ) =>
      (await rpc("tools/call", { name, arguments: args }, sessionId)).body
        .result!,
  };
}

describe("on-demand tool_search and deferred tool activation", () => {
  let baseDir: string;
  let workspaceDir: string;

  beforeAll(() => {
    baseDir = realpathSync(mkdtempSync(join(tmpdir(), "justnewmcp-search-")));
    workspaceDir = join(baseDir, "repo");
    mkdirSync(workspaceDir, { recursive: true });
  });

  afterAll(() => {
    rmSync(baseDir, { recursive: true, force: true });
  });

  test("exposes compact core tools + tool_search upfront, rejects inactive deferred calls, and activates on demand", async () => {
    const clientId = "tool-search-client";
    const clientSecret = "tool-search-secret-value-123456";
    const approvalCode = "SRCH-1234-5678";
    const running = createAppServer(
      ConfigSchema.parse({
        port: 0,
        publicUrl: "https://mcp.example.com",
        allowedRoots: [baseDir],
        deferredTools: true,
        oauth: {
          clientId,
          clientSecret,
          allowedRedirectUris: ["http://127.0.0.1/callback"],
        },
      }),
      { initialApprovalCode: approvalCode },
    );

    try {
      const client = await authorizedClient(
        `http://127.0.0.1:${running.server.port}`,
        clientId,
        clientSecret,
        approvalCode,
      );

      // initialize advertises listChanged: true and issues distinct Mcp-Session-Id headers
      const initA = await client.initialize();
      const initB = await client.initialize();
      expect(initA.body.result?.capabilities?.tools?.listChanged).toBe(true);
      expect(initA.sessionId).toBeTruthy();
      expect(initB.sessionId).toBeTruthy();
      expect(initA.sessionId).not.toBe(initB.sessionId);

      // Initial tools/list contains only core tools + tool_search
      const initialTools = await client.listTools(initA.sessionId);
      expect(initialTools).toContain("workspace_init");
      expect(initialTools).toContain("read_file");
      expect(initialTools).toContain("run_allowed_cmd");
      expect(initialTools).toContain("tool_search");
      expect(initialTools).not.toContain("memory_write");
      expect(initialTools).not.toContain("task_create");
      expect(initialTools).not.toContain("lsp_diagnostics");
      expect(initialTools).not.toContain("run_shell");

      await client.call("workspace_init", { path: workspaceDir });

      // Direct call to an inactive deferred tool must fail with actionable message
      const inactiveCall = await client.call("task_create", {
        title: "Before activation",
      });
      expect(inactiveCall.isError).toBe(true);
      expect(inactiveCall.content?.[0]?.text).toContain("tool_search");

      // Disabled run_shell must never be discoverable via tool_search
      const shellSearch = await client.call("tool_search", {
        query: "shell",
      });
      const shellData = JSON.parse(shellSearch.content?.[0]?.text ?? "{}") as {
        tools: Array<{ name: string }>;
      };
      expect(shellData.tools.some((t) => t.name === "run_shell")).toBe(false);

      // Empty tool_search lists available deferred modules without activating them
      const modulesRes = await client.call("tool_search", {});
      const modulesData = JSON.parse(modulesRes.content?.[0]?.text ?? "{}") as {
        availableModules: Array<{ module: string; totalTools: number }>;
        newlyActivated: string[];
      };
      expect(modulesData.newlyActivated).toEqual([]);
      expect(modulesData.availableModules.map((m) => m.module)).toEqual(
        expect.arrayContaining(["memory", "tasks", "worktree", "lsp"]),
      );

      // Activate tasks module and verify tools/list + tools/call + audit log
      const activateTasks = await client.call("tool_search", {
        module: "tasks",
      });
      expect(activateTasks.isError).toBeUndefined();
      const tasksData = JSON.parse(
        activateTasks.content?.[0]?.text ?? "{}",
      ) as {
        newlyActivated: string[];
      };
      expect(tasksData.newlyActivated).toContain("task_create");
      expect(tasksData.newlyActivated).toContain("plan_enter");

      const afterTasksTools = await client.listTools();
      expect(afterTasksTools).toContain("task_create");
      expect(afterTasksTools).toContain("plan_enter");

      // Session isolation: Session A and Session B do not leak activations to each other
      const sseRes = await fetch(
        `http://127.0.0.1:${running.server.port}/mcp`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            Authorization: `Bearer ${client.accessToken}`,
            "Mcp-Session-Id": initA.sessionId!,
          },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 99,
            method: "tools/call",
            params: { name: "tool_search", arguments: { module: "worktree" } },
          }),
        },
      );
      expect(sseRes.headers.get("content-type")).toContain("text/event-stream");
      const sseText = await sseRes.text();
      expect(sseText).toContain("notifications/tools/list_changed");
      expect(sseText).toContain("worktree_enter");
      expect(await client.listTools(initA.sessionId)).toContain(
        "worktree_enter",
      );
      expect(await client.listTools(initB.sessionId)).not.toContain(
        "worktree_enter",
      );
      const blockedInB = await client.call(
        "worktree_enter",
        {},
        initB.sessionId,
      );
      expect(blockedInB.isError).toBe(true);
      expect(blockedInB.content?.[0]?.text).toContain("tool_search");

      // Workspace isolation: Session A and Session B maintain independent activeRoot values
      const repoB = join(baseDir, "repo-b");
      mkdirSync(repoB, { recursive: true });
      await client.call(
        "workspace_init",
        { path: workspaceDir },
        initA.sessionId,
      );
      await client.call("workspace_init", { path: repoB }, initB.sessionId);
      const infoA = JSON.parse(
        (await client.call("workspace_info", {}, initA.sessionId)).content?.[0]
          ?.text ?? "{}",
      ) as { activeRoot: string };
      const infoB = JSON.parse(
        (await client.call("workspace_info", {}, initB.sessionId)).content?.[0]
          ?.text ?? "{}",
      ) as { activeRoot: string };
      expect(infoA.activeRoot).toBe(workspaceDir);
      expect(infoB.activeRoot).toBe(repoB);

      const createdTask = await client.call("task_create", {
        title: "After activation",
      });
      expect(createdTask.isError).toBeUndefined();
      expect(createdTask.content?.[0]?.text).toContain("After activation");

      // tool_search stays usable in read-only plan mode, while newly activated mutators stay blocked
      await client.call("plan_enter");
      const activateMemoryInPlan = await client.call("tool_search", {
        query: "select:memory_write,memory_read",
      });
      expect(activateMemoryInPlan.isError).toBeUndefined();
      const blockedMemWrite = await client.call("memory_write", {
        content: "nope",
      });
      expect(blockedMemWrite.isError).toBe(true);
      expect(blockedMemWrite.content?.[0]?.text).toContain(
        "Plan mode is active",
      );
      await client.call("plan_exit");

      const okMemWrite = await client.call("memory_write", {
        content: "# Memory\n",
      });
      expect(okMemWrite.isError).toBeUndefined();

      expect(
        running.audit
          .list()
          .some(
            (e) =>
              e.event === "mcp.tools.activated" &&
              e.clientId === clientId &&
              e.detail?.includes("task_create"),
          ),
      ).toBe(true);
    } finally {
      await running.shutdown(true);
    }
  });
});
