import { describe, expect, spyOn, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigSchema } from "../src/config.ts";
import { createAppServer } from "../src/index.ts";
import { computePkceS256, generateRandomToken } from "../src/security/crypto.ts";
import { PlanMode, TaskManager, type Task } from "../src/workspace/tasks.ts";

describe("TaskManager", () => {
  test("creates, updates, lists, and retrieves tasks with timestamps", () => {
    const tasks = new TaskManager();
    const task = tasks.create({ title: "Draft plan" });

    expect(task).toMatchObject({
      title: "Draft plan",
      status: "pending",
      dependencies: [],
      notes: "",
      updatedAt: task.createdAt,
    });
    expect(new Date(task.createdAt).toISOString()).toBe(task.createdAt);

    const started = tasks.update(task.id, { status: "in_progress", notes: "Reviewing" });
    const blocked = tasks.update(task.id, { status: "blocked" });
    const completed = tasks.update(task.id, { title: "Plan approved", status: "completed" });

    expect(started.status).toBe("in_progress");
    expect(blocked.status).toBe("blocked");
    expect(completed).toMatchObject({
      id: task.id,
      title: "Plan approved",
      status: "completed",
      notes: "Reviewing",
      createdAt: task.createdAt,
    });
    expect(completed.updatedAt >= started.updatedAt).toBe(true);
    expect(tasks.list()).toEqual([completed]);
    expect(tasks.get(task.id)).toEqual(completed);
    expect(() => tasks.get("missing")).toThrow("Task not found: missing");
  });

  test("tracks dependencies and rejects missing tasks and cycles without changing stored tasks", () => {
    const tasks = new TaskManager();
    const first = tasks.create({ title: "First" });
    const second = tasks.create({ title: "Second", dependencies: [first.id, first.id] });
    const third = tasks.create({ title: "Third", dependencies: [second.id] });

    expect(second.dependencies).toEqual([first.id]);
    expect(() => tasks.create({ title: "Missing prerequisite", dependencies: ["missing"] })).toThrow("Task not found");
    expect(() => tasks.update(first.id, { dependencies: [first.id] })).toThrow("cycle");
    expect(() => tasks.update(first.id, { title: "Rejected", dependencies: [third.id] })).toThrow("cycle");
    expect(tasks.list()).toEqual([first, second, third]);

    tasks.get(third.id).dependencies.pop();
    expect(tasks.get(third.id).dependencies).toEqual([second.id]);
    expect(tasks.update(third.id, { dependencies: [] }).dependencies).toEqual([]);
  });
});

test("plan mode returns the summary on exit and clears it for the next plan", () => {
  const plan = new PlanMode();
  expect(plan.active).toBe(false);
  expect(plan.enter("Review the workspace")).toEqual({ active: true, summary: "Review the workspace" });
  expect(plan.active).toBe(true);
  expect(plan.exit()).toEqual({ active: false, summary: "Review the workspace" });
  expect(plan.enter()).toEqual({ active: true });
  expect(plan.exit("Review complete")).toEqual({ active: false, summary: "Review complete" });
  expect(plan.active).toBe(false);
});

interface McpReply {
  result?: {
    content?: Array<{ text: string }>;
    isError?: boolean;
    tools?: Array<{ name: string }>;
  };
  error?: { message: string };
}

test("authenticated /mcp calls manage tasks and enforce read-only plan mode", async () => {
  const root = mkdtempSync(join(tmpdir(), "justnewmcp-plan-"));
  const clientId = "plan-test-client";
  const clientSecret = "plan-test-secret-value";
  const approvalCode = "PLAN-1234-5678";
  const redirectUri = "http://127.0.0.1/callback";
  const running = createAppServer(ConfigSchema.parse({
    port: 0,
    publicUrl: "https://mcp.example.com",
    allowedRoots: [root],
    oauth: { clientId, clientSecret, allowedRedirectUris: [redirectUri] },
  }), { initialApprovalCode: approvalCode });
  const baseUrl = `http://127.0.0.1:${running.server.port}`;

  try {
    writeFileSync(join(root, ".env"), "FLAG=before\n");
    const verifier = generateRandomToken(48);
    const authorizeParams = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: computePkceS256(verifier),
    });
    const query = new URLSearchParams(authorizeParams);
    query.set("response_type", "code");
    query.set("code_challenge_method", "S256");
    const form = await fetch(`${baseUrl}/oauth/authorize?${query}`);
    expect(form.status).toBe(200);

    const csrfToken = (await form.text()).match(/name="csrf_token"\s+value="([^"]+)"/)?.[1];
    const cookie = form.headers.get("set-cookie")?.split(";")[0];
    expect(csrfToken).toBeTruthy();
    expect(cookie).toBeTruthy();
    authorizeParams.set("csrf_token", csrfToken ?? "");
    authorizeParams.set("approval_code", approvalCode);
    const approval = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { Cookie: cookie ?? "" },
      body: authorizeParams,
      redirect: "manual",
    });
    expect(approval.status).toBe(302);

    const code = new URL(approval.headers.get("location") ?? "").searchParams.get("code");
    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: clientSecret,
        code: code ?? "",
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    expect(tokenResponse.status).toBe(200);
    const { access_token } = (await tokenResponse.json()) as { access_token: string };

    const request = async (method: string, params?: Record<string, unknown>) => {
      const response = await fetch(`${baseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${access_token}` },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as McpReply;
    };

    const call = (name: string, args: Record<string, unknown> = {}) =>
      request("tools/call", { name, arguments: args });

    const result = async <T>(name: string, args?: Record<string, unknown>): Promise<T> => {
      const reply = await call(name, args);
      expect(reply.error).toBeUndefined();
      expect(reply.result?.isError).toBeUndefined();
      return JSON.parse(reply.result?.content?.[0]?.text ?? "") as T;
    };

    const listing = await request("tools/list");
    expect(listing.result?.tools?.map(({ name }) => name)).toEqual(expect.arrayContaining([
      "task_create", "task_update", "task_list", "task_get", "plan_enter", "plan_exit",
    ]));

    await result("workspace_init", { path: root });
    const file = "plan.txt";
    const started = Promise.withResolvers<void>();
    const resume = Promise.withResolvers<void>();
    const originalWrite = Bun.write;
    const writeSpy = spyOn(Bun, "write").mockImplementation(async (path, data) => {
      if (typeof path !== "string" || typeof data !== "string") {
        throw new Error("Expected a text write to the workspace.");
      }
      started.resolve();
      await resume.promise;
      return originalWrite(path, data);
    });
    const pendingWrite = result<{ checkpointId: string }>("write_file", { path: file, content: "before" });
    try {
      await Promise.race([started.promise, pendingWrite]);
      expect(writeSpy).toHaveBeenCalledTimes(1);
      const prematureEntry = await call("plan_enter");
      expect(prematureEntry.result?.isError).toBe(true);
      expect(prematureEntry.result?.content?.[0]?.text).toContain("workspace mutation is in progress");
    } finally {
      resume.resolve();
      writeSpy.mockRestore();
      await pendingWrite;
    }
    const { checkpointId } = await pendingWrite;
    const checkpoints = await result("checkpoint_list");

    expect(await result("plan_enter", { summary: "Inspect files" })).toEqual({ active: true, summary: "Inspect files" });

    const mutations = [
      ["edit_file", { path: file, old_string: "before", new_string: "after" }],
      ["multi_edit", { path: file, edits: [{ old_string: "before", new_string: "after" }] }],
      ["write_file", { path: file, content: "after" }],
      ["set_env_var", { key: "FLAG", value: "after" }],
      ["checkpoint_rewind", { checkpoint_id: checkpointId }],
      ["workspace_init", { path: root }],
    ] as const;

    expect(JSON.stringify(await result("read_file", { path: file }))).toContain("before");
    expect(await result("glob_files", { pattern: "*.txt" })).toMatchObject({ files: [file] });
    expect(await result("grep_files", { pattern: "before", mode: "files_with_matches" }))
      .toMatchObject({ matches: [file] });
    expect(await result("workspace_info")).toMatchObject({ activeRoot: expect.any(String) });
    await result("read_available_envs");

    for (const [name, args] of mutations) {
      const { result } = await call(name, args);
      expect(result?.isError).toBe(true);
      expect(result?.content?.[0]?.text).toContain(`read-only). Call plan_exit before using ${name}`);
    }
    expect(await result("checkpoint_list")).toEqual(checkpoints);
    expect(readFileSync(join(root, file), "utf8")).toBe("before");
    expect(readFileSync(join(root, ".env"), "utf8")).toBe("FLAG=before\n");

    const first = await result<Task>("task_create", { title: "Inspect" });
    const second = await result<Task>("task_create", { title: "Apply changes", dependencies: [first.id] });
    expect(await result("task_list")).toEqual({ tasks: [first, second] });
    expect(await result("task_get", { id: second.id })).toEqual(second);
    expect(await result("task_update", { id: first.id, status: "completed", notes: "Done" }))
      .toMatchObject({ id: first.id, status: "completed", notes: "Done" });

    expect(await result("plan_exit")).toEqual({ active: false, summary: "Inspect files" });
    await result("write_file", { path: file, content: "after" });
    expect(readFileSync(join(root, file), "utf8")).toBe("after");

    const planEvents = running.audit.list().filter(({ event }) => event.startsWith("mcp.plan."));
    expect(planEvents).toMatchObject([
      { event: "mcp.plan.entered", clientId, detail: "plan_enter" },
      { event: "mcp.plan.exited", clientId, detail: "plan_exit" },
    ]);
  } finally {
    running.server.stop(true);
    rmSync(root, { recursive: true, force: true });
  }
});
