import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AppConfig } from "../src/config.ts";
import { createAppServer, type RunningServer } from "../src/index.ts";
import { computePkceS256, generateRandomToken } from "../src/security/crypto.ts";

describe("OAuth 2.1 gate and MCP /mcp integration", () => {
  let tempRoot: string;
  let outsideDir: string;
  let running: RunningServer;
  let baseUrl: string;
  const clientId = "gemini-test-client";
  const clientSecret = "super-secret-value-for-testing-123456";
  const approvalCode = "ABCD-1234-EFGH";

  beforeAll(() => {
    tempRoot = mkdtempSync(join(tmpdir(), "justnewmcp-root-"));
    outsideDir = mkdtempSync(join(tmpdir(), "justnewmcp-outside-"));
    mkdirSync(join(tempRoot, "repo"), { recursive: true });
    writeFileSync(join(tempRoot, "repo", "README.md"), "# Demo\n", "utf8");

    const config: AppConfig = {
      host: "127.0.0.1",
      port: 0,
      publicUrl: "https://mcp.example.com",
      allowedRoots: [tempRoot],
      oauth: {
        clientId,
        clientSecret,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        rateLimit: {
          maxFailures: 3,
          windowMs: 60_000,
          lockoutMs: 60_000,
        },
      },
    };

    running = createAppServer(config, approvalCode);
    baseUrl = `http://127.0.0.1:${running.server.port}`;
  });

  afterAll(() => {
    running.server.stop(true);
    rmSync(tempRoot, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  });

  test("health and well-known metadata endpoints respond", async () => {
    const health = await fetch(`${baseUrl}/health`);
    expect(health.status).toBe(200);
    const healthJson = (await health.json()) as { status: string; bun: string };
    expect(healthJson.status).toBe("ok");

    const prm = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    expect(prm.status).toBe(200);
    const prmJson = (await prm.json()) as { resource: string };
    expect(prmJson.resource).toBe("https://mcp.example.com/mcp");

    const asm = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    expect(asm.status).toBe(200);
    const asmJson = (await asm.json()) as { code_challenge_methods_supported: string[] };
    expect(asmJson.code_challenge_methods_supported).toContain("S256");
  });

  test("rejects unauthenticated /mcp calls with WWW-Authenticate", async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Forwarded-For": "10.0.0.1" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
    });
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("resource_metadata=");
  });

  test("locks out IP after repeated invalid client secrets", async () => {
    const ip = "10.0.0.99";
    for (let i = 0; i < 2; i += 1) {
      const res = await fetch(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: "wrong-secret",
          code: "fake",
        }),
      });
      expect(res.status).toBe(401);
    }

    const locked = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: "wrong-secret",
        code: "fake",
      }),
    });
    expect(locked.status).toBe(429);
    expect(locked.headers.get("retry-after")).toBeTruthy();
  });

  test("full OAuth 2.1 PKCE flow, refresh rotation, and MCP workspace_init", async () => {
    const ip = "10.0.0.42";
    const verifier = generateRandomToken(48);
    const challenge = computePkceS256(verifier);
    const redirectUri = "https://gemini.google.com/oauth/callback";

    const getAuth = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=xyz`,
    );
    expect(getAuth.status).toBe(200);

    const form = new FormData();
    form.set("client_id", clientId);
    form.set("redirect_uri", redirectUri);
    form.set("code_challenge", challenge);
    form.set("state", "xyz");
    form.set("scope", "mcp:tools");
    form.set("approval_code", approvalCode);

    const postAuth = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: { "X-Forwarded-For": ip },
      body: form,
      redirect: "manual",
    });
    expect(postAuth.status).toBe(302);
    const location = new URL(postAuth.headers.get("location") ?? "");
    const authCode = location.searchParams.get("code") ?? "";
    expect(authCode.length).toBeGreaterThan(20);
    expect(location.searchParams.get("state")).toBe("xyz");

    const tokenRes = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: clientSecret,
        code: authCode,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as { access_token: string; refresh_token: string };
    expect(tokens.access_token.length).toBeGreaterThan(20);

    // Code replay must fail
    const replayRes = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: clientSecret,
        code: authCode,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }),
    });
    expect(replayRes.status).toBe(400);

    // Call MCP initialize and tools/list
    const initRes = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
    });
    expect(initRes.status).toBe(200);

    // Call workspace_init on allowed repo
    const wsOk = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "workspace_init", arguments: { path: join(tempRoot, "repo") } },
      }),
    });
    expect(wsOk.status).toBe(200);
    const wsOkJson = (await wsOk.json()) as { result: { content: Array<{ text: string }>; isError?: boolean } };
    expect(wsOkJson.result.isError).toBeUndefined();
    expect(wsOkJson.result.content[0]?.text).toContain("README.md");

    // Call workspace_init outside allowed root must return isError
    const wsBlocked = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "workspace_init", arguments: { path: outsideDir } },
      }),
    });
    const wsBlockedJson = (await wsBlocked.json()) as { result: { isError?: boolean; content: Array<{ text: string }> } };
    expect(wsBlockedJson.result.isError).toBe(true);
    expect(wsBlockedJson.result.content[0]?.text).toContain("outside allowed workspace roots");

    // Refresh token rotation
    const refreshRes = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: clientId,
        client_secret: clientSecret,
        refresh_token: tokens.refresh_token,
      }),
    });
    expect(refreshRes.status).toBe(200);
    const rotated = (await refreshRes.json()) as { access_token: string; refresh_token: string };
    expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
  });
});
