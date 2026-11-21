import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_ALLOWED_REDIRECT_URIS,
  DEFAULT_DENIED_PATH_PATTERNS,
  type AppConfig,
} from "../src/config.ts";
import { createAppServer, type RunningServer } from "../src/index.ts";
import { computePkceS256, generateRandomToken } from "../src/security/crypto.ts";
import { readBodyWithinLimit } from "../src/security/headers.ts";

describe("OAuth 2.1 security hardening and MCP /mcp integration", () => {
  let tempRoot: string;
  let outsideDir: string;
  let running: RunningServer;
  let baseUrl: string;
  const rotatedCodes: string[] = [];
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
      trustedProxies: ["127.0.0.1", "::1"],
      allowedRoots: [tempRoot],
      deniedPathPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      maxMcpBodyBytes: 4096,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        rateLimit: {
          maxFailures: 3,
          windowMs: 60_000,
          lockoutMs: 60_000,
          maxTrackedIps: 1000,
        },
      },
    };

    running = createAppServer(config, {
      initialApprovalCode: approvalCode,
      onApprovalCodeRotated(code) {
        rotatedCodes.push(code);
      },
    });
    baseUrl = `http://127.0.0.1:${running.server.port}`;
  });

  afterAll(() => {
    running.server.stop(true);
    rmSync(tempRoot, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  });

  test("health and well-known metadata include security headers and revocation endpoint", async () => {
    const health = await fetch(`${baseUrl}/health`);
    expect(health.status).toBe(200);
    expect(health.headers.get("x-content-type-options")).toBe("nosniff");
    expect(health.headers.get("x-frame-options")).toBe("DENY");
    expect(health.headers.get("referrer-policy")).toBe("no-referrer");
    expect(health.headers.get("cache-control")).toBe("no-store");

    const asm = await fetch(`${baseUrl}/.well-known/oauth-authorization-server`);
    expect(asm.status).toBe(200);
    const asmJson = (await asm.json()) as {
      code_challenge_methods_supported: string[];
      revocation_endpoint: string;
    };
    expect(asmJson.code_challenge_methods_supported).toContain("S256");
    expect(asmJson.revocation_endpoint).toBe("https://mcp.example.com/oauth/revoke");
  });

  test("blocks open redirect to untrusted redirect_uri", async () => {
    const challenge = computePkceS256(generateRandomToken(48));
    const res = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent("https://evil.example/steal")}&code_challenge=${challenge}&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);
  });

  test("blocks authorize POST without matching CSRF session cookie and rejects oversized or multipart bodies", async () => {
    const badCsrf = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "10.0.0.55",
      },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: "https://gemini.google.com/oauth/callback",
        code_challenge: computePkceS256(generateRandomToken(48)),
        approval_code: approvalCode,
        csrf_token: "forged-token",
      }),
    });
    expect(badCsrf.status).toBe(403);

    const oversized = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "10.0.0.56",
      },
      body: `pad=${"a".repeat(20_000)}`,
    });
    expect(oversized.status).toBe(413);
  });

  test("readBodyWithinLimit cancels chunked streams without Content-Length once limit is exceeded", async () => {
    let chunksPulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        chunksPulled += 1;
        controller.enqueue(new Uint8Array(1024).fill(65));
        if (chunksPulled >= 100) {
          controller.close();
        }
      },
    });
    const req = new Request("http://127.0.0.1/mcp", { method: "POST", body: stream });
    const result = await readBodyWithinLimit(req, 2048);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.response.status).toBe(413);
    }
    expect(chunksPulled).toBeLessThan(10);
  });

  test("ignores spoofed X-Forwarded-For when trustedProxies is empty", async () => {
    const directServer = createAppServer({
      host: "127.0.0.1",
      port: 0,
      publicUrl: "https://mcp.example.com",
      trustedProxies: [],
      allowedRoots: [tempRoot],
      deniedPathPatterns: DEFAULT_DENIED_PATH_PATTERNS,
      maxMcpBodyBytes: 4096,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        rateLimit: {
          maxFailures: 2,
          windowMs: 60_000,
          lockoutMs: 60_000,
          maxTrackedIps: 1000,
        },
      },
    });

    try {
      const url = `http://127.0.0.1:${directServer.server.port}/oauth/token`;
      const first = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "1.1.1.1" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: "wrong",
          code: "fake",
        }),
      });
      expect(first.status).toBe(401);

      const second = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "2.2.2.2" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: clientId,
          client_secret: "wrong",
          code: "fake",
        }),
      });
      expect(second.status).toBe(429);
    } finally {
      directServer.server.stop(true);
    }
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

  test("full OAuth 2.1 PKCE + Bun.CSRF flow, approval rotation, MCP checks, revocation, and audit log", async () => {
    const ip = "10.0.0.42";
    const verifier = generateRandomToken(48);
    const challenge = computePkceS256(verifier);
    const redirectUri = "https://gemini.google.com/oauth/callback";

    const getAuth = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=xyz`,
    );
    expect(getAuth.status).toBe(200);
    expect(getAuth.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");

    const setCookie = getAuth.headers.get("set-cookie") ?? "";
    const cookieMatch = setCookie.match(/justnewmcp_csrf_sid=([^;]+)/);
    const csrfSid = cookieMatch?.[1] ?? "";
    expect(csrfSid.length).toBeGreaterThan(16);

    const html = await getAuth.text();
    const tokenMatch = html.match(/name="csrf_token"\s+value="([^"]+)"/);
    const csrfToken = tokenMatch?.[1] ?? "";
    expect(csrfToken.length).toBeGreaterThan(16);

    const postAuth = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": ip,
        Cookie: `justnewmcp_csrf_sid=${csrfSid}`,
      },
      body: new URLSearchParams({
        csrf_token: csrfToken,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        state: "xyz",
        scope: "mcp:tools",
        approval_code: approvalCode,
      }),
      redirect: "manual",
    });
    expect(postAuth.status).toBe(302);
    expect(rotatedCodes.length).toBe(1);
    expect(rotatedCodes[0]).not.toBe(approvalCode);
    expect(running.oauth.getApprovalCode()).toBe(rotatedCodes[0] ?? "");

    const location = new URL(postAuth.headers.get("location") ?? "");
    const authCode = location.searchParams.get("code") ?? "";
    expect(authCode.length).toBeGreaterThan(20);

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

    const badCt = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "text/plain",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: "ping",
    });
    expect(badCt.status).toBe(415);

    const oversized = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping", params: { pad: "x".repeat(5000) } }),
    });
    expect(oversized.status).toBe(413);

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

    const revokeRes = await fetch(`${baseUrl}/oauth/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": ip },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        token: tokens.access_token,
      }),
    });
    expect(revokeRes.status).toBe(200);

    const afterRevoke = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.access_token}`,
        "X-Forwarded-For": ip,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" }),
    });
    expect(afterRevoke.status).toBe(401);

    const auditText = JSON.stringify(running.audit.list());
    expect(auditText).toContain("oauth.authorize.approved");
    expect(auditText).toContain("oauth.token.issued");
    expect(auditText).toContain("oauth.token.revoked");
    expect(auditText).toContain("mcp.tool.called");
    expect(auditText).not.toContain(tokens.access_token);
    expect(auditText).not.toContain(clientSecret);
  });
});
