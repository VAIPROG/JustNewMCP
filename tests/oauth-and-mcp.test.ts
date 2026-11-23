import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ConfigSchema,
  DEFAULT_ALLOWED_REDIRECT_URIS,
  DEFAULT_DENIED_PATH_PATTERNS,
  type AppConfig,
} from "../src/config.ts";
import { createAppServer, type RunningServer } from "../src/index.ts";
import { isAllowedRedirectUri } from "../src/oauth/server.ts";
import {
  computePkceS256,
  generateRandomToken,
} from "../src/security/crypto.ts";
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
      allowEnvReading: false,
      askHumanAllowance: false,
      allowedCommands: [],
      maxMcpBodyBytes: 4096,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        inMemoryTokens: true,
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
    const landing = await fetch(`${baseUrl}/`);
    expect(landing.status).toBe(200);
    expect(landing.headers.get("content-type")).toContain("text/html");
    expect(landing.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'none'",
    );
    const landingHtml = await landing.text();
    expect(landingHtml).toContain("https://github.com/VAIPROG/JustNewMCP");
    expect(landingHtml).toContain("prefers-color-scheme: dark");
    expect(landingHtml).toContain("https://mcp.example.com/mcp");

    const health = await fetch(`${baseUrl}/health`);
    expect(health.status).toBe(200);
    expect(health.headers.get("x-content-type-options")).toBe("nosniff");
    expect(health.headers.get("x-frame-options")).toBe("DENY");
    expect(health.headers.get("referrer-policy")).toBe("no-referrer");
    expect(health.headers.get("cache-control")).toBe("no-store");

    const asm = await fetch(
      `${baseUrl}/.well-known/oauth-authorization-server`,
    );
    expect(asm.status).toBe(200);
    const asmJson = (await asm.json()) as {
      code_challenge_methods_supported: string[];
      revocation_endpoint: string;
      authorization_response_iss_parameter_supported: boolean;
    };
    expect(asmJson.code_challenge_methods_supported).toContain("S256");
    expect(asmJson.revocation_endpoint).toBe(
      "https://mcp.example.com/oauth/revoke",
    );
    expect(asmJson.authorization_response_iss_parameter_supported).toBe(true);
  });

  test("blocks open redirect and enforces exact callback path and query matching", async () => {
    const challenge = computePkceS256(generateRandomToken(48));
    const res = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent("https://evil.example/steal")}&code_challenge=${challenge}&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);

    const strictAllowlist = [
      "https://gemini.google.com/oauth/callback",
      "http://127.0.0.1",
    ];
    expect(
      isAllowedRedirectUri(
        "https://gemini.google.com/oauth/callback",
        strictAllowlist,
      ),
    ).toBe(true);
    expect(
      isAllowedRedirectUri(
        "https://gemini.google.com/oauth/callback.attacker",
        strictAllowlist,
      ),
    ).toBe(false);
    expect(
      isAllowedRedirectUri(
        "https://gemini.google.com/oauth/callback/extra",
        strictAllowlist,
      ),
    ).toBe(false);
    expect(
      isAllowedRedirectUri(
        "https://gemini.google.com/oauth/callback?next=evil",
        strictAllowlist,
      ),
    ).toBe(false);
    expect(
      isAllowedRedirectUri(
        "https://gemini.google.com/oauth/callback#frag",
        strictAllowlist,
      ),
    ).toBe(false);
    expect(
      isAllowedRedirectUri("http://127.0.0.1:43210/cb", strictAllowlist),
    ).toBe(true);
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
    const req = new Request("http://127.0.0.1/mcp", {
      method: "POST",
      body: stream,
    });
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
      allowEnvReading: false,
      askHumanAllowance: false,
      allowedCommands: [],
      maxMcpBodyBytes: 4096,
      oauth: {
        clientId,
        clientSecret,
        allowedRedirectUris: DEFAULT_ALLOWED_REDIRECT_URIS,
        accessTokenTtlSec: 3600,
        refreshTokenTtlSec: 604800,
        authCodeTtlSec: 300,
        inMemoryTokens: true,
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
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Forwarded-For": "1.1.1.1",
        },
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
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Forwarded-For": "2.2.2.2",
        },
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

  test("walks X-Forwarded-For right-to-left so spoofed leftmost IPs cannot bypass rate limiting", async () => {
    const first = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "198.51.100.1, 203.0.113.77, 127.0.0.1",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: "wrong",
        code: "fake",
      }),
    });
    expect(first.status).toBe(401);

    const second = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "198.51.100.2, 203.0.113.77, 127.0.0.1",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: "wrong",
        code: "fake",
      }),
    });
    expect(second.status).toBe(401);

    const third = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "198.51.100.3, 203.0.113.77, 127.0.0.1",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: clientId,
        client_secret: "wrong",
        code: "fake",
      }),
    });
    expect(third.status).toBe(429);
  });

  test("rejects unauthenticated /mcp calls with WWW-Authenticate", async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": "10.0.0.1",
      },
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
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-Forwarded-For": ip,
        },
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
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": ip,
      },
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
    const csp = getAuth.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("form-action");

    const setCookie = getAuth.headers.get("set-cookie") ?? "";
    const cookieMatch = setCookie.match(/justnewmcp_csrf_sid=([^;]+)/);
    const csrfSid = cookieMatch?.[1] ?? "";
    expect(csrfSid.length).toBeGreaterThan(16);

    const html = await getAuth.text();
    const tokenMatch = html.match(/name="csrf_token"\s+value="([^"]+)"/);
    const csrfToken = tokenMatch?.[1] ?? "";
    expect(csrfToken.length).toBeGreaterThan(16);

    const wrongCode = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": "198.51.100.77",
        Cookie: `justnewmcp_csrf_sid=${csrfSid}`,
      },
      body: new URLSearchParams({
        csrf_token: csrfToken,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        state: "xyz",
        scope: "mcp:tools",
        approval_code: "WRONG-CODE-0000",
      }),
      redirect: "manual",
    });
    expect(wrongCode.status).toBe(403);
    expect(wrongCode.headers.get("content-type")).toContain("text/html");
    const wrongHtml = await wrongCode.text();
    expect(wrongHtml).toContain("Invalid approval code");
    expect(wrongHtml).toContain('role="alert"');
    expect(wrongHtml).toContain('name="csrf_token"');

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
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": ip,
      },
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
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token: string;
    };

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
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 9,
        method: "ping",
        params: { pad: "x".repeat(5000) },
      }),
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
        params: {
          name: "workspace_init",
          arguments: { path: join(tempRoot, "repo") },
        },
      }),
    });
    expect(wsOk.status).toBe(200);
    const wsOkJson = (await wsOk.json()) as {
      result: { content: Array<{ text: string }>; isError?: boolean };
    };
    expect(wsOkJson.result.isError).toBeUndefined();
    expect(wsOkJson.result.content[0]?.text).toContain("README.md");

    const revokeRes = await fetch(`${baseUrl}/oauth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Forwarded-For": ip,
      },
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

  test("supports OpenAI ChatGPT redirect URIs and RFC 9207 iss parameter", async () => {
    expect(
      isAllowedRedirectUri(
        "https://chatgpt.com/connector_platform_oauth_redirect",
        DEFAULT_ALLOWED_REDIRECT_URIS,
      ),
    ).toBe(true);
    expect(
      isAllowedRedirectUri(
        "https://chatgpt.com/connector/oauth/cb_12345",
        DEFAULT_ALLOWED_REDIRECT_URIS,
      ),
    ).toBe(true);
    expect(
      isAllowedRedirectUri(
        "https://platform.openai.com/oauth/callback",
        DEFAULT_ALLOWED_REDIRECT_URIS,
      ),
    ).toBe(true);

    const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
    const verifier = generateRandomToken(48);
    const challenge = computePkceS256(verifier);
    const ip = "10.0.0.88";

    const getRes = await fetch(
      `${baseUrl}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=openai-state`,
      { headers: { "X-Forwarded-For": ip } },
    );
    expect(getRes.status).toBe(200);
    const html = await getRes.text();
    const csrfMatch = html.match(/name="csrf_token" value="([^"]+)"/);
    expect(csrfMatch).not.toBeNull();
    const cookieHeader = getRes.headers.get("set-cookie")?.split(";")[0] ?? "";

    const postRes = await fetch(`${baseUrl}/oauth/authorize`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: cookieHeader,
        "X-Forwarded-For": ip,
      },
      body: new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        state: "openai-state",
        scope: "mcp:tools",
        csrf_token: csrfMatch?.[1] ?? "",
        approval_code: running.oauth.getApprovalCode(),
      }),
    });
    expect(postRes.status).toBe(302);
    const location = new URL(postRes.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(redirectUri);
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(location.searchParams.get("state")).toBe("openai-state");
    expect(location.searchParams.get("iss")).toBe("https://mcp.example.com");
  });

  test("persists hashed OAuth tokens across restarts when inMemoryTokens is false and stays RAM-only when true", async () => {
    const storeDir = mkdtempSync(join(tmpdir(), "justnewmcp-token-store-"));
    const tokenStorePath = join(storeDir, "oauth-tokens.json");
    const ramOnlyPath = join(storeDir, "ram-only-tokens.json");
    const redirectUri = "http://127.0.0.1:43219/callback";

    const makeConfig = (
      inMemoryTokens: boolean,
      storePath: string,
    ): AppConfig =>
      ConfigSchema.parse({
        host: "127.0.0.1",
        port: 0,
        publicUrl: "https://mcp.example.com",
        trustedProxies: ["127.0.0.1", "::1"],
        allowedRoots: [tempRoot],
        oauth: {
          clientId: "persist-test-client",
          clientSecret: "persist-test-secret-value-1234567890",
          allowedRedirectUris: [redirectUri],
          inMemoryTokens,
          tokenStorePath: storePath,
        },
      });

    expect(() =>
      createAppServer(
        makeConfig(false, join(tempRoot, "oauth-tokens-inside.json")),
      ),
    ).toThrow(/outside configured allowedRoots/i);

    const completeOAuth = async (srv: RunningServer) => {
      const url = `http://127.0.0.1:${srv.server.port}`;
      const verifier = generateRandomToken(48);
      const challenge = computePkceS256(verifier);
      const getRes = await fetch(
        `${url}/oauth/authorize?response_type=code&client_id=persist-test-client&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=p1`,
      );
      const html = await getRes.text();
      const csrf = html.match(/name="csrf_token" value="([^"]+)"/)?.[1] ?? "";
      const cookie = getRes.headers.get("set-cookie")?.split(";")[0] ?? "";
      const postRes = await fetch(`${url}/oauth/authorize`, {
        method: "POST",
        redirect: "manual",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: cookie,
        },
        body: new URLSearchParams({
          client_id: "persist-test-client",
          redirect_uri: redirectUri,
          code_challenge: challenge,
          state: "p1",
          scope: "mcp:tools",
          csrf_token: csrf,
          approval_code: srv.oauth.getApprovalCode(),
        }),
      });
      const code =
        new URL(postRes.headers.get("location") ?? "").searchParams.get(
          "code",
        ) ?? "";
      const tokenRes = await fetch(`${url}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
          client_id: "persist-test-client",
          client_secret: "persist-test-secret-value-1234567890",
        }),
      });
      expect(tokenRes.status).toBe(200);
      return (await tokenRes.json()) as {
        access_token: string;
        refresh_token: string;
      };
    };

    try {
      const ramSrv = createAppServer(makeConfig(true, ramOnlyPath));
      try {
        await completeOAuth(ramSrv);
        expect(existsSync(ramOnlyPath)).toBe(false);
      } finally {
        await ramSrv.shutdown(true);
      }

      const srv1 = createAppServer(makeConfig(false, tokenStorePath));
      let tokens: { access_token: string; refresh_token: string };
      try {
        tokens = await completeOAuth(srv1);
      } finally {
        await srv1.shutdown(true);
      }

      expect(existsSync(tokenStorePath)).toBe(true);
      if (process.platform !== "win32") {
        expect(statSync(tokenStorePath).mode & 0o777).toBe(0o600);
      }
      const persistedRaw = readFileSync(tokenStorePath, "utf8");
      expect(persistedRaw).not.toContain(tokens.access_token);
      expect(persistedRaw).not.toContain(tokens.refresh_token);

      const otherSecretConfig = ConfigSchema.parse({
        host: "127.0.0.1",
        port: 0,
        publicUrl: "https://mcp.example.com",
        trustedProxies: ["127.0.0.1", "::1"],
        allowedRoots: [tempRoot],
        oauth: {
          clientId: "persist-test-client",
          clientSecret: "different-server-secret-value-0987654321",
          allowedRedirectUris: [redirectUri],
          inMemoryTokens: false,
          tokenStorePath,
        },
      });
      const foreignSrv = createAppServer(otherSecretConfig);
      try {
        const foreignPing = await fetch(
          `http://127.0.0.1:${foreignSrv.server.port}/mcp`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${tokens.access_token}`,
            },
            body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "ping" }),
          },
        );
        expect(foreignPing.status).toBe(401);
      } finally {
        await foreignSrv.shutdown(true);
      }

      const srv2 = createAppServer(makeConfig(false, tokenStorePath));
      let refreshed: { access_token: string; refresh_token: string };
      try {
        const url2 = `http://127.0.0.1:${srv2.server.port}`;
        const pingRes = await fetch(`${url2}/mcp`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokens.access_token}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        });
        expect(pingRes.status).toBe(200);

        const refreshRes = await fetch(`${url2}/oauth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: tokens.refresh_token,
            client_id: "persist-test-client",
            client_secret: "persist-test-secret-value-1234567890",
          }),
        });
        expect(refreshRes.status).toBe(200);
        refreshed = (await refreshRes.json()) as {
          access_token: string;
          refresh_token: string;
        };

        const revokeRes = await fetch(`${url2}/oauth/revoke`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: "persist-test-client",
            client_secret: "persist-test-secret-value-1234567890",
            token: refreshed.access_token,
          }),
        });
        expect(revokeRes.status).toBe(200);
      } finally {
        await srv2.shutdown(true);
      }

      const srv3 = createAppServer(makeConfig(false, tokenStorePath));
      try {
        const url3 = `http://127.0.0.1:${srv3.server.port}`;
        const revokedPing = await fetch(`${url3}/mcp`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${refreshed.access_token}`,
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
        });
        expect(revokedPing.status).toBe(401);
      } finally {
        await srv3.shutdown(true);
      }
    } finally {
      rmSync(storeDir, { recursive: true, force: true });
    }
  });
});
