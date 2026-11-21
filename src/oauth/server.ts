import type { AppConfig } from "../config.ts";
import {
  generateApprovalCode,
  generateRandomToken,
  timingSafeEqualStrings,
  verifyPkceS256,
} from "../security/crypto.ts";
import { IpRateLimiter } from "../security/rate-limiter.ts";

interface AuthCodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  expiresAt: number;
}

interface TokenRecord {
  clientId: string;
  scope: string;
  expiresAt: number;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function extractClientIp(req: Request): string {
  const forwarded = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return first;
  }
  return "127.0.0.1";
}

export class OAuthServer {
  private readonly rateLimiter: IpRateLimiter;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly accessTokens = new Map<string, TokenRecord>();
  private readonly refreshTokens = new Map<string, TokenRecord>();
  private approvalCode: string;

  constructor(private readonly config: AppConfig, initialApprovalCode?: string) {
    this.rateLimiter = new IpRateLimiter(config.oauth.rateLimit);
    this.approvalCode = initialApprovalCode ?? generateApprovalCode();
  }

  getApprovalCode(): string {
    return this.approvalCode;
  }

  rotateApprovalCode(): string {
    this.approvalCode = generateApprovalCode();
    return this.approvalCode;
  }

  handleProtectedResourceMetadata(): Response {
    return Response.json({
      resource: `${this.config.publicUrl}/mcp`,
      authorization_servers: [this.config.publicUrl],
      bearer_methods_supported: ["header"],
      scopes_supported: ["mcp:tools"],
    });
  }

  handleAuthorizationServerMetadata(): Response {
    return Response.json({
      issuer: this.config.publicUrl,
      authorization_endpoint: `${this.config.publicUrl}/oauth/authorize`,
      token_endpoint: `${this.config.publicUrl}/oauth/token`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: ["mcp:tools"],
    });
  }

  async handleAuthorizeGet(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const clientId = url.searchParams.get("client_id") ?? "";
    const redirectUri = url.searchParams.get("redirect_uri") ?? "";
    const responseType = url.searchParams.get("response_type") ?? "";
    const codeChallenge = url.searchParams.get("code_challenge") ?? "";
    const codeChallengeMethod = url.searchParams.get("code_challenge_method") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const scope = url.searchParams.get("scope") ?? "mcp:tools";

    if (responseType !== "code") {
      return new Response("Unsupported response_type", { status: 400 });
    }
    if (!timingSafeEqualStrings(clientId, this.config.oauth.clientId)) {
      return new Response("Unknown client_id", { status: 400 });
    }
    if (!redirectUri.startsWith("https://") && !redirectUri.startsWith("http://127.0.0.1") && !redirectUri.startsWith("http://localhost")) {
      return new Response("Invalid redirect_uri", { status: 400 });
    }
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return new Response("PKCE S256 is required", { status: 400 });
    }

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Authorize JustNewMCP</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 420px; margin: 64px auto; padding: 0 16px; color: #111; }
    input, button { width: 100%; padding: 10px; margin-top: 8px; box-sizing: border-box; font-size: 15px; }
    button { background: #111; color: #fff; border: 0; cursor: pointer; }
    code { background: #f3f3f3; padding: 2px 5px; }
  </style>
</head>
<body>
  <h1>Approve MCP access</h1>
  <p>Client <code>${escapeHtml(clientId)}</code> is requesting scope <code>${escapeHtml(scope)}</code>.</p>
  <form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="${escapeHtml(clientId)}" />
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}" />
    <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}" />
    <input type="hidden" name="state" value="${escapeHtml(state)}" />
    <input type="hidden" name="scope" value="${escapeHtml(scope)}" />
    <label for="approval_code">Terminal approval code</label>
    <input id="approval_code" name="approval_code" autocomplete="off" required />
    <button type="submit">Approve</button>
  </form>
</body>
</html>`;

    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  async handleAuthorizePost(req: Request): Promise<Response> {
    const ip = extractClientIp(req);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      return new Response("Too many failed attempts", {
        status: 429,
        headers: { "Retry-After": String(gate.retryAfterSec) },
      });
    }

    const form = await req.formData();
    const clientId = String(form.get("client_id") ?? "");
    const redirectUri = String(form.get("redirect_uri") ?? "");
    const codeChallenge = String(form.get("code_challenge") ?? "");
    const state = String(form.get("state") ?? "");
    const scope = String(form.get("scope") ?? "mcp:tools");
    const submittedCode = String(form.get("approval_code") ?? "").trim().toUpperCase();

    if (!timingSafeEqualStrings(clientId, this.config.oauth.clientId)) {
      this.rateLimiter.recordFailure(ip);
      return new Response("Invalid client_id", { status: 400 });
    }

    if (!timingSafeEqualStrings(submittedCode, this.approvalCode)) {
      const fail = this.rateLimiter.recordFailure(ip);
      return new Response("Invalid approval code", {
        status: fail.locked ? 429 : 403,
        headers: fail.locked ? { "Retry-After": String(fail.retryAfterSec) } : undefined,
      });
    }

    this.rateLimiter.recordSuccess(ip);
    this.rotateApprovalCode();

    const code = generateRandomToken(32);
    this.authCodes.set(code, {
      clientId,
      redirectUri,
      codeChallenge,
      scope,
      expiresAt: Date.now() + this.config.oauth.authCodeTtlSec * 1000,
    });

    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (state) {
      target.searchParams.set("state", state);
    }

    return new Response(null, {
      status: 302,
      headers: {
        Location: target.toString(),
        "Cache-Control": "no-store",
      },
    });
  }

  private extractClientCredentials(req: Request, body: URLSearchParams): { clientId: string; clientSecret: string } {
    const auth = req.headers.get("authorization");
    if (auth?.startsWith("Basic ")) {
      const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
      const sep = decoded.indexOf(":");
      if (sep !== -1) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, sep)),
          clientSecret: decodeURIComponent(decoded.slice(sep + 1)),
        };
      }
    }
    return {
      clientId: body.get("client_id") ?? "",
      clientSecret: body.get("client_secret") ?? "",
    };
  }

  async handleToken(req: Request): Promise<Response> {
    const ip = extractClientIp(req);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      return Response.json(
        { error: "temporarily_unavailable", error_description: "Rate limit exceeded" },
        { status: 429, headers: { "Retry-After": String(gate.retryAfterSec) } },
      );
    }

    const text = await req.text();
    const params = new URLSearchParams(text);
    const grantType = params.get("grant_type") ?? "";
    const { clientId, clientSecret } = this.extractClientCredentials(req, params);

    const clientValid =
      timingSafeEqualStrings(clientId, this.config.oauth.clientId) &&
      timingSafeEqualStrings(clientSecret, this.config.oauth.clientSecret);

    if (!clientValid) {
      const fail = this.rateLimiter.recordFailure(ip);
      return Response.json(
        { error: "invalid_client" },
        {
          status: fail.locked ? 429 : 401,
          headers: fail.locked ? { "Retry-After": String(fail.retryAfterSec) } : undefined,
        },
      );
    }

    if (grantType === "authorization_code") {
      const code = params.get("code") ?? "";
      const redirectUri = params.get("redirect_uri") ?? "";
      const codeVerifier = params.get("code_verifier") ?? "";

      const record = this.authCodes.get(code);
      this.authCodes.delete(code);

      if (!record || record.expiresAt < Date.now() || record.redirectUri !== redirectUri) {
        this.rateLimiter.recordFailure(ip);
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
        this.rateLimiter.recordFailure(ip);
        return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });
      }

      this.rateLimiter.recordSuccess(ip);
      return this.issueTokenPair(record.clientId, record.scope);
    }

    if (grantType === "refresh_token") {
      const refresh = params.get("refresh_token") ?? "";
      const record = this.refreshTokens.get(refresh);
      this.refreshTokens.delete(refresh);

      if (!record || record.expiresAt < Date.now() || record.clientId !== clientId) {
        this.rateLimiter.recordFailure(ip);
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      this.rateLimiter.recordSuccess(ip);
      return this.issueTokenPair(record.clientId, record.scope);
    }

    return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
  }

  private issueTokenPair(clientId: string, scope: string): Response {
    const now = Date.now();
    const accessToken = generateRandomToken(32);
    const refreshToken = generateRandomToken(32);

    this.accessTokens.set(accessToken, {
      clientId,
      scope,
      expiresAt: now + this.config.oauth.accessTokenTtlSec * 1000,
    });
    this.refreshTokens.set(refreshToken, {
      clientId,
      scope,
      expiresAt: now + this.config.oauth.refreshTokenTtlSec * 1000,
    });

    return Response.json(
      {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: this.config.oauth.accessTokenTtlSec,
        refresh_token: refreshToken,
        scope,
      },
      {
        status: 200,
        headers: { "Cache-Control": "no-store" },
      },
    );
  }

  authenticateBearer(req: Request): { ok: true; clientId: string; scope: string } | { ok: false; response: Response } {
    const ip = extractClientIp(req);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      return {
        ok: false,
        response: new Response("Too many failed attempts", {
          status: 429,
          headers: { "Retry-After": String(gate.retryAfterSec) },
        }),
      };
    }

    const auth = req.headers.get("authorization") ?? "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    const token = match?.[1]?.trim();

    if (token) {
      const record = this.accessTokens.get(token);
      if (record && record.expiresAt > Date.now()) {
        return { ok: true, clientId: record.clientId, scope: record.scope };
      }
    }

    this.rateLimiter.recordFailure(ip);
    const metadataUrl = `${this.config.publicUrl}/.well-known/oauth-protected-resource`;
    return {
      ok: false,
      response: Response.json(
        { error: "unauthorized" },
        {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}"`,
          },
        },
      ),
    };
  }
}
