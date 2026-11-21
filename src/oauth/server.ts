import type { AppConfig } from "../config.ts";
import { AuditLogger } from "../security/audit.ts";
import {
  generateApprovalCode,
  generateRandomToken,
  sha256Hex,
  timingSafeEqualStrings,
  verifyPkceS256,
} from "../security/crypto.ts";
import { readBodyWithinLimit } from "../security/headers.ts";
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

interface CsrfRecord {
  expiresAt: number;
}

const MAX_OAUTH_BODY_BYTES = 16 * 1024;
const CSRF_TTL_MS = 10 * 60 * 1000;
const CSRF_COOKIE_NAME = "justnewmcp_csrf";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

export function extractClientIp(
  req: Request,
  peerIp = "127.0.0.1",
  trustedProxies: string[] = [],
): string {
  const normalizedPeer = normalizeIp(peerIp);
  const isTrustedProxy = trustedProxies.some((proxy) => normalizeIp(proxy) === normalizedPeer);
  if (!isTrustedProxy) {
    return normalizedPeer;
  }

  const forwarded = req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for");
  if (forwarded) {
    const first = forwarded.split(",")[0]?.trim();
    if (first) return normalizeIp(first);
  }
  return normalizedPeer;
}

function parseCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    if (k === name) {
      return part.slice(idx + 1).trim();
    }
  }
  return null;
}

export function isAllowedRedirectUri(redirectUri: string, allowlist: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return false;
  }
  if (parsed.protocol === "http:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
    return false;
  }

  return allowlist.some((prefix) => {
    try {
      const allowed = new URL(prefix);
      if (allowed.origin !== parsed.origin) return false;
      if (allowed.pathname === "/" || allowed.pathname === "") return true;
      return parsed.pathname.startsWith(allowed.pathname);
    } catch {
      return false;
    }
  });
}

export interface OAuthServerOptions {
  audit?: AuditLogger;
  initialApprovalCode?: string;
  onApprovalCodeRotated?: (code: string) => void;
}

export class OAuthServer {
  private readonly rateLimiter: IpRateLimiter;
  private readonly audit: AuditLogger;
  private readonly onApprovalCodeRotated?: (code: string) => void;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly accessTokens = new Map<string, TokenRecord>();
  private readonly refreshTokens = new Map<string, TokenRecord>();
  private readonly csrfTokens = new Map<string, CsrfRecord>();
  private approvalCode: string;

  constructor(private readonly config: AppConfig, options: OAuthServerOptions = {}) {
    this.rateLimiter = new IpRateLimiter(config.oauth.rateLimit);
    this.audit = options.audit ?? new AuditLogger();
    this.onApprovalCodeRotated = options.onApprovalCodeRotated;
    this.approvalCode = options.initialApprovalCode ?? generateApprovalCode();
  }

  private resolveIp(req: Request, peerIp?: string): string {
    return extractClientIp(req, peerIp ?? "127.0.0.1", this.config.trustedProxies);
  }

  private pruneExpired(now = Date.now()): void {
    for (const [k, v] of this.authCodes) {
      if (v.expiresAt <= now) this.authCodes.delete(k);
    }
    for (const [k, v] of this.accessTokens) {
      if (v.expiresAt <= now) this.accessTokens.delete(k);
    }
    for (const [k, v] of this.refreshTokens) {
      if (v.expiresAt <= now) this.refreshTokens.delete(k);
    }
    for (const [k, v] of this.csrfTokens) {
      if (v.expiresAt <= now) this.csrfTokens.delete(k);
    }
  }

  getApprovalCode(): string {
    return this.approvalCode;
  }

  rotateApprovalCode(): string {
    this.approvalCode = generateApprovalCode();
    this.onApprovalCodeRotated?.(this.approvalCode);
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
      revocation_endpoint: `${this.config.publicUrl}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      scopes_supported: ["mcp:tools"],
    });
  }

  async handleAuthorizeGet(req: Request): Promise<Response> {
    this.pruneExpired();
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
    if (!isAllowedRedirectUri(redirectUri, this.config.oauth.allowedRedirectUris)) {
      return new Response("Disallowed redirect_uri", { status: 400 });
    }
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return new Response("PKCE S256 is required", { status: 400 });
    }

    const csrfToken = generateRandomToken(24);
    this.csrfTokens.set(sha256Hex(csrfToken), { expiresAt: Date.now() + CSRF_TTL_MS });

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
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
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

    const secureFlag = this.config.publicUrl.startsWith("https://") ? "; Secure" : "";
    return new Response(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy":
          "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        "Set-Cookie": `${CSRF_COOKIE_NAME}=${csrfToken}; HttpOnly; SameSite=Strict; Path=/oauth/authorize${secureFlag}`,
      },
    });
  }

  async handleAuthorizePost(req: Request, peerIp?: string): Promise<Response> {
    this.pruneExpired();
    const ip = this.resolveIp(req, peerIp);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      this.audit.record("oauth.rate_limited", ip, { detail: "authorize" });
      return new Response("Too many failed attempts", {
        status: 429,
        headers: { "Retry-After": String(gate.retryAfterSec) },
      });
    }

    const form = await req.formData();
    const csrfField = String(form.get("csrf_token") ?? "");
    const csrfCookie = parseCookie(req.headers.get("cookie"), CSRF_COOKIE_NAME) ?? "";
    const csrfHash = sha256Hex(csrfField);
    const csrfRecord = this.csrfTokens.get(csrfHash);
    this.csrfTokens.delete(csrfHash);

    if (
      !csrfField ||
      !csrfCookie ||
      !csrfRecord ||
      csrfRecord.expiresAt < Date.now() ||
      !timingSafeEqualStrings(csrfField, csrfCookie)
    ) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, { detail: "invalid_csrf" });
      return new Response("Invalid CSRF token", { status: 403 });
    }

    const clientId = String(form.get("client_id") ?? "");
    const redirectUri = String(form.get("redirect_uri") ?? "");
    const codeChallenge = String(form.get("code_challenge") ?? "");
    const state = String(form.get("state") ?? "");
    const scope = String(form.get("scope") ?? "mcp:tools");
    const submittedCode = String(form.get("approval_code") ?? "").trim().toUpperCase();

    if (!timingSafeEqualStrings(clientId, this.config.oauth.clientId)) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, { detail: "invalid_client" });
      return new Response("Invalid client_id", { status: 400 });
    }

    if (!isAllowedRedirectUri(redirectUri, this.config.oauth.allowedRedirectUris)) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, { clientId, detail: "disallowed_redirect_uri" });
      return new Response("Disallowed redirect_uri", { status: 400 });
    }

    if (!timingSafeEqualStrings(submittedCode, this.approvalCode)) {
      const fail = this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, { clientId, detail: "invalid_approval_code" });
      return new Response("Invalid approval code", {
        status: fail.locked ? 429 : 403,
        headers: fail.locked ? { "Retry-After": String(fail.retryAfterSec) } : undefined,
      });
    }

    this.rateLimiter.recordSuccess(ip);
    this.rotateApprovalCode();
    this.audit.record("oauth.authorize.approved", ip, { clientId });

    const code = generateRandomToken(32);
    this.authCodes.set(sha256Hex(code), {
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

  private verifyClient(req: Request, params: URLSearchParams): { ok: boolean; clientId: string } {
    const { clientId, clientSecret } = this.extractClientCredentials(req, params);
    const valid =
      timingSafeEqualStrings(clientId, this.config.oauth.clientId) &&
      timingSafeEqualStrings(clientSecret, this.config.oauth.clientSecret);
    return { ok: valid, clientId };
  }

  async handleToken(req: Request, peerIp?: string): Promise<Response> {
    this.pruneExpired();
    const ip = this.resolveIp(req, peerIp);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      this.audit.record("oauth.rate_limited", ip, { detail: "token" });
      return Response.json(
        { error: "temporarily_unavailable", error_description: "Rate limit exceeded" },
        { status: 429, headers: { "Retry-After": String(gate.retryAfterSec) } },
      );
    }

    const bodyRes = await readBodyWithinLimit(req, MAX_OAUTH_BODY_BYTES);
    if (!bodyRes.ok) return bodyRes.response;

    const params = new URLSearchParams(bodyRes.text);
    const grantType = params.get("grant_type") ?? "";
    const client = this.verifyClient(req, params);

    if (!client.ok) {
      const fail = this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.token.denied", ip, { detail: "invalid_client" });
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

      const codeHash = sha256Hex(code);
      const record = this.authCodes.get(codeHash);
      this.authCodes.delete(codeHash);

      if (!record || record.expiresAt < Date.now() || record.redirectUri !== redirectUri) {
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, { clientId: client.clientId, detail: "invalid_code" });
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, { clientId: client.clientId, detail: "pkce_mismatch" });
        return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });
      }

      this.rateLimiter.recordSuccess(ip);
      this.audit.record("oauth.token.issued", ip, { clientId: record.clientId, detail: "authorization_code" });
      return this.issueTokenPair(record.clientId, record.scope);
    }

    if (grantType === "refresh_token") {
      const refresh = params.get("refresh_token") ?? "";
      const refreshHash = sha256Hex(refresh);
      const record = this.refreshTokens.get(refreshHash);
      this.refreshTokens.delete(refreshHash);

      if (!record || record.expiresAt < Date.now() || record.clientId !== client.clientId) {
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, { clientId: client.clientId, detail: "invalid_refresh_token" });
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      this.rateLimiter.recordSuccess(ip);
      this.audit.record("oauth.token.issued", ip, { clientId: record.clientId, detail: "refresh_token" });
      return this.issueTokenPair(record.clientId, record.scope);
    }

    return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
  }

  async handleRevoke(req: Request, peerIp?: string): Promise<Response> {
    this.pruneExpired();
    const ip = this.resolveIp(req, peerIp);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      return Response.json(
        { error: "temporarily_unavailable" },
        { status: 429, headers: { "Retry-After": String(gate.retryAfterSec) } },
      );
    }

    const bodyRes = await readBodyWithinLimit(req, MAX_OAUTH_BODY_BYTES);
    if (!bodyRes.ok) return bodyRes.response;

    const params = new URLSearchParams(bodyRes.text);
    const client = this.verifyClient(req, params);
    if (!client.ok) {
      this.rateLimiter.recordFailure(ip);
      return Response.json({ error: "invalid_client" }, { status: 401 });
    }

    const token = params.get("token") ?? "";
    if (token) {
      const hash = sha256Hex(token);
      this.accessTokens.delete(hash);
      this.refreshTokens.delete(hash);
      this.audit.record("oauth.token.revoked", ip, { clientId: client.clientId });
    }

    return new Response(null, { status: 200 });
  }

  private issueTokenPair(clientId: string, scope: string): Response {
    const now = Date.now();
    const accessToken = generateRandomToken(32);
    const refreshToken = generateRandomToken(32);

    this.accessTokens.set(sha256Hex(accessToken), {
      clientId,
      scope,
      expiresAt: now + this.config.oauth.accessTokenTtlSec * 1000,
    });
    this.refreshTokens.set(sha256Hex(refreshToken), {
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
      { status: 200 },
    );
  }

  authenticateBearer(
    req: Request,
    peerIp?: string,
  ): { ok: true; clientId: string; scope: string; ip: string } | { ok: false; response: Response } {
    this.pruneExpired();
    const ip = this.resolveIp(req, peerIp);
    const gate = this.rateLimiter.check(ip);
    if (!gate.allowed) {
      this.audit.record("oauth.rate_limited", ip, { detail: "mcp_bearer" });
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
      const record = this.accessTokens.get(sha256Hex(token));
      if (record && record.expiresAt > Date.now()) {
        return { ok: true, clientId: record.clientId, scope: record.scope, ip };
      }
    }

    this.rateLimiter.recordFailure(ip);
    this.audit.record("mcp.auth.denied", ip);
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
