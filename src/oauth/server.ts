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
import { renderAuthorizePage } from "../ui/pages.ts";
import {
  computeServerIdentity,
  defaultTokenStorePath,
  HashedTokenStore,
} from "./token-store.ts";

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

const MAX_OAUTH_BODY_BYTES = 16 * 1024;
const CSRF_TTL_MS = 10 * 60 * 1000;
const CSRF_SESSION_COOKIE = "justnewmcp_csrf_sid";

function normalizeIp(ip: string): string {
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

export function extractClientIp(
  req: Request,
  peerIp = "127.0.0.1",
  trustedProxies: string[] = [],
): string {
  const normalizedPeer = normalizeIp(peerIp);
  const isTrustedProxy = trustedProxies.some(
    (proxy) => normalizeIp(proxy) === normalizedPeer,
  );
  if (!isTrustedProxy) {
    return normalizedPeer;
  }

  const cfIp = req.headers.get("cf-connecting-ip")?.trim();
  if (cfIp) {
    return normalizeIp(cfIp);
  }

  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const trustedSet = new Set(trustedProxies.map(normalizeIp));
    const hops = xff
      .split(",")
      .map((part) => normalizeIp(part.trim()))
      .filter(Boolean);
    for (let i = hops.length - 1; i >= 0; i -= 1) {
      const hop = hops[i];
      if (hop && !trustedSet.has(hop)) {
        return hop;
      }
    }
  }
  return normalizedPeer;
}

export function isAllowedRedirectUri(
  redirectUri: string,
  allowlist: string[],
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return false;
  }

  if (parsed.hash !== "") {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return false;
  }
  const isLoopback =
    parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost";
  if (parsed.protocol === "http:" && !isLoopback) {
    return false;
  }

  return allowlist.some((entry) => {
    try {
      const allowed = new URL(entry);
      const allowedIsLoopback =
        allowed.protocol === "http:" &&
        (allowed.hostname === "127.0.0.1" || allowed.hostname === "localhost");

      if (allowedIsLoopback && allowed.port === "") {
        if (parsed.protocol !== "http:" || parsed.hostname !== allowed.hostname)
          return false;
        if (allowed.pathname === "/" && allowed.search === "") return true;
        return (
          parsed.pathname === allowed.pathname &&
          parsed.search === allowed.search
        );
      }

      if (allowed.origin !== parsed.origin) return false;
      if (allowed.pathname === "/" && allowed.search === "") return true;
      return (
        parsed.pathname === allowed.pathname && parsed.search === allowed.search
      );
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
  private readonly csrfSecret: string;
  private readonly authCodes = new Map<string, AuthCodeRecord>();
  private readonly accessTokens = new Map<string, TokenRecord>();
  private readonly refreshTokens = new Map<string, TokenRecord>();
  private readonly tokenStore?: HashedTokenStore;
  private tokenStoreDirty = false;
  private approvalCode: string;

  constructor(
    private readonly config: AppConfig,
    options: OAuthServerOptions = {},
  ) {
    this.rateLimiter = new IpRateLimiter(config.oauth.rateLimit);
    this.audit = options.audit ?? new AuditLogger();
    this.onApprovalCodeRotated = options.onApprovalCodeRotated;
    this.csrfSecret = generateRandomToken(32);
    this.approvalCode = options.initialApprovalCode ?? generateApprovalCode();

    if (!config.oauth.inMemoryTokens) {
      const serverIdentity = computeServerIdentity(
        config.publicUrl,
        config.oauth.clientId,
        config.oauth.clientSecret,
      );
      const storePath =
        config.oauth.tokenStorePath ?? defaultTokenStorePath(serverIdentity);
      this.tokenStore = new HashedTokenStore(
        storePath,
        config.allowedRoots,
        serverIdentity,
      );
      const loaded = this.tokenStore.load();
      for (const [hash, record] of loaded.accessTokens) {
        this.accessTokens.set(hash, record);
      }
      for (const [hash, record] of loaded.refreshTokens) {
        this.refreshTokens.set(hash, record);
      }
    }
  }

  close(): void {
    this.tokenStore?.close();
  }

  private persistTokens(now = Date.now()): void {
    if (!this.tokenStore) return;
    try {
      this.tokenStore.save(this.accessTokens, this.refreshTokens, now);
      this.tokenStoreDirty = false;
    } catch (err) {
      this.tokenStoreDirty = true;
      throw err;
    }
  }

  private resolveIp(req: Request, peerIp?: string): string {
    return extractClientIp(
      req,
      peerIp ?? "127.0.0.1",
      this.config.trustedProxies,
    );
  }

  private pruneExpired(now = Date.now()): void {
    for (const [k, v] of this.authCodes) {
      if (v.expiresAt <= now) this.authCodes.delete(k);
    }
    let tokensChanged = false;
    for (const [k, v] of this.accessTokens) {
      if (v.expiresAt <= now) {
        this.accessTokens.delete(k);
        tokensChanged = true;
      }
    }
    for (const [k, v] of this.refreshTokens) {
      if (v.expiresAt <= now) {
        this.refreshTokens.delete(k);
        tokensChanged = true;
      }
    }
    if (tokensChanged || this.tokenStoreDirty) {
      try {
        this.persistTokens(now);
      } catch {
        // Best-effort during read/auth paths; tokenStoreDirty remains true for retry.
      }
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
      authorization_response_iss_parameter_supported: true,
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
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
    const codeChallengeMethod =
      url.searchParams.get("code_challenge_method") ?? "";
    const state = url.searchParams.get("state") ?? "";
    const scope = url.searchParams.get("scope") ?? "mcp:tools";

    if (responseType !== "code") {
      return new Response("Unsupported response_type", { status: 400 });
    }
    if (!timingSafeEqualStrings(clientId, this.config.oauth.clientId)) {
      return new Response("Unknown client_id", { status: 400 });
    }
    if (
      !isAllowedRedirectUri(redirectUri, this.config.oauth.allowedRedirectUris)
    ) {
      return new Response("Disallowed redirect_uri", { status: 400 });
    }
    if (!codeChallenge || codeChallengeMethod !== "S256") {
      return new Response("PKCE S256 is required", { status: 400 });
    }

    return this.buildAuthorizePageResponse({
      clientId,
      scope,
      redirectUri,
      codeChallenge,
      state,
      status: 200,
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

    const contentType = (req.headers.get("content-type") ?? "").toLowerCase();
    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return new Response("Unsupported Content-Type", { status: 415 });
    }

    const bodyRes = await readBodyWithinLimit(req, MAX_OAUTH_BODY_BYTES);
    if (!bodyRes.ok) return bodyRes.response;

    const params = new URLSearchParams(bodyRes.text);
    const cookies = new Bun.CookieMap(req.headers.get("cookie") ?? "");
    const csrfSessionId = cookies.get(CSRF_SESSION_COOKIE) ?? "";
    const csrfField = params.get("csrf_token") ?? "";

    const csrfValid =
      Boolean(csrfSessionId) &&
      Boolean(csrfField) &&
      Bun.CSRF.verify(csrfField, {
        secret: this.csrfSecret,
        sessionId: csrfSessionId,
      });

    if (!csrfValid) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, {
        detail: "invalid_csrf",
      });
      return new Response("Invalid CSRF token", { status: 403 });
    }

    const clientId = params.get("client_id") ?? "";
    const redirectUri = params.get("redirect_uri") ?? "";
    const codeChallenge = params.get("code_challenge") ?? "";
    const state = params.get("state") ?? "";
    const scope = params.get("scope") ?? "mcp:tools";
    const submittedCode = (params.get("approval_code") ?? "")
      .trim()
      .toUpperCase();

    if (!timingSafeEqualStrings(clientId, this.config.oauth.clientId)) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, {
        detail: "invalid_client",
      });
      return new Response("Invalid client_id", { status: 400 });
    }

    if (
      !isAllowedRedirectUri(redirectUri, this.config.oauth.allowedRedirectUris)
    ) {
      this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, {
        clientId,
        detail: "disallowed_redirect_uri",
      });
      return new Response("Disallowed redirect_uri", { status: 400 });
    }

    if (!timingSafeEqualStrings(submittedCode, this.approvalCode)) {
      const fail = this.rateLimiter.recordFailure(ip);
      this.audit.record("oauth.authorize.denied", ip, {
        clientId,
        detail: "invalid_approval_code",
      });
      const errorMessage = fail.locked
        ? `Invalid approval code. Too many failed attempts; try again in ${fail.retryAfterSec} seconds.`
        : "Invalid approval code. Check your local approval-code file and try again.";
      return this.buildAuthorizePageResponse({
        clientId,
        scope,
        redirectUri,
        codeChallenge,
        state,
        status: fail.locked ? 429 : 403,
        errorMessage,
        locked: fail.locked,
        retryAfterSec: fail.locked ? fail.retryAfterSec : undefined,
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
    target.searchParams.set("iss", this.config.publicUrl);
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

  private buildAuthorizePageResponse(opts: {
    clientId: string;
    scope: string;
    redirectUri: string;
    codeChallenge: string;
    state: string;
    status: number;
    errorMessage?: string;
    locked?: boolean;
    retryAfterSec?: number;
  }): Response {
    const csrfSessionId = generateRandomToken(24);
    const csrfToken = Bun.CSRF.generate(this.csrfSecret, {
      sessionId: csrfSessionId,
      expiresIn: CSRF_TTL_MS,
    });
    const redirectOrigin = new URL(opts.redirectUri).origin;
    const html = renderAuthorizePage({
      clientId: opts.clientId,
      scope: opts.scope,
      redirectUri: opts.redirectUri,
      redirectOrigin,
      codeChallenge: opts.codeChallenge,
      state: opts.state,
      csrfToken,
      errorMessage: opts.errorMessage,
      locked: opts.locked,
    });
    const cookie = new Bun.Cookie(CSRF_SESSION_COOKIE, csrfSessionId, {
      httpOnly: true,
      sameSite: "strict",
      path: "/oauth/authorize",
      secure: this.config.publicUrl.startsWith("https://"),
      maxAge: Math.floor(CSRF_TTL_MS / 1000),
    });
    const headers: Record<string, string> = {
      "Content-Type": "text/html; charset=utf-8",
      // Omit form-action so Chromium allows multi-hop OAuth callback redirects
      // (e.g. oauth-redirect.googleusercontent.com -> gemini.google.com).
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      "Set-Cookie": cookie.toString(),
    };
    if (opts.retryAfterSec !== undefined) {
      headers["Retry-After"] = String(opts.retryAfterSec);
    }
    return new Response(html, { status: opts.status, headers });
  }

  private extractClientCredentials(
    req: Request,
    body: URLSearchParams,
  ): { clientId: string; clientSecret: string } {
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

  private verifyClient(
    req: Request,
    params: URLSearchParams,
  ): { ok: boolean; clientId: string } {
    const { clientId, clientSecret } = this.extractClientCredentials(
      req,
      params,
    );
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
        {
          error: "temporarily_unavailable",
          error_description: "Rate limit exceeded",
        },
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
          headers: fail.locked
            ? { "Retry-After": String(fail.retryAfterSec) }
            : undefined,
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

      if (
        !record ||
        record.expiresAt < Date.now() ||
        record.redirectUri !== redirectUri
      ) {
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, {
          clientId: client.clientId,
          detail: "invalid_code",
        });
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, {
          clientId: client.clientId,
          detail: "pkce_mismatch",
        });
        return Response.json(
          {
            error: "invalid_grant",
            error_description: "PKCE verification failed",
          },
          { status: 400 },
        );
      }

      const res = this.issueTokenPair(record.clientId, record.scope, {
        rollbackAuthCode: { hash: codeHash, record },
      });
      this.rateLimiter.recordSuccess(ip);
      this.audit.record("oauth.token.issued", ip, {
        clientId: record.clientId,
        detail: "authorization_code",
      });
      return res;
    }

    if (grantType === "refresh_token") {
      const refresh = params.get("refresh_token") ?? "";
      const refreshHash = sha256Hex(refresh);
      const record = this.refreshTokens.get(refreshHash);
      const deleted = this.refreshTokens.delete(refreshHash);

      if (
        !record ||
        record.expiresAt < Date.now() ||
        record.clientId !== client.clientId
      ) {
        if (deleted || this.tokenStoreDirty) {
          this.persistTokens();
        }
        this.rateLimiter.recordFailure(ip);
        this.audit.record("oauth.token.denied", ip, {
          clientId: client.clientId,
          detail: "invalid_refresh_token",
        });
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      const res = this.issueTokenPair(record.clientId, record.scope, {
        rollbackRefresh: { hash: refreshHash, record },
      });
      this.rateLimiter.recordSuccess(ip);
      this.audit.record("oauth.token.issued", ip, {
        clientId: record.clientId,
        detail: "refresh_token",
      });
      return res;
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
      const removedAccess = this.accessTokens.delete(hash);
      const removedRefresh = this.refreshTokens.delete(hash);
      if (removedAccess || removedRefresh || this.tokenStoreDirty) {
        this.persistTokens();
      }
      this.audit.record("oauth.token.revoked", ip, {
        clientId: client.clientId,
      });
    }

    return new Response(null, { status: 200 });
  }

  private issueTokenPair(
    clientId: string,
    scope: string,
    opts?: {
      rollbackAuthCode?: { hash: string; record: AuthCodeRecord };
      rollbackRefresh?: { hash: string; record: TokenRecord };
    },
  ): Response {
    const now = Date.now();
    const accessToken = generateRandomToken(32);
    const refreshToken = generateRandomToken(32);
    const accessHash = sha256Hex(accessToken);
    const refreshHash = sha256Hex(refreshToken);

    this.accessTokens.set(accessHash, {
      clientId,
      scope,
      expiresAt: now + this.config.oauth.accessTokenTtlSec * 1000,
    });
    this.refreshTokens.set(refreshHash, {
      clientId,
      scope,
      expiresAt: now + this.config.oauth.refreshTokenTtlSec * 1000,
    });
    try {
      this.persistTokens(now);
    } catch (err) {
      this.accessTokens.delete(accessHash);
      this.refreshTokens.delete(refreshHash);
      if (opts?.rollbackAuthCode) {
        this.authCodes.set(
          opts.rollbackAuthCode.hash,
          opts.rollbackAuthCode.record,
        );
      }
      if (opts?.rollbackRefresh) {
        this.refreshTokens.set(
          opts.rollbackRefresh.hash,
          opts.rollbackRefresh.record,
        );
      }
      throw err;
    }

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
  ):
    | { ok: true; clientId: string; scope: string; ip: string }
    | { ok: false; response: Response } {
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
