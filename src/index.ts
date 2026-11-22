import { loadConfig, type AppConfig } from "./config.ts";
import { McpRouter } from "./mcp/server.ts";
import { OAuthServer } from "./oauth/server.ts";
import { ensureBunVersion } from "./runtime/bun-version.ts";
import { AuditLogger } from "./security/audit.ts";
import { withSecurityHeaders } from "./security/headers.ts";

export interface RunningServer {
  server: ReturnType<typeof Bun.serve>;
  oauth: OAuthServer;
  mcp: McpRouter;
  audit: AuditLogger;
}

export interface CreateServerOptions {
  initialApprovalCode?: string;
  onApprovalCodeRotated?: (code: string) => void;
}

export function createAppServer(
  config: AppConfig,
  options: CreateServerOptions = {},
): RunningServer {
  ensureBunVersion("1.4.0");
  const audit = new AuditLogger();
  const oauth = new OAuthServer(config, {
    audit,
    initialApprovalCode: options.initialApprovalCode,
    onApprovalCodeRotated: options.onApprovalCodeRotated,
  });
  const mcp = new McpRouter(config, audit);

  const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    maxRequestBodySize: Math.max(config.maxMcpBodyBytes, 64 * 1024),
    async fetch(req: Request, bunServer): Promise<Response> {
      const url = new URL(req.url);
      const peerIp = bunServer.requestIP(req)?.address ?? "127.0.0.1";
      let res: Response;

      if (req.method === "GET" && url.pathname === "/health") {
        res = Response.json({ status: "ok", bun: Bun.version });
      } else if (
        req.method === "GET" &&
        url.pathname === "/.well-known/oauth-protected-resource"
      ) {
        res = oauth.handleProtectedResourceMetadata();
      } else if (
        req.method === "GET" &&
        url.pathname === "/.well-known/oauth-authorization-server"
      ) {
        res = oauth.handleAuthorizationServerMetadata();
      } else if (url.pathname === "/oauth/authorize" && req.method === "GET") {
        res = await oauth.handleAuthorizeGet(req);
      } else if (url.pathname === "/oauth/authorize" && req.method === "POST") {
        res = await oauth.handleAuthorizePost(req, peerIp);
      } else if (req.method === "POST" && url.pathname === "/oauth/token") {
        res = await oauth.handleToken(req, peerIp);
      } else if (req.method === "POST" && url.pathname === "/oauth/revoke") {
        res = await oauth.handleRevoke(req, peerIp);
      } else if (req.method === "POST" && url.pathname === "/mcp") {
        const auth = oauth.authenticateBearer(req, peerIp);
        res = auth.ok
          ? await mcp.handleRequest(req, auth.clientId, auth.ip)
          : auth.response;
      } else {
        res = new Response("Not Found", { status: 404 });
      }

      return withSecurityHeaders(res);
    },
  });

  return { server, oauth, mcp, audit };
}

if (import.meta.main) {
  const bunVersion = ensureBunVersion("1.4.0");
  const config = loadConfig();
  const { server, oauth } = createAppServer(config, {
    onApprovalCodeRotated(code) {
      console.log(`Rotated one-time OAuth approval code: ${code}`);
    },
  });
  console.log(
    `JustNewMCP listening on http://${server.hostname}:${server.port} (Bun ${bunVersion})`,
  );
  console.log(`One-time OAuth approval code: ${oauth.getApprovalCode()}`);
}
