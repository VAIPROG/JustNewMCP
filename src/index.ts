import { loadConfig, type AppConfig } from "./config.ts";
import { McpRouter } from "./mcp/server.ts";
import { OAuthServer } from "./oauth/server.ts";
import { ensureBunVersion } from "./runtime/bun-version.ts";

export interface RunningServer {
  server: ReturnType<typeof Bun.serve>;
  oauth: OAuthServer;
  mcp: McpRouter;
}

export function createAppServer(config: AppConfig, initialApprovalCode?: string): RunningServer {
  ensureBunVersion("1.4.0");
  const oauth = new OAuthServer(config, initialApprovalCode);
  const mcp = new McpRouter(config);

  const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url);

      if (req.method === "GET" && url.pathname === "/health") {
        return Response.json({ status: "ok", bun: Bun.version });
      }

      if (req.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
        return oauth.handleProtectedResourceMetadata();
      }

      if (req.method === "GET" && url.pathname === "/.well-known/oauth-authorization-server") {
        return oauth.handleAuthorizationServerMetadata();
      }

      if (url.pathname === "/oauth/authorize") {
        if (req.method === "GET") return oauth.handleAuthorizeGet(req);
        if (req.method === "POST") return oauth.handleAuthorizePost(req);
      }

      if (req.method === "POST" && url.pathname === "/oauth/token") {
        return oauth.handleToken(req);
      }

      if (req.method === "POST" && url.pathname === "/mcp") {
        const auth = oauth.authenticateBearer(req);
        if (!auth.ok) return auth.response;
        return mcp.handleRequest(req);
      }

      return new Response("Not Found", { status: 404 });
    },
  });

  return { server, oauth, mcp };
}

if (import.meta.main) {
  const bunVersion = ensureBunVersion("1.4.0");
  const config = loadConfig();
  const { server, oauth } = createAppServer(config);
  console.log(`JustNewMCP listening on http://${server.hostname}:${server.port} (Bun ${bunVersion})`);
  console.log(`One-time OAuth approval code: ${oauth.getApprovalCode()}`);
}
