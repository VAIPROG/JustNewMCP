import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  mkdirSync,
  openSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { loadConfig, type AppConfig } from "./config.ts";
import { McpRouter } from "./mcp/server.ts";
import { OAuthServer } from "./oauth/server.ts";
import { ensureBunVersion } from "./runtime/bun-version.ts";
import { AuditLogger } from "./security/audit.ts";
import { withSecurityHeaders } from "./security/headers.ts";
import { renderLandingPage } from "./ui/pages.ts";
import { isPathInsideRoot } from "./workspace/paths.ts";

export interface RunningServer {
  server: ReturnType<typeof Bun.serve>;
  oauth: OAuthServer;
  mcp: McpRouter;
  audit: AuditLogger;
  shutdown(closeActiveConnections?: boolean): Promise<void>;
}

export interface CreateServerOptions {
  initialApprovalCode?: string;
  onApprovalCodeRotated?: (code: string) => void;
}

function canonicalizeCandidatePath(filePath: string): string {
  const abs = resolve(filePath);
  if (existsSync(abs)) {
    return realpathSync(abs);
  }
  const trailing: string[] = [];
  let cursor = abs;
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) break;
    trailing.unshift(basename(cursor));
    cursor = parent;
  }
  const realBase = existsSync(cursor) ? realpathSync(cursor) : cursor;
  return join(realBase, ...trailing);
}

export function assertApprovalCodeFileOutsideAllowedRoots(
  filePath: string,
  allowedRoots: string[],
  platform: NodeJS.Platform = process.platform,
): string {
  const canonicalTarget = canonicalizeCandidatePath(filePath);
  for (const root of allowedRoots) {
    const canonicalRoot = existsSync(resolve(root))
      ? realpathSync(resolve(root))
      : resolve(root);
    if (isPathInsideRoot(canonicalTarget, canonicalRoot, platform)) {
      throw new Error(
        `Approval code file "${filePath}" must reside outside configured allowedRoots.`,
      );
    }
  }
  return canonicalTarget;
}

function writeApprovalCodeFile(filePath: string, code: string): void {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const noFollowFlag =
    process.platform !== "win32" && typeof fsConstants.O_NOFOLLOW === "number"
      ? fsConstants.O_NOFOLLOW
      : 0;
  const fd = openSync(
    filePath,
    fsConstants.O_WRONLY |
      fsConstants.O_CREAT |
      fsConstants.O_TRUNC |
      noFollowFlag,
    0o600,
  );
  try {
    if (process.platform !== "win32") {
      fchmodSync(fd, 0o600);
    }
    writeFileSync(fd, `${code}\n`, "utf8");
  } finally {
    closeSync(fd);
  }
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

      if (req.method === "GET" && url.pathname === "/") {
        res = new Response(renderLandingPage(config.publicUrl), {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Security-Policy":
              "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
          },
        });
      } else if (req.method === "GET" && url.pathname === "/health") {
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

  const stopListening = server.stop.bind(server);
  const shutdown = async (closeActiveConnections?: boolean) => {
    await Promise.all([
      stopListening(closeActiveConnections),
      mcp.stopAllBackgroundJobs(),
      mcp.stopLanguageServers(),
    ]);
  };
  server.stop = shutdown;

  return { server, oauth, mcp, audit, shutdown };
}

export function installShutdownSignalHandlers(
  shutdown: RunningServer["shutdown"],
): void {
  let shuttingDown = false;
  const stopOnSignal = (code: number) => {
    if (shuttingDown) return;
    shuttingDown = true;
    void shutdown(true).then(
      () => process.exit(code),
      (err) => {
        console.error("Server shutdown failed:", err);
        process.exit(1);
      },
    );
  };
  process.once("SIGINT", () => stopOnSignal(130));
  process.once("SIGTERM", () => stopOnSignal(143));
}

if (import.meta.main) {
  const bunVersion = ensureBunVersion("1.4.0");
  const config = loadConfig();
  const configuredApprovalPath = process.env.JUSTNEWMCP_APPROVAL_CODE_FILE;
  let approvalCodeFile = configuredApprovalPath
    ? assertApprovalCodeFileOutsideAllowedRoots(
        configuredApprovalPath,
        config.allowedRoots,
      )
    : "";
  const { server, oauth, shutdown } = createAppServer(config, {
    onApprovalCodeRotated(code) {
      writeApprovalCodeFile(approvalCodeFile, code);
      console.log(
        `Rotated one-time OAuth approval code written to ${approvalCodeFile}`,
      );
    },
  });
  if (!approvalCodeFile) {
    approvalCodeFile = assertApprovalCodeFileOutsideAllowedRoots(
      join(
        homedir(),
        ".justnewmcp",
        `approval-code-${server.port}-${process.pid}`,
      ),
      config.allowedRoots,
    );
  }
  writeApprovalCodeFile(approvalCodeFile, oauth.getApprovalCode());
  installShutdownSignalHandlers(shutdown);
  console.log(
    `JustNewMCP listening on http://${server.hostname}:${server.port} (Bun ${bunVersion})`,
  );
  console.log(
    `One-time OAuth approval code written to ${approvalCodeFile} (mode 0600)`,
  );
}
