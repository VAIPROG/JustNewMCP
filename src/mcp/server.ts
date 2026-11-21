import { z } from "zod";
import type { AppConfig } from "../config.ts";
import { extractClientIp } from "../oauth/server.ts";
import { AuditLogger } from "../security/audit.ts";
import { readBodyWithinLimit } from "../security/headers.ts";
import { initializeWorkspace, type WorkspaceState } from "../workspace/init.ts";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const WorkspaceInitArgs = z.object({
  path: z.string().min(1),
});

export class McpRouter {
  private readonly workspaceState: WorkspaceState = {
    activeRoot: null,
    matchedAllowedRoot: null,
  };

  constructor(
    private readonly config: AppConfig,
    private readonly audit: AuditLogger = new AuditLogger(),
  ) {}

  async handleRequest(req: Request, clientId: string): Promise<Response> {
    const contentType = req.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Content-Type must be application/json" } },
        { status: 415 },
      );
    }

    const bodyRes = await readBodyWithinLimit(req, this.config.maxMcpBodyBytes);
    if (!bodyRes.ok) return bodyRes.response;

    let payload: JsonRpcRequest;
    try {
      payload = JSON.parse(bodyRes.text) as JsonRpcRequest;
    } catch {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } },
        { status: 400 },
      );
    }

    const id = payload.id ?? null;
    const ip = extractClientIp(req);

    if (payload.method === "initialize") {
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          capabilities: { tools: {} },
          serverInfo: { name: "JustNewMCP", version: "0.1.0" },
          instructions:
            "Call workspace_init first to select a project inside the allowed roots before reading or modifying files.",
        },
      });
    }

    if (payload.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }

    if (payload.method === "ping") {
      return Response.json({ jsonrpc: "2.0", id, result: {} });
    }

    if (payload.method === "tools/list") {
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: {
          tools: [
            {
              name: "workspace_init",
              description:
                "Set the active working directory inside configured allowed roots and return instruction files, memory preview, and git status.",
              inputSchema: {
                type: "object",
                properties: {
                  path: { type: "string", description: "Directory path inside an allowed root" },
                },
                required: ["path"],
              },
            },
            {
              name: "workspace_info",
              description: "Return the active workspace directory and configured allowed roots.",
              inputSchema: {
                type: "object",
                properties: {},
              },
            },
          ],
        },
      });
    }

    if (payload.method === "tools/call") {
      const name = String(payload.params?.name ?? "");
      const args = (payload.params?.arguments ?? {}) as Record<string, unknown>;

      try {
        if (name === "workspace_init") {
          const parsed = WorkspaceInitArgs.parse(args);
          const result = await initializeWorkspace(
            parsed.path,
            this.config.allowedRoots,
            this.workspaceState,
          );
          this.audit.record("mcp.tool.called", ip, { clientId, detail: "workspace_init" });
          return Response.json({
            jsonrpc: "2.0",
            id,
            result: {
              content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            },
          });
        }

        if (name === "workspace_info") {
          this.audit.record("mcp.tool.called", ip, { clientId, detail: "workspace_info" });
          return Response.json({
            jsonrpc: "2.0",
            id,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      activeRoot: this.workspaceState.activeRoot,
                      matchedAllowedRoot: this.workspaceState.matchedAllowedRoot,
                      allowedRoots: this.config.allowedRoots,
                      deniedPathPatterns: this.config.deniedPathPatterns,
                    },
                    null,
                    2,
                  ),
                },
              ],
            },
          });
        }

        return Response.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Unknown tool: ${name}` },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.audit.record("mcp.tool.denied", ip, { clientId, detail: `${name}: ${message}` });
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [{ type: "text", text: message }],
          },
        });
      }
    }

    return Response.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${payload.method}` },
    });
  }
}
