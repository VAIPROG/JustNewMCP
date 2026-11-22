import { z } from "zod";
import type { AppConfig } from "../config.ts";
import { AuditLogger } from "../security/audit.ts";
import { readBodyWithinLimit } from "../security/headers.ts";
import { BackgroundJobManager } from "../workspace/background-jobs.ts";
import { listCheckpoints, rewindCheckpoint } from "../workspace/checkpoints.ts";
import { runAllowedCmdTool } from "../workspace/cmd-runner.ts";
import {
  readAvailableEnvsTool,
  setEnvVarTool,
} from "../workspace/env-tools.ts";
import {
  applyEditsTool,
  globFilesTool,
  grepFilesTool,
  readFileTool,
  writeFileTool,
} from "../workspace/fs-tools.ts";
import { initializeWorkspace, type WorkspaceState } from "../workspace/init.ts";
import {
  memoryReadTool,
  memorySearchTool,
  memoryWriteTool,
} from "../workspace/memory.ts";
import { assertWorkspaceAnchored } from "../workspace/paths.ts";
import {
  PlanMode,
  TASK_FIELD_LIMITS,
  TASK_STATUSES,
  TaskManager,
} from "../workspace/tasks.ts";

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

const WorkspaceInitArgs = z.object({
  path: z.string().min(1),
});

const ReadFileArgs = z.object({
  path: z.string().min(1),
  offset: z.number().int().min(1).optional(),
  limit: z.number().int().min(1).max(2000).optional(),
  human_approved: z.boolean().optional(),
  human_approval_note: z.string().max(300).optional(),
});

const ReadAvailableEnvsArgs = z.object({
  path: z.string().min(1).optional(),
});

const SetEnvVarArgs = z.object({
  path: z.string().min(1).optional(),
  key: z.string().min(1).max(128),
  value: z.string().optional(),
  action: z.enum(["set", "delete"]).optional(),
});

const EditOpSchema = z.object({
  old_string: z.string().min(1),
  new_string: z.string(),
  replace_all: z.boolean().optional(),
});

const EditFileArgs = z.object({
  path: z.string().min(1),
  old_string: z.string().min(1),
  new_string: z.string(),
  replace_all: z.boolean().optional(),
});

const MultiEditArgs = z.object({
  path: z.string().min(1),
  edits: z.array(EditOpSchema).min(1).max(50),
});

const WriteFileArgs = z.object({
  path: z.string().min(1),
  content: z.string(),
});

const GlobFilesArgs = z.object({
  pattern: z.string().min(1).max(500),
  limit: z.number().int().min(1).max(1000).optional(),
});

const GrepFilesArgs = z.object({
  pattern: z.string().min(1).max(500),
  glob: z.string().min(1).max(500).optional(),
  case_insensitive: z.boolean().optional(),
  context_lines: z.number().int().min(0).max(5).optional(),
  mode: z.enum(["files_with_matches", "content", "count"]).optional(),
  max_matches: z.number().int().min(1).max(500).optional(),
});

const CheckpointListArgs = z.object({
  limit: z.number().int().min(1).max(100).optional(),
});

const CheckpointRewindArgs = z.object({
  checkpoint_id: z.string().min(8).max(64),
});

const RunAllowedCmdArgs = z.object({
  command: z.string().min(1).max(128),
  args: z.array(z.string().max(4096)).max(100).optional(),
  timeout_ms: z.number().int().min(100).max(600_000).optional(),
  background: z.boolean().default(false),
});

const JobId = z.uuid();
const CmdStatusArgs = z.object({
  job_id: JobId.optional(),
  tail_chars: z.number().int().min(1).max(30_000).default(4000),
});
const TaskStopArgs = z.object({
  job_id: JobId,
  grace_ms: z.number().int().min(0).max(10_000).default(2000),
});

const TaskIdArgs = z.object({ id: z.string().min(1) });
const TaskCreateArgs = z.object({
  title: z.string().trim().min(1).max(TASK_FIELD_LIMITS.title),
  status: z.enum(TASK_STATUSES).optional(),
  dependencies: z
    .array(z.string().min(1))
    .max(TASK_FIELD_LIMITS.dependencies)
    .optional(),
  notes: z.string().max(TASK_FIELD_LIMITS.notes).optional(),
});
const TaskUpdateArgs = TaskCreateArgs.partial().merge(TaskIdArgs);
const PlanArgs = z.object({ summary: z.string().optional() });

const MemoryReadArgs = z.object({
  path: z.string().min(1).max(300).optional(),
  offset: z.number().int().min(1).optional(),
  limit: z.number().int().min(1).max(2000).optional(),
});

const MemoryWriteArgs = z.object({
  path: z.string().min(1).max(300).optional(),
  content: z.string(),
  mode: z.enum(["overwrite", "append"]).optional(),
});

const MemorySearchArgs = z.object({
  pattern: z.string().min(1).max(500),
  case_insensitive: z.boolean().optional(),
  max_matches: z.number().int().min(1).max(200).optional(),
});

const TASK_PROPERTIES = {
  title: { type: "string", minLength: 1, maxLength: TASK_FIELD_LIMITS.title },
  status: { type: "string", enum: TASK_STATUSES },
  dependencies: {
    type: "array",
    maxItems: TASK_FIELD_LIMITS.dependencies,
    items: { type: "string" },
    description: "IDs of prerequisite tasks",
  },
  notes: { type: "string", maxLength: TASK_FIELD_LIMITS.notes },
};

const PLAN_PROPERTIES = { summary: { type: "string" } };

const PLAN_BLOCKED_TOOLS = new Set([
  "edit_file",
  "multi_edit",
  "write_file",
  "set_env_var",
  "checkpoint_rewind",
  "run_allowed_cmd",
  "task_stop",
  "memory_write",
]);

const TOOL_DEFINITIONS = [
  {
    name: "workspace_init",
    description:
      "Set the active working directory inside configured allowed roots and return instruction files, memory preview, memory topics, and git status.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Directory path inside an allowed root",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "workspace_info",
    description:
      "Return the active workspace directory, configured allowed roots, and denied path patterns.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "read_file",
    description:
      "Read a UTF-8 file inside the active workspace with line numbers, optional offset, and line limit. Safe .env templates (.env.example) are readable by default; real .env files require allowEnvReading or explicit human approval when askHumanAllowance is enabled.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        offset: { type: "integer", minimum: 1 },
        limit: { type: "integer", minimum: 1, maximum: 2000 },
        human_approved: { type: "boolean" },
        human_approval_note: { type: "string" },
      },
      required: ["path"],
    },
  },
  {
    name: "read_available_envs",
    description:
      "List variable names and value lengths from a .env file without exposing secret values.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Relative path to .env file (default: .env)",
        },
      },
    },
  },
  {
    name: "set_env_var",
    description:
      "Add, update, or delete an environment variable in a .env file with an automatic pre-edit checkpoint.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Relative path to .env file (default: .env)",
        },
        key: { type: "string" },
        value: { type: "string" },
        action: { type: "string", enum: ["set", "delete"] },
      },
      required: ["key"],
    },
  },
  {
    name: "edit_file",
    description:
      "Replace an exact string inside a previously read UTF-8 file and automatically snapshot a local checkpoint before writing.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        old_string: { type: "string" },
        new_string: { type: "string" },
        replace_all: { type: "boolean" },
      },
      required: ["path", "old_string", "new_string"],
    },
  },
  {
    name: "multi_edit",
    description:
      "Atomically apply multiple exact string edits to one previously read UTF-8 file with a single pre-edit checkpoint.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        edits: {
          type: "array",
          items: {
            type: "object",
            properties: {
              old_string: { type: "string" },
              new_string: { type: "string" },
              replace_all: { type: "boolean" },
            },
            required: ["old_string", "new_string"],
          },
        },
      },
      required: ["path", "edits"],
    },
  },
  {
    name: "write_file",
    description:
      "Create or overwrite a file inside the active workspace (creating missing parent folders) with an automatic pre-write checkpoint.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
        content: { type: "string" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "glob_files",
    description:
      "Find files matching a glob pattern inside the active workspace, sorted by modification time.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 1000 },
      },
      required: ["pattern"],
    },
  },
  {
    name: "grep_files",
    description:
      "Search UTF-8 files in the active workspace with a regular expression.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        glob: { type: "string" },
        case_insensitive: { type: "boolean" },
        context_lines: { type: "integer", minimum: 0, maximum: 5 },
        mode: {
          type: "string",
          enum: ["files_with_matches", "content", "count"],
        },
        max_matches: { type: "integer", minimum: 1, maximum: 500 },
      },
      required: ["pattern"],
    },
  },
  {
    name: "checkpoint_list",
    description: "List recent local file checkpoints in the active workspace.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 100 },
      },
    },
  },
  {
    name: "checkpoint_rewind",
    description:
      "Restore a file (or remove a newly created file) from a local checkpoint ID.",
    inputSchema: {
      type: "object",
      properties: {
        checkpoint_id: { type: "string" },
      },
      required: ["checkpoint_id"],
    },
  },
  {
    name: "run_allowed_cmd",
    description:
      "Run an allowlisted executable directly without a shell, optionally starting a background job with a bounded log.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        args: { type: "array", items: { type: "string" } },
        timeout_ms: { type: "integer", minimum: 100, maximum: 600000 },
        background: { type: "boolean", default: false },
      },
      required: ["command"],
    },
  },
  {
    name: "cmd_status",
    description:
      "List background jobs or inspect one job with a bounded log tail.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string", format: "uuid" },
        tail_chars: {
          type: "integer",
          minimum: 1,
          maximum: 30000,
          default: 4000,
        },
      },
    },
  },
  {
    name: "task_stop",
    description: "Stop a background command and report its final status.",
    inputSchema: {
      type: "object",
      properties: {
        job_id: { type: "string", format: "uuid" },
        grace_ms: {
          type: "integer",
          minimum: 0,
          maximum: 10000,
          default: 2000,
        },
      },
      required: ["job_id"],
    },
  },
  {
    name: "task_create",
    description: "Create a server-side task. Status defaults to pending.",
    inputSchema: {
      type: "object",
      properties: TASK_PROPERTIES,
      required: ["title"],
    },
  },
  {
    name: "task_update",
    description:
      "Update the supplied fields of a task. A supplied dependency list replaces the existing list.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" }, ...TASK_PROPERTIES },
      required: ["id"],
    },
  },
  {
    name: "task_list",
    description: "List all tasks in creation order.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "task_get",
    description: "Get a task by ID.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    },
  },
  {
    name: "plan_enter",
    description:
      "Enter read-only workspace mode, optionally recording a plan summary.",
    inputSchema: { type: "object", properties: PLAN_PROPERTIES },
  },
  {
    name: "plan_exit",
    description:
      "Exit read-only workspace mode and return the plan summary, with an optional replacement.",
    inputSchema: { type: "object", properties: PLAN_PROPERTIES },
  },
  {
    name: "memory_read",
    description:
      "Read MEMORY.md or a nested topic file inside the active project's memory directory.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description:
            "Relative path inside project memory (default: MEMORY.md)",
        },
        offset: { type: "integer", minimum: 1 },
        limit: { type: "integer", minimum: 1, maximum: 2000 },
      },
    },
  },
  {
    name: "memory_write",
    description:
      "Create, overwrite, or append to MEMORY.md or a topic file inside the active project's memory directory.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description:
            "Relative path inside project memory (default: MEMORY.md)",
        },
        content: { type: "string" },
        mode: { type: "string", enum: ["overwrite", "append"] },
      },
      required: ["content"],
    },
  },
  {
    name: "memory_search",
    description:
      "Search Markdown files inside the active project's memory directory by regular expression.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        case_insensitive: { type: "boolean" },
        max_matches: { type: "integer", minimum: 1, maximum: 200 },
      },
      required: ["pattern"],
    },
  },
];

export class McpRouter {
  private readonly workspaceState: WorkspaceState = {
    activeRoot: null,
    matchedAllowedRoot: null,
  };
  private readonly readTracker = new Set<string>();
  private readonly tasks = new TaskManager();
  private readonly backgroundJobs = new BackgroundJobManager();
  private readonly plan = new PlanMode();
  private activeWorkspaceMutations = 0;

  constructor(
    private readonly config: AppConfig,
    private readonly audit: AuditLogger = new AuditLogger(),
  ) {}

  stopAllBackgroundJobs(): Promise<void> {
    return this.backgroundJobs.stopAllBackgroundJobs();
  }

  private requireActiveWorkspace(): string {
    if (!this.workspaceState.activeRoot) {
      throw new Error("No active workspace. Call workspace_init first.");
    }
    return assertWorkspaceAnchored(
      this.workspaceState.activeRoot,
      this.config.allowedRoots,
    );
  }

  async handleRequest(
    req: Request,
    clientId: string,
    ip: string,
  ): Promise<Response> {
    const contentType = req.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return Response.json(
        {
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32600,
            message: "Content-Type must be application/json",
          },
        },
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
        {
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        },
        { status: 400 },
      );
    }

    const id = payload.id ?? null;

    if (payload.method === "initialize") {
      return Response.json({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2025-03-26",
          capabilities: { tools: {} },
          serverInfo: { name: "JustNewMCP", version: "0.2.0" },
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
        result: { tools: TOOL_DEFINITIONS },
      });
    }

    if (payload.method === "tools/call") {
      const name = String(payload.params?.name ?? "");
      const args = (payload.params?.arguments ?? {}) as Record<string, unknown>;
      const changesWorkspace = PLAN_BLOCKED_TOOLS.has(name);
      let mutationStarted = false;

      try {
        if (changesWorkspace) {
          if (this.plan.active) {
            throw new Error(
              `Plan mode is active (read-only). Call plan_exit before using ${name}.`,
            );
          }
          this.activeWorkspaceMutations++;
          mutationStarted = true;
        }
        const result = await this.dispatchTool(name, args, ip, clientId);
        if (result === null) {
          return Response.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Unknown tool: ${name}` },
          });
        }
        this.audit.record("mcp.tool.called", ip, { clientId, detail: name });
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          },
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        this.audit.record("mcp.tool.denied", ip, {
          clientId,
          detail: `${name}: ${message}`,
        });
        return Response.json({
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [{ type: "text", text: message }],
          },
        });
      } finally {
        if (mutationStarted) this.activeWorkspaceMutations--;
      }
    }

    return Response.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: `Method not found: ${payload.method}` },
    });
  }

  private async dispatchTool(
    name: string,
    args: Record<string, unknown>,
    ip: string,
    clientId: string,
  ): Promise<unknown | null> {
    if (name === "task_create") {
      return this.tasks.create(TaskCreateArgs.parse(args));
    }

    if (name === "task_update") {
      const { id, ...changes } = TaskUpdateArgs.parse(args);
      return this.tasks.update(id, changes);
    }

    if (name === "task_list") {
      return { tasks: this.tasks.list() };
    }

    if (name === "task_get") {
      return this.tasks.get(TaskIdArgs.parse(args).id);
    }

    if (name === "plan_enter") {
      if (this.activeWorkspaceMutations > 0) {
        throw new Error(
          "Cannot enter plan mode while a workspace mutation is in progress. Try again when it finishes.",
        );
      }
      const wasActive = this.plan.active;
      const result = this.plan.enter(PlanArgs.parse(args).summary);
      if (!wasActive)
        this.audit.record("mcp.plan.entered", ip, { clientId, detail: name });
      return result;
    }

    if (name === "plan_exit") {
      const wasActive = this.plan.active;
      const result = this.plan.exit(PlanArgs.parse(args).summary);
      if (wasActive)
        this.audit.record("mcp.plan.exited", ip, { clientId, detail: name });
      return result;
    }

    if (name === "workspace_init") {
      const parsed = WorkspaceInitArgs.parse(args);
      this.readTracker.clear();
      return initializeWorkspace(
        parsed.path,
        this.config.allowedRoots,
        this.workspaceState,
        {
          deniedPatterns: this.config.deniedPathPatterns,
          memoryDir: this.config.memoryDir,
        },
      );
    }

    if (name === "workspace_info") {
      return {
        activeRoot: this.workspaceState.activeRoot,
        matchedAllowedRoot: this.workspaceState.matchedAllowedRoot,
        allowedRoots: this.config.allowedRoots,
        deniedPathPatterns: this.config.deniedPathPatterns,
      };
    }

    if (name === "read_file") {
      const root = this.requireActiveWorkspace();
      const parsed = ReadFileArgs.parse(args);
      const res = await readFileTool(
        root,
        this.config.deniedPathPatterns,
        this.readTracker,
        {
          path: parsed.path,
          offset: parsed.offset,
          limit: parsed.limit,
          humanApproved: parsed.human_approved,
        },
        {
          allowEnvReading: this.config.allowEnvReading,
          askHumanAllowance: this.config.askHumanAllowance,
        },
      );
      if (res.usedHumanApproval) {
        this.audit.record("mcp.tool.human_approved", ip, {
          clientId,
          detail: `read_file:${parsed.path}${parsed.human_approval_note ? ` (${parsed.human_approval_note})` : ""}`,
        });
      }
      return res;
    }

    if (name === "read_available_envs") {
      const root = this.requireActiveWorkspace();
      const parsed = ReadAvailableEnvsArgs.parse(args);
      return readAvailableEnvsTool(
        root,
        this.config.deniedPathPatterns,
        parsed.path,
      );
    }

    if (name === "set_env_var") {
      const root = this.requireActiveWorkspace();
      const parsed = SetEnvVarArgs.parse(args);
      return setEnvVarTool(root, this.config.deniedPathPatterns, parsed);
    }

    if (name === "edit_file") {
      const root = this.requireActiveWorkspace();
      const parsed = EditFileArgs.parse(args);
      return applyEditsTool(
        root,
        this.config.deniedPathPatterns,
        this.readTracker,
        parsed.path,
        [
          {
            old_string: parsed.old_string,
            new_string: parsed.new_string,
            replace_all: parsed.replace_all,
          },
        ],
      );
    }

    if (name === "multi_edit") {
      const root = this.requireActiveWorkspace();
      const parsed = MultiEditArgs.parse(args);
      return applyEditsTool(
        root,
        this.config.deniedPathPatterns,
        this.readTracker,
        parsed.path,
        parsed.edits,
      );
    }

    if (name === "write_file") {
      const root = this.requireActiveWorkspace();
      const parsed = WriteFileArgs.parse(args);
      return writeFileTool(
        root,
        this.config.deniedPathPatterns,
        this.readTracker,
        parsed.path,
        parsed.content,
      );
    }

    if (name === "glob_files") {
      const root = this.requireActiveWorkspace();
      const parsed = GlobFilesArgs.parse(args);
      return globFilesTool(
        root,
        this.config.deniedPathPatterns,
        parsed.pattern,
        parsed.limit,
      );
    }

    if (name === "grep_files") {
      const root = this.requireActiveWorkspace();
      const parsed = GrepFilesArgs.parse(args);
      return grepFilesTool(root, this.config.deniedPathPatterns, {
        pattern: parsed.pattern,
        glob: parsed.glob,
        caseInsensitive: parsed.case_insensitive,
        contextLines: parsed.context_lines,
        mode: parsed.mode,
        maxMatches: parsed.max_matches,
      });
    }

    if (name === "checkpoint_list") {
      const root = this.requireActiveWorkspace();
      const parsed = CheckpointListArgs.parse(args);
      return { checkpoints: listCheckpoints(root, parsed.limit) };
    }

    if (name === "checkpoint_rewind") {
      const root = this.requireActiveWorkspace();
      const parsed = CheckpointRewindArgs.parse(args);
      return rewindCheckpoint(
        root,
        parsed.checkpoint_id,
        this.config.deniedPathPatterns,
      );
    }

    if (name === "run_allowed_cmd") {
      const root = this.requireActiveWorkspace();
      const parsed = RunAllowedCmdArgs.parse(args);
      const result = await runAllowedCmdTool(
        root,
        this.config.allowedCommands,
        {
          command: parsed.command,
          args: parsed.args,
          timeoutMs: parsed.timeout_ms,
          background: parsed.background,
        },
        this.backgroundJobs,
      );
      if ("jobId" in result) {
        this.audit.record("mcp.cmd.background_started", ip, {
          clientId,
          detail: result.jobId,
        });
      }
      return result;
    }

    if (name === "cmd_status") {
      const { job_id, tail_chars } = CmdStatusArgs.parse(args);
      return job_id
        ? this.backgroundJobs.status(
            job_id,
            tail_chars,
            this.config.allowedRoots,
          )
        : { jobs: this.backgroundJobs.list() };
    }

    if (name === "task_stop") {
      const { job_id, grace_ms } = TaskStopArgs.parse(args);
      const result = await this.backgroundJobs.stop(job_id, grace_ms);
      this.audit.record("mcp.cmd.background_stopped", ip, {
        clientId,
        detail: job_id,
      });
      return result;
    }

    if (name === "memory_read") {
      const root = this.requireActiveWorkspace();
      const parsed = MemoryReadArgs.parse(args);
      return memoryReadTool(root, this.config.memoryDir, {
        ...parsed,
        deniedPatterns: this.config.deniedPathPatterns,
      });
    }

    if (name === "memory_write") {
      const root = this.requireActiveWorkspace();
      const parsed = MemoryWriteArgs.parse(args);
      return memoryWriteTool(root, this.config.memoryDir, {
        ...parsed,
        deniedPatterns: this.config.deniedPathPatterns,
      });
    }

    if (name === "memory_search") {
      const root = this.requireActiveWorkspace();
      const parsed = MemorySearchArgs.parse(args);
      return memorySearchTool(root, this.config.memoryDir, {
        pattern: parsed.pattern,
        caseInsensitive: parsed.case_insensitive,
        maxMatches: parsed.max_matches,
        deniedPatterns: this.config.deniedPathPatterns,
      });
    }

    return null;
  }
}
