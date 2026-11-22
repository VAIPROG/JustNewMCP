export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export type ToolModuleName =
  | "core"
  | "env"
  | "checkpoints"
  | "memory"
  | "tasks"
  | "background"
  | "worktree"
  | "lsp"
  | "shell";

export interface ToolCatalogEntry {
  definition: McpToolDefinition;
  module: ToolModuleName;
  keywords: string[];
  deferred: boolean;
}

const TOOL_MODULE_METADATA: Record<
  string,
  { module: ToolModuleName; keywords: string[]; deferred: boolean }
> = {
  workspace_init: {
    module: "core",
    keywords: ["workspace", "init", "project", "root", "git"],
    deferred: false,
  },
  workspace_info: {
    module: "core",
    keywords: ["workspace", "info", "roots", "config"],
    deferred: false,
  },
  read_file: {
    module: "core",
    keywords: ["file", "read", "view", "lines"],
    deferred: false,
  },
  edit_file: {
    module: "core",
    keywords: ["file", "edit", "replace", "patch"],
    deferred: false,
  },
  multi_edit: {
    module: "core",
    keywords: ["file", "edit", "atomic", "batch"],
    deferred: false,
  },
  write_file: {
    module: "core",
    keywords: ["file", "write", "create", "overwrite"],
    deferred: false,
  },
  glob_files: {
    module: "core",
    keywords: ["file", "glob", "find", "list", "search"],
    deferred: false,
  },
  grep_files: {
    module: "core",
    keywords: ["file", "grep", "regex", "search", "content"],
    deferred: false,
  },
  run_allowed_cmd: {
    module: "core",
    keywords: ["command", "exec", "run", "test", "build", "git", "bun"],
    deferred: false,
  },
  read_available_envs: {
    module: "env",
    keywords: ["env", "dotenv", "secrets", "variables", "keys"],
    deferred: true,
  },
  set_env_var: {
    module: "env",
    keywords: ["env", "dotenv", "set", "delete", "variables"],
    deferred: true,
  },
  checkpoint_list: {
    module: "checkpoints",
    keywords: ["checkpoint", "snapshot", "rollback", "history", "undo"],
    deferred: true,
  },
  checkpoint_rewind: {
    module: "checkpoints",
    keywords: ["checkpoint", "rewind", "restore", "rollback", "undo"],
    deferred: true,
  },
  memory_read: {
    module: "memory",
    keywords: ["memory", "notes", "read", "index", "topic"],
    deferred: true,
  },
  memory_write: {
    module: "memory",
    keywords: ["memory", "notes", "write", "append", "save"],
    deferred: true,
  },
  memory_search: {
    module: "memory",
    keywords: ["memory", "notes", "search", "grep", "find"],
    deferred: true,
  },
  task_create: {
    module: "tasks",
    keywords: ["task", "todo", "plan", "create", "tracker"],
    deferred: true,
  },
  task_update: {
    module: "tasks",
    keywords: ["task", "todo", "update", "status", "dependencies"],
    deferred: true,
  },
  task_list: {
    module: "tasks",
    keywords: ["task", "todo", "list", "tracker"],
    deferred: true,
  },
  task_get: {
    module: "tasks",
    keywords: ["task", "todo", "get", "inspect"],
    deferred: true,
  },
  plan_enter: {
    module: "tasks",
    keywords: ["plan", "readonly", "mode", "enter", "design"],
    deferred: true,
  },
  plan_exit: {
    module: "tasks",
    keywords: ["plan", "readonly", "mode", "exit", "summary"],
    deferred: true,
  },
  cmd_status: {
    module: "background",
    keywords: ["background", "job", "process", "status", "logs", "tail"],
    deferred: true,
  },
  task_stop: {
    module: "background",
    keywords: ["background", "job", "process", "stop", "kill", "terminate"],
    deferred: true,
  },
  worktree_enter: {
    module: "worktree",
    keywords: ["git", "worktree", "branch", "isolate", "enter"],
    deferred: true,
  },
  worktree_exit: {
    module: "worktree",
    keywords: ["git", "worktree", "branch", "cleanup", "exit", "remove"],
    deferred: true,
  },
  lsp_diagnostics: {
    module: "lsp",
    keywords: ["lsp", "diagnostics", "errors", "warnings", "typecheck"],
    deferred: true,
  },
  lsp_definition: {
    module: "lsp",
    keywords: ["lsp", "definition", "goto", "symbol", "navigate"],
    deferred: true,
  },
  lsp_references: {
    module: "lsp",
    keywords: ["lsp", "references", "usages", "symbol", "navigate"],
    deferred: true,
  },
  run_shell: {
    module: "shell",
    keywords: ["shell", "bash", "powershell", "terminal", "exec"],
    deferred: true,
  },
};

export const TOOL_SEARCH_DEFINITION: McpToolDefinition = {
  name: "tool_search",
  description:
    "Search and activate deferred MCP tools by keyword, module name, or 'select:tool_a,tool_b'. Call with no arguments to list available deferred modules.",
  inputSchema: {
    type: "object",
    properties: {
      query: {
        type: "string",
        description:
          "Keywords to match against tool names/descriptions, or 'select:name1,name2' for exact activation",
      },
      module: {
        type: "string",
        description:
          "Optional module name (env, checkpoints, memory, tasks, background, worktree, lsp, shell)",
      },
      limit: {
        type: "integer",
        minimum: 1,
        maximum: 30,
        default: 10,
      },
    },
  },
};

export interface ToolSearchResult {
  deferredMode: boolean;
  query?: string;
  module?: string;
  newlyActivated: string[];
  activeDeferredTools: string[];
  availableModules: Array<{
    module: ToolModuleName;
    totalTools: number;
    activeTools: number;
  }>;
  tools: McpToolDefinition[];
}

const MAX_TRACKED_SESSIONS = 200;

export class ToolRegistry {
  private readonly entries = new Map<string, ToolCatalogEntry>();
  private readonly sessions = new Map<string, Set<string>>();

  constructor(
    definitions: readonly McpToolDefinition[],
    private readonly deferredMode: boolean,
  ) {
    for (const definition of definitions) {
      const meta = TOOL_MODULE_METADATA[definition.name] ?? {
        module: "core" as ToolModuleName,
        keywords: [],
        deferred: false,
      };
      this.entries.set(definition.name, {
        definition,
        module: meta.module,
        keywords: meta.keywords,
        deferred: meta.deferred,
      });
    }
  }

  private getActivatedSet(sessionKey: string, create = false): Set<string> {
    const existing = this.sessions.get(sessionKey);
    if (existing) {
      // Refresh insertion order for LRU eviction
      this.sessions.delete(sessionKey);
      this.sessions.set(sessionKey, existing);
      return existing;
    }
    if (!create) return new Set<string>();
    const created = new Set<string>();
    this.sessions.set(sessionKey, created);
    while (this.sessions.size > MAX_TRACKED_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
    return created;
  }

  listVisibleTools(sessionKey = "default"): McpToolDefinition[] {
    if (!this.deferredMode) {
      return Array.from(this.entries.values(), (e) => e.definition);
    }
    const activated = this.getActivatedSet(sessionKey);
    const visible: McpToolDefinition[] = [];
    for (const entry of this.entries.values()) {
      if (!entry.deferred) {
        visible.push(entry.definition);
      }
    }
    visible.push(TOOL_SEARCH_DEFINITION);
    for (const name of activated) {
      const entry = this.entries.get(name);
      if (entry?.deferred) {
        visible.push(entry.definition);
      }
    }
    return visible;
  }

  isToolActive(name: string, sessionKey = "default"): boolean {
    if (name === TOOL_SEARCH_DEFINITION.name) return true;
    const entry = this.entries.get(name);
    if (!entry) return false;
    if (!this.deferredMode || !entry.deferred) return true;
    return this.getActivatedSet(sessionKey).has(name);
  }

  isKnownDeferredTool(name: string): boolean {
    return this.entries.get(name)?.deferred === true;
  }

  private summarizeModules(
    activated: Set<string>,
  ): ToolSearchResult["availableModules"] {
    const counts = new Map<
      ToolModuleName,
      { totalTools: number; activeTools: number }
    >();
    for (const entry of this.entries.values()) {
      if (!entry.deferred) continue;
      const cur = counts.get(entry.module) ?? {
        totalTools: 0,
        activeTools: 0,
      };
      cur.totalTools += 1;
      if (!this.deferredMode || activated.has(entry.definition.name)) {
        cur.activeTools += 1;
      }
      counts.set(entry.module, cur);
    }
    return Array.from(counts.entries(), ([module, stats]) => ({
      module,
      ...stats,
    }));
  }

  search(
    opts: {
      query?: string;
      module?: string;
      limit?: number;
    },
    sessionKey = "default",
  ): ToolSearchResult {
    const limit = Math.max(1, Math.min(opts.limit ?? 10, 30));
    const query = opts.query?.trim();
    const moduleFilter = opts.module?.trim().toLowerCase();
    const activated = this.getActivatedSet(sessionKey, this.deferredMode);

    if (!query && !moduleFilter) {
      return {
        deferredMode: this.deferredMode,
        newlyActivated: [],
        activeDeferredTools: [...activated],
        availableModules: this.summarizeModules(activated),
        tools: [],
      };
    }

    const candidates = Array.from(this.entries.values()).filter((entry) => {
      if (moduleFilter && entry.module !== moduleFilter) return false;
      return true;
    });

    let matched: ToolCatalogEntry[];
    if (query?.toLowerCase().startsWith("select:")) {
      const wanted = new Set(
        query
          .slice("select:".length)
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      );
      matched = candidates.filter((entry) =>
        wanted.has(entry.definition.name.toLowerCase()),
      );
    } else if (query) {
      const tokens = query
        .toLowerCase()
        .split(/[\s,]+/)
        .filter(Boolean);
      const scored: Array<{ entry: ToolCatalogEntry; score: number }> = [];
      for (const entry of candidates) {
        const nameLower = entry.definition.name.toLowerCase();
        const descLower = entry.definition.description.toLowerCase();
        const kwSet = new Set(entry.keywords);
        let score = 0;
        for (const token of tokens) {
          if (nameLower === token) score += 10;
          else if (nameLower.includes(token)) score += 6;
          if (entry.module === token) score += 5;
          if (kwSet.has(token)) score += 4;
          if (descLower.includes(token)) score += 2;
        }
        if (score > 0) {
          scored.push({ entry, score });
        }
      }
      scored.sort(
        (a, b) =>
          b.score - a.score ||
          a.entry.definition.name.localeCompare(b.entry.definition.name),
      );
      matched = scored.map((s) => s.entry);
    } else {
      matched = candidates;
    }

    const limited = matched.slice(0, limit);
    const newlyActivated: string[] = [];
    if (this.deferredMode) {
      for (const entry of limited) {
        if (entry.deferred && !activated.has(entry.definition.name)) {
          activated.add(entry.definition.name);
          newlyActivated.push(entry.definition.name);
        }
      }
    }

    return {
      deferredMode: this.deferredMode,
      ...(query ? { query } : {}),
      ...(moduleFilter ? { module: moduleFilter } : {}),
      newlyActivated,
      activeDeferredTools: [...activated],
      availableModules: this.summarizeModules(activated),
      tools: limited.map((e) => e.definition),
    };
  }
}
