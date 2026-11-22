# Architecture

JustNewMCP is a cross-platform MCP server written in TypeScript for Bun 1.4+, targeting Linux and Windows out of the box. It exposes a Streamable HTTP endpoint at `/mcp` behind OAuth 2.1.

## Authentication and transport

- **Endpoint.** Streamable HTTP at `https://<host>/mcp` with per-session `Mcp-Session-Id` headers and SSE `notifications/tools/list_changed` support.
- **OAuth 2.1.** Built-in discovery at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, plus `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` with PKCE S256 and stateless `Bun.CSRF` protection.
- **Brute-force protection.** Secrets and tokens compare with `crypto.timingSafeEqual`, backed by trusted-proxy IP rate limiting and one-time approval codes written to a per-instance `0600` file outside `allowedRoots` rather than printed to stdout.

## Core modules

1. **Workspace and git worktrees.** `workspace_init` switches inside config-approved roots after `path.resolve` and `fs.realpath` checks, loading `AGENTS.md` or `CLAUDE.md`, `git status` with `core.fsmonitor=false`, and the project memory index. `worktree_enter` and `worktree_exit` create, reattach, keep, or remove isolated worktrees under `.justnewmcp/worktrees/` with repository hooks and external filter drivers disabled.
2. **Files and checkpoints.** `read_file` with line numbers and UTF-8/binary checks, `edit_file` with read-before-edit and unique-match checks, atomic `multi_edit`, `write_file`, `glob_files`, and `grep_files` respecting `.gitignore` and `deniedPathPatterns`. Every mutating file call saves a pre-edit snapshot in `.justnewmcp/checkpoints/` for `checkpoint_list` and `checkpoint_rewind`.
3. **Project memory.** `memory_read`, `memory_write`, and `memory_search` backed by a compact `MEMORY.md` index capped at 25 KiB and 200 lines on preview, linking to topic folders like `how-to-use-user-machine/INDEX.md`. Stored either in `<workspace>/.justnewmcp/memory/` or under a configured `memoryDir/<normalized-workspace-slug>/` such as `c--users--vaiprog--somecoolproject--<hash>`. Writes enforce `deniedPathPatterns`, run synchronously on a single `O_NOFOLLOW` descriptor, and serialize concurrent appends per target path.
4. **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, and `task_get`, plus `plan_enter` and `plan_exit` that enforce read-only access in code while active.
5. **Allowlisted execution, background jobs, and opt-in shell.** `run_allowed_cmd` validates bare executable names and `argv` patterns from local config and spawns processes via `Bun.spawn` with no shell. Outputs over 30K characters spill to `.justnewmcp/logs/` with `0600` POSIX permissions and return a 2K preview plus file path. Passing `background: true` registers a managed job inspected via `cmd_status` and terminated via `task_stop` or server shutdown. An optional `run_shell` tool for Bash or PowerShell remains hidden and disabled unless `allowShell: true` is configured.
6. **Code intelligence.** `src/workspace/lsp.ts` and `src/workspace/lsp-protocol.ts` manage configured stdio language servers with byte-accurate UTF-8 `Content-Length` framing, push and pull diagnostics, URI boundary filtering, idle teardown, and crash recovery behind `lsp_diagnostics`, `lsp_definition`, and `lsp_references`.
7. **On-demand tool search.** `src/mcp/tool-registry.ts` partitions tools into compact core tools and deferred modules when `deferredTools: true` is enabled, activating matched tools per `Mcp-Session-Id` via `tool_search` and emitting `notifications/tools/list_changed` over SSE.

## Delivery status

- **Phase 1, complete on `main`.** OAuth 2.1, `workspace_init`, file tools with checkpoints, `.env` workflow, `memory_read`/`memory_write`/`memory_search`, task tracker, plan mode, `run_allowed_cmd` with 30K log spilling, and CI security automation.
- **Phase 2, complete on `main`.** Git worktrees in [#12](https://github.com/VAIPROG/JustNewMCP/issues/12), background processes with `task_stop` in [#13](https://github.com/VAIPROG/JustNewMCP/issues/13), `tool_search` in [#14](https://github.com/VAIPROG/JustNewMCP/issues/14), LSP diagnostics in [#15](https://github.com/VAIPROG/JustNewMCP/issues/15), and opt-in `run_shell` disabled by default in [#16](https://github.com/VAIPROG/JustNewMCP/issues/16).
