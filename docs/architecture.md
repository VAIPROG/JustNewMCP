# Architecture

JustNewMCP is a cross-platform MCP server written in TypeScript for Bun, targeting Linux and Windows out of the box. It exposes a Streamable HTTP endpoint at `/mcp` behind OAuth 2.1.

## Authentication and transport

- **Endpoint.** Streamable HTTP at `https://<host>/mcp`.
- **OAuth 2.1.** Built-in discovery at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, plus `/oauth/authorize` and `/oauth/token` with PKCE.
- **Brute-force protection.** Secrets and tokens compare with `crypto.timingSafeEqual`, backed by per-IP rate limiting and one-time approval codes printed only in the local terminal.

## Core modules

1. **Workspace and isolation.** `workspace_init` switches inside config-approved roots after `path.resolve` and `fs.realpath` checks, loading `AGENTS.md` or `CLAUDE.md`, `git status`, and the project memory index. Phase 2 adds `worktree_enter` and `worktree_exit`.
2. **Files and checkpoints.** `read` with line numbers and ranges, `edit` with read-before-edit and unique-match checks, `write`, `glob`, and `grep` respecting `.gitignore`. Every mutating file call saves a pre-edit snapshot for `checkpoint_list` and `checkpoint_rewind`.
3. **Project memory.** `memory_read`, `memory_write`, and `memory_search` backed by a per-project `MEMORY.md` index capped at 200 lines or 25 KB on session start.
4. **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, and `task_get`, plus `plan_enter` and `plan_exit` that enforce read-only access in code while active.
5. **Allowlisted execution.** `run_allowed_cmd` validates binary name and `argv` patterns from local config and spawns processes via `Bun.spawn` with no shell. Outputs over 30K characters spill to a temp file and return a 2K preview plus file path.
6. **On-demand tool search.** Phase 2 exposes core tools plus `tool_search` upfront and activates extended modules on demand.
7. **Code intelligence.** Phase 2 adds an `lsp` module for definitions, references, and post-edit diagnostics.

## Delivery phases

- **Phase 1.** OAuth 2.1, `workspace_init`, file tools with checkpoints, project memory, task tracker, plan mode, and `run_allowed_cmd` with log spilling.
- **Phase 2.** Git worktrees, background processes with `task_stop`, `tool_search`, LSP diagnostics, and an opt-in Bash or PowerShell tool disabled by default.
