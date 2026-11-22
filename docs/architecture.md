# Architecture

JustNewMCP is a cross-platform MCP server written in TypeScript for Bun 1.4+, targeting Linux and Windows out of the box. It exposes a Streamable HTTP endpoint at `/mcp` behind OAuth 2.1.

## Authentication and transport

- **Endpoint.** Streamable HTTP at `https://<host>/mcp`.
- **OAuth 2.1.** Built-in discovery at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`, plus `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` with PKCE S256 and stateless `Bun.CSRF` protection.
- **Brute-force protection.** Secrets and tokens compare with `crypto.timingSafeEqual`, backed by trusted-proxy IP rate limiting and one-time approval codes written to a per-instance `0600` file outside `allowedRoots` rather than printed to stdout.

## Core modules

1. **Workspace and isolation.** `workspace_init` switches inside config-approved roots after `path.resolve` and `fs.realpath` checks, loading `AGENTS.md` or `CLAUDE.md`, `git status` with `core.fsmonitor=false`, and the project memory index. Phase 2 adds `worktree_enter` and `worktree_exit` in [#12](https://github.com/VAIPROG/JustNewMCP/issues/12).
2. **Files and checkpoints.** `read_file` with line numbers and UTF-8/binary checks, `edit_file` with read-before-edit and unique-match checks, atomic `multi_edit`, `write_file`, `glob_files`, and `grep_files` respecting `.gitignore` and `deniedPathPatterns`. Every mutating file call saves a pre-edit snapshot in `.justnewmcp/checkpoints/` for `checkpoint_list` and `checkpoint_rewind`.
3. **Project memory.** `memory_read`, `memory_write`, and `memory_search` backed by a compact `MEMORY.md` index capped at 25 KiB and 200 lines on preview, linking to topic folders like `how-to-use-user-machine/INDEX.md`. Stored either in `<workspace>/.justnewmcp/memory/` or under a configured `memoryDir/<normalized-workspace-slug>/` such as `c--users--vaiprog--somecoolproject--<hash>`. Writes enforce `deniedPathPatterns`, run synchronously on a single `O_NOFOLLOW` descriptor, and serialize concurrent appends per target path.
4. **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, and `task_get`, plus `plan_enter` and `plan_exit` that enforce read-only access in code while active.
5. **Allowlisted execution.** `run_allowed_cmd` validates bare executable names and `argv` patterns from local config and spawns processes via `Bun.spawn` with no shell. Outputs over 30K characters spill to `.justnewmcp/logs/` with `0600` POSIX permissions and return a 2K preview plus file path. Phase 2 adds background jobs with `task_stop` in [#13](https://github.com/VAIPROG/JustNewMCP/issues/13) and an opt-in shell tool disabled by default in [#16](https://github.com/VAIPROG/JustNewMCP/issues/16).
6. **On-demand tool search.** Phase 2 exposes core tools plus `tool_search` upfront and activates extended modules on demand in [#14](https://github.com/VAIPROG/JustNewMCP/issues/14).
7. **Code intelligence.** Phase 2 adds an `lsp` module for definitions, references, and post-edit diagnostics in [#15](https://github.com/VAIPROG/JustNewMCP/issues/15).

## Delivery phases

- **Phase 1, complete on `main`.** OAuth 2.1, `workspace_init`, file tools with checkpoints, `.env` workflow, `memory_read`/`memory_write`/`memory_search`, task tracker, plan mode, `run_allowed_cmd` with 30K log spilling, and CI security automation.
- **Phase 2, in progress.** Git worktrees in [#12](https://github.com/VAIPROG/JustNewMCP/issues/12), background processes with `task_stop` in [#13](https://github.com/VAIPROG/JustNewMCP/issues/13), `tool_search` in [#14](https://github.com/VAIPROG/JustNewMCP/issues/14), LSP diagnostics in [#15](https://github.com/VAIPROG/JustNewMCP/issues/15), and an opt-in Bash or PowerShell tool disabled by default in [#16](https://github.com/VAIPROG/JustNewMCP/issues/16).
