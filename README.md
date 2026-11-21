# JustNewMCP

[Русская версия](./docs/ru/README.md) · [Architecture](./docs/architecture.md)

A remote MCP server that turns any chat model with MCP support into a local coding agent. Built on TypeScript and Bun 1.4+ for Linux and Windows, with OAuth 2.1 access control and a workspace loop modeled after Claude Code.

## Why we are building this

Chat clients already support MCP, yet most local servers stop at raw file reads and writes. That leaves the model guessing paths, overwriting whole files, and working without memory or rollback. JustNewMCP puts the missing runtime into one self-hosted server: bounded workspaces, exact diffs with local checkpoints, project memory, stateful tasks, and allowlisted commands.

## Status

### Ready on `main`

- **OAuth 2.1 gate.** Built-in authorization server (`/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`) with PKCE S256, stateless `Bun.CSRF` tokens, exact callback URI matching, one-time terminal approval codes, SHA-256 hashed token storage, and trusted-proxy IP rate limiting.
- **Workspace bootstrap and memory index.** `workspace_init` and `workspace_info` with cross-platform root anchoring, symlink escape checks, `core.fsmonitor=false` git status, and bounded 25 KiB `MEMORY.md` preview loading from `.justnewmcp/memory/` or a centralized `memoryDir`.
- **Files, search, and checkpoints.** `read_file` with line numbers and UTF-8/binary guards, `edit_file` with read-before-edit enforcement, atomic `multi_edit`, `write_file`, `.gitignore`-aware `glob_files` and `grep_files`, plus `checkpoint_list` and `checkpoint_rewind` with `0700`/`0600` POSIX permissions.
- **Safe `.env` workflow.** Safe templates like `.env.example` stay readable by default. Real `.env` files stay protected behind `read_available_envs` (names and value lengths only), `set_env_var` (multiline-aware dotenv updates with checkpoints), `allowEnvReading`, and `askHumanAllowance`.

### In progress (Phase 1)

- **Allowlisted command execution.** `run_allowed_cmd` via `Bun.spawn` (`argv` array, no shell) with per-command rules, timeouts, and disk spilling for logs over 30K characters.
- **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, `task_get`, and read-only `plan_enter` / `plan_exit`.
- **Project memory write tools.** `memory_read`, `memory_write`, and `memory_search` over topic directories.
- **CI security automation.** CodeQL, Gitleaks, `bun audit`, and Dependabot.

### Planned (Phase 2)

- Isolated git worktrees, background processes with `task_stop`, on-demand `tool_search`, LSP diagnostics, and an opt-in shell tool disabled by default.

## License

MIT. See [LICENSE](./LICENSE).
