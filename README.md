# JustNewMCP

[Русская версия](./docs/ru/README.md) · [Architecture](./docs/architecture.md)

A remote MCP server that turns any chat model with MCP support into a local coding agent. Built on TypeScript and Bun 1.4+ for Linux and Windows, with OAuth 2.1 access control and a workspace loop modeled after Claude Code.

## Why we are building this

Chat clients already support MCP, yet most local servers stop at raw file reads and writes. That leaves the model guessing paths, overwriting whole files, and working without memory or rollback. JustNewMCP puts the missing runtime into one self-hosted server: bounded workspaces, exact diffs with local checkpoints, project memory, stateful tasks, and allowlisted commands.

## Status

Phase 1 is complete on `main` with 43 tests passing across Linux and Windows CI and 0 open Code Scanning alerts. Active development is now moving to Phase 2.

### Ready on `main`

- **OAuth 2.1 gate.** Built-in authorization server at `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` with PKCE S256, stateless `Bun.CSRF` tokens, exact callback URI matching, per-instance `0600` approval-code files outside `allowedRoots`, SHA-256 hashed token storage, and trusted-proxy IP rate limiting.
- **Workspace bootstrap and memory index.** `workspace_init` and `workspace_info` with cross-platform root anchoring, symlink escape checks, `core.fsmonitor=false` git status, and bounded 25 KiB `MEMORY.md` preview loading from `.justnewmcp/memory/` or a centralized `memoryDir`.
- **Files, search, and checkpoints.** `read_file` with line numbers and UTF-8/binary guards, `edit_file` with read-before-edit enforcement, atomic `multi_edit`, `write_file`, `.gitignore`-aware `glob_files` and `grep_files`, plus `checkpoint_list` and `checkpoint_rewind` with `0700`/`0600` POSIX permissions.
- **Safe `.env` workflow.** Safe templates like `.env.example` stay readable by default. Real `.env` files stay protected behind `read_available_envs` returning only names and value lengths, `set_env_var` with multiline-aware dotenv updates and checkpoints, `allowEnvReading`, and `askHumanAllowance`.
- **Allowlisted command execution.** `run_allowed_cmd` spawns bare executables directly via `Bun.spawn` with `argv` arrays and no shell, enforces per-command rules and timeouts with `SIGTERM` to `SIGKILL` escalation, strips `JUSTNEWMCP_*` variables, and spills output over 30K characters to `.justnewmcp/logs/` with `0600` POSIX permissions.
- **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, and `task_get` with dependency cycle checks and a 500-task cap, plus `plan_enter` and `plan_exit` that enforce read-only access in code while active.
- **Project memory tools.** `memory_read`, `memory_write`, and `memory_search` over `MEMORY.md` and nested topic folders with `deniedPathPatterns` enforcement, single-fd atomic writes, and a per-target write lock queue for concurrent appends.
- **CI and security checks.** Ubuntu and Windows CI running `bun fmt --check`, `bun check`, and `bun test --check`, alongside CodeQL, Semgrep OSS, Gitleaks, OSV-Scanner, `bun audit`, Dependency Review, `actionlint` + `zizmor`, and Dependabot.

### In progress and planned for Phase 2

- **Git worktree isolation** in [#12](https://github.com/VAIPROG/JustNewMCP/issues/12). `worktree_enter` and `worktree_exit` for isolated branches inside approved roots.
- **Background jobs and `task_stop`** in [#13](https://github.com/VAIPROG/JustNewMCP/issues/13). Background mode for `run_allowed_cmd`, bounded log streaming, and clean process termination.
- **On-demand `tool_search`** in [#14](https://github.com/VAIPROG/JustNewMCP/issues/14). Compact initial `tools/list` with session-scoped activation of extended modules.
- **LSP code intelligence** in [#15](https://github.com/VAIPROG/JustNewMCP/issues/15). `lsp_diagnostics`, `lsp_definition`, and `lsp_references` over stdio language servers.
- **Opt-in local shell** in [#16](https://github.com/VAIPROG/JustNewMCP/issues/16). Explicit opt-in `run_shell` tool for Bash or PowerShell, disabled by default.

## License

MIT. See [LICENSE](./LICENSE).
