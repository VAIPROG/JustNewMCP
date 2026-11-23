# JustNewMCP

[Русская версия](./docs/ru/README.md) · [Architecture](./docs/architecture.md) · [Setup Guides](./docs/guides.md)

A remote MCP server that turns any chat model with MCP support into a local coding agent. Built on TypeScript and Bun 1.4+ for Linux and Windows, with OAuth 2.1 access control and a workspace loop modeled after Claude Code.

## Why we are building this

Chat clients already support MCP, yet most local servers stop at raw file reads and writes. That leaves the model guessing paths, overwriting whole files, and working without memory or rollback. JustNewMCP puts the missing runtime into one self-hosted server: bounded workspaces, exact diffs with local checkpoints, project memory, stateful tasks, git worktrees, background jobs, LSP diagnostics, and on-demand tool discovery.

## Status

Release `v0.1.0` brings Phase 1 and Phase 2 together on `main` with 71 tests passing across Linux and Windows CI and 0 open Code Scanning alerts.

### Ready on `main`

- **OAuth 2.1 gate.** Built-in authorization server at `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token`, and `/oauth/revoke` with PKCE S256, RFC 9207 `iss` responses for Gemini and OpenAI ChatGPT, stateless `Bun.CSRF` tokens, exact callback URI matching, per-instance `0600` approval-code files outside `allowedRoots`, toggleable `inMemoryTokens` vs `0600` persisted SHA-256 token hashes, and trusted-proxy IP rate limiting.
- **Workspace bootstrap and git worktrees.** `workspace_init` and `workspace_info` with cross-platform root anchoring, symlink escape checks, `core.fsmonitor=false` git status, and bounded 25 KiB `MEMORY.md` preview loading, plus `worktree_enter` and `worktree_exit` for isolated branches under `.justnewmcp/worktrees/` with repository hooks and external filter drivers disabled.
- **Files, search, and checkpoints.** `read_file` with line numbers and UTF-8/binary guards, `edit_file` with read-before-edit enforcement, atomic `multi_edit`, `write_file`, `.gitignore`-aware `glob_files` and `grep_files`, plus `checkpoint_list` and `checkpoint_rewind` with `0700`/`0600` POSIX permissions.
- **Safe `.env` workflow.** Safe templates like `.env.example` stay readable by default. Real `.env` files stay protected behind `read_available_envs` returning only names and value lengths, `set_env_var` with multiline-aware dotenv updates and checkpoints, `allowEnvReading`, and `askHumanAllowance`.
- **Allowlisted commands, background jobs, and opt-in shell.** `run_allowed_cmd` spawns bare executables directly via `Bun.spawn` with `argv` arrays and no shell, supports `background: true` with `cmd_status` bounded log tails and `task_stop` process-group termination, strips `JUSTNEWMCP_*` variables, and spills outputs over 30K characters to `.justnewmcp/logs/` with `0600` POSIX permissions. An explicit opt-in `run_shell` tool for Bash or PowerShell stays hidden and disabled unless `allowShell: true` is set.
- **Tasks and plan mode.** Server-side `task_create`, `task_update`, `task_list`, and `task_get` with dependency cycle checks and a 500-task cap, plus `plan_enter` and `plan_exit` that enforce read-only access in code while active.
- **Project memory tools.** `memory_read`, `memory_write`, and `memory_search` over `MEMORY.md` and nested topic folders with `deniedPathPatterns` enforcement, single-fd atomic writes, and a per-target write lock queue for concurrent appends.
- **LSP code intelligence.** `lsp_diagnostics`, `lsp_definition`, and `lsp_references` over configured stdio language servers with byte-accurate UTF-8 `Content-Length` framing, push and pull diagnostics, URI boundary filtering, idle shutdown, and crash recovery.
- **On-demand `tool_search`.** Optional `deferredTools: true` mode exposing compact core tools plus `tool_search` upfront, tracking activations per `Mcp-Session-Id`, and emitting `notifications/tools/list_changed` over Streamable HTTP SSE when new tools activate.
- **CI and security checks.** Ubuntu and Windows CI running `bun fmt --check`, `bun check`, and `bun test --check`, alongside CodeQL, Semgrep OSS, Gitleaks, OSV-Scanner, `bun audit`, Dependency Review, `actionlint` + `zizmor`, and Dependabot.

## Quick start

Copy `config.example.json` to `config.json`, set `allowedRoots`, `publicUrl`, and a random 32-byte `oauth.clientSecret`, then start the server:

```bash
bun install
JUSTNEWMCP_CONFIG=./config.json bun run start
```

## License

MIT. See [LICENSE](./LICENSE).
