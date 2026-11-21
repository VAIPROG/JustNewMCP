# JustNewMCP

[Русская версия](./docs/ru/README.md) · [Architecture](./docs/architecture.md)

A remote MCP server that turns any chat model with MCP support into a local coding agent. Built on TypeScript and Bun for Linux and Windows, with OAuth 2.1 access control and a workspace loop modeled after Claude Code.

## Why we are building this

Chat clients already support MCP, yet most local servers stop at raw file reads and writes. That leaves the model guessing paths, overwriting whole files, and working without memory or rollback. JustNewMCP puts the missing runtime into one self-hosted server: bounded workspaces, exact diffs with local checkpoints, project memory, stateful tasks, and allowlisted commands.

## Planned modules

- **OAuth 2.1 gate.** Built-in authorization server with PKCE, one-time terminal approval codes, timing-safe token checks, and IP rate limiting.
- **Workspace and checkpoints.** Root-bounded directories, line-numbered reads, unique-match edits, gitignore-aware glob and grep, and automatic pre-edit snapshots for instant rollback.
- **Project memory and plan mode.** Per-repo `MEMORY.md` index loaded on session start, server-side task tracking, and a read-only plan mode enforced in code.
- **Allowlisted execution.** No shell interpolation. Commands run as `argv` arrays via `Bun.spawn` against a user-owned allowlist, spilling logs over 30K characters to disk.
- **Phase 2.** Isolated git worktrees, background processes, on-demand tool search, LSP diagnostics, and an opt-in shell tool disabled by default.

## Status

Early development. Architecture is locked; the initial Bun runtime and OAuth 2.1 scaffold are next.

## License

MIT. See [LICENSE](./LICENSE).
