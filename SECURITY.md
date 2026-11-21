# Security policy

JustNewMCP exposes local files and allowlisted commands over HTTPS to remote MCP clients. Security bugs are treated as top priority.

## Reporting a vulnerability

Do not open a public GitHub issue for security flaws. Report them privately via GitHub Security Advisories in this repository, or email `vadim@vai-rice.space` with:

- The affected file or endpoint
- A minimal reproduction
- The expected vs actual behavior

## Security model

- **Transport.** Run behind HTTPS only. Never bind an unencrypted public port.
- **Authentication.** OAuth 2.1 with PKCE, timing-safe secret comparison, and IP rate limiting on failed attempts.
- **Filesystem boundaries.** Workspace roots are fixed in local config. Every path resolves symlinks before boundary checks.
- **Command execution.** `run_allowed_cmd` runs `argv` arrays without a shell. Any future raw shell tool stays disabled by default.
