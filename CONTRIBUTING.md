# Contributing

We build JustNewMCP in small, tested increments on TypeScript and Bun 1.4.0+.

## Branch naming

Name branches by goal using `<type>/<kebab-case-name>`:

- `feat/bun-oauth-scaffold`
- `bug-fix/windows-symlink-check`
- `docs/ru-architecture`
- `chore/sync-labels`

## Before you open a pull request

- Require Bun `1.4.0` or newer.
- Keep changes scoped to one module or fix.
- Run `bun test` and `bun run typecheck` and make sure all checks pass.
- Test path handling with both POSIX and Windows separators when touching filesystem or command logic.
- Follow the security model in [SECURITY.md](./SECURITY.md). Never add shell string interpolation to allowlisted command runners.

## Commit style

Use short imperative commit titles with a scope prefix, such as `feat(oauth): add PKCE verifier check` or `fix(fs): resolve symlinks before root check`.
