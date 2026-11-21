# Contributing

We build JustNewMCP in small, tested increments on TypeScript and Bun.

## Before you open a pull request

- Keep changes scoped to one module or fix.
- Run `bun test` and make sure all checks pass on your branch.
- Test path handling with both POSIX and Windows separators when touching filesystem or command logic.
- Follow the security model in [SECURITY.md](./SECURITY.md). Never add shell string interpolation to allowlisted command runners.

## Commit style

Use short imperative commit titles with a scope prefix, such as `feat(oauth): add PKCE verifier check` or `fix(fs): resolve symlinks before root check`.
