# Setup and Client Connection Guides

This guide walks through configuring JustNewMCP, exposing it safely over HTTPS, and connecting Google Gemini or OpenAI ChatGPT.

## 1. Local configuration

1. Install dependencies with Bun 1.4 or newer:

   ```bash
   bun install
   ```

2. Copy `config.example.json` to `config.json` and update:
   - `publicUrl`: the public HTTPS URL of your tunnel or reverse proxy, with no trailing slash.
   - `allowedRoots`: absolute paths to directories the agent may access.
   - `oauth.clientId` and `oauth.clientSecret`: pick a client ID and generate a 32-byte random secret.
   - `oauth.inMemoryTokens`: `false` by default so SHA-256 token hashes persist across server restarts in `~/.justnewmcp/oauth-tokens-<hash>.json` with `0600` POSIX permissions. Set to `true`, or pass `JUSTNEWMCP_IN_MEMORY_TOKENS=true`, to keep tokens strictly in RAM.
   - `oauth.tokenStorePath`: optional custom path outside `allowedRoots` for the hashed token store, also configurable via `JUSTNEWMCP_TOKEN_STORE_PATH`.

3. Start the server:

   Linux or macOS:

   ```bash
   JUSTNEWMCP_CONFIG=./config.json bun run start
   ```

   Windows PowerShell:

   ```powershell
   $env:JUSTNEWMCP_CONFIG = "./config.json"
   bun run start
   ```

When the server starts, it writes a one-time approval code to `~/.justnewmcp/approval-code-<port>-<pid>` with `0600` permissions. The path is printed once at startup; the code itself is never printed to stdout.

## 2. Expose over HTTPS with Cloudflare Tunnel

For quick testing without opening firewall ports:

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

Copy the generated `https://*.trycloudflare.com` URL into `publicUrl` in `config.json`, restart JustNewMCP, and open that URL in a browser to verify the landing page loads.

Keep `trustedProxies` set to `["127.0.0.1", "::1"]` when `cloudflared` runs on the same machine so rate limiting sees the real client IP via `CF-Connecting-IP`.

## 3. Connect from Google Gemini

`DEFAULT_ALLOWED_REDIRECT_URIS` already includes `https://gemini.google.com/`, `https://aistudio.google.com/`, and `https://oauth-redirect.googleusercontent.com/`.

1. Add a custom remote MCP server in Gemini with URL `https://<your-public-url>/mcp`.
2. Enter your configured `oauth.clientId` and `oauth.clientSecret`.
3. Complete the OAuth flow in the browser by entering the current approval code from `~/.justnewmcp/approval-code-<port>-<pid>`.
4. After approval, the code rotates immediately and your hashed access and refresh tokens are saved if `inMemoryTokens` is `false`.

## 4. Connect from OpenAI ChatGPT

`DEFAULT_ALLOWED_REDIRECT_URIS` includes `https://chatgpt.com/` and `https://platform.openai.com/`, and `/.well-known/oauth-authorization-server` advertises RFC 9207 issuer identification via `authorization_response_iss_parameter_supported: true` with an `iss` parameter on every authorization callback. That lets ChatGPT use its stable redirect URI `https://chatgpt.com/connector_platform_oauth_redirect` alongside its per-callback fallback `https://chatgpt.com/connector/oauth/<callback_id>`.

1. In ChatGPT MCP connector settings, set the server URL to `https://<your-public-url>/mcp`.
2. Choose OAuth authentication and enter your configured `oauth.clientId` and `oauth.clientSecret`.
3. Approve the authorization prompt with your local approval code.

Reference: [OpenAI MCP Authentication Guide](https://developers.openai.com/plugins/build/auth).

## 5. Security tuning tips

- Keep `allowEnvReading` and `allowShell` set to `false` unless you actively need them.
- Restrict `allowedCommands` to specific subcommands and `deniedArgs`, such as blocking `git -c` or `--exec-path*`.
- Set `oauth.inMemoryTokens` to `true` on shared or temporary machines where you want every restart to force a fresh OAuth approval.
- Never place `oauth.tokenStorePath` or the approval-code file inside `allowedRoots`; the server rejects configurations that violate this boundary.
