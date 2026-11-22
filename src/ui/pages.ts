const REPO_URL = "https://github.com/VAIPROG/JustNewMCP";

const BASE_CSS = `
:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-subtle: #f1f3f6;
  --border: #e2e6ec;
  --text: #111827;
  --muted: #525d70;
  --accent: #18181b;
  --accent-hover: #27272a;
  --accent-fg: #ffffff;
  --link: #2563eb;
  --badge-bg: #eef2ff;
  --badge-text: #3730a3;
  --error-bg: #fef2f2;
  --error-border: #fecaca;
  --error-text: #991b1b;
  --shadow: 0 10px 30px rgba(15, 23, 42, 0.06), 0 1px 3px rgba(15, 23, 42, 0.04);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0b0d12;
    --surface: #131722;
    --surface-subtle: #1a2030;
    --border: #262f42;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --accent: #f3f4f6;
    --accent-hover: #e5e7eb;
    --accent-fg: #0b0d12;
    --link: #60a5fa;
    --badge-bg: #1e293b;
    --badge-text: #93c5fd;
    --error-bg: #2a1215;
    --error-border: #7f1d1d;
    --error-text: #fca5a5;
    --shadow: 0 14px 36px rgba(0, 0, 0, 0.45), 0 1px 3px rgba(0, 0, 0, 0.3);
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
.card {
  width: 100%;
  max-width: 460px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 28px;
  box-shadow: var(--shadow);
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 14px;
}
.brand {
  font-size: 14px;
  font-weight: 700;
  letter-spacing: -0.01em;
}
.badge {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 9px;
  border-radius: 999px;
  background: var(--badge-bg);
  color: var(--badge-text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
h1 {
  margin: 0 0 8px;
  font-size: 22px;
  line-height: 1.25;
  letter-spacing: -0.02em;
}
.lead {
  margin: 0 0 20px;
  font-size: 14px;
  color: var(--muted);
}
.meta {
  display: grid;
  gap: 8px;
  padding: 14px;
  margin: 0 0 20px;
  border-radius: 10px;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  font-size: 13px;
}
.meta-row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 12px;
}
.meta-label { color: var(--muted); flex-shrink: 0; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1px 6px;
  word-break: break-all;
}
.meta code {
  background: transparent;
  border: 0;
  padding: 0;
  text-align: right;
}
.alert {
  margin: 0 0 16px;
  padding: 12px 14px;
  border-radius: 10px;
  background: var(--error-bg);
  border: 1px solid var(--error-border);
  color: var(--error-text);
  font-size: 13.5px;
  font-weight: 500;
}
label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 6px;
}
input[type="text"], input:not([type]) {
  width: 100%;
  padding: 11px 12px;
  border-radius: 9px;
  border: 1px solid var(--border);
  background: var(--bg);
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 15px;
  letter-spacing: 0.06em;
  outline: none;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
input[type="text"]:focus, input:not([type]):focus {
  border-color: var(--link);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.18);
}
input[aria-invalid="true"] {
  border-color: var(--error-text);
}
.hint {
  margin: 8px 0 18px;
  font-size: 12.5px;
  color: var(--muted);
}
button {
  width: 100%;
  padding: 11px 16px;
  border: 0;
  border-radius: 9px;
  background: var(--accent);
  color: var(--accent-fg);
  font-size: 14.5px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.15s ease, opacity 0.15s ease;
}
button:hover { background: var(--accent-hover); }
button:disabled { opacity: 0.55; cursor: not-allowed; }
.steps {
  margin: 0 0 20px;
  padding: 16px 16px 16px 32px;
  border-radius: 10px;
  background: var(--surface-subtle);
  border: 1px solid var(--border);
  font-size: 13.5px;
}
.steps li { margin-bottom: 10px; }
.steps li:last-child { margin-bottom: 0; }
.section-title {
  margin: 0 0 10px;
  font-size: 13px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted);
}
.footer {
  margin-top: 20px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  font-size: 12.5px;
  color: var(--muted);
}
a {
  color: var(--link);
  text-decoration: none;
  font-weight: 500;
}
a:hover { text-decoration: underline; }
`;

export interface AuthorizePageParams {
  clientId: string;
  scope: string;
  redirectUri: string;
  redirectOrigin: string;
  codeChallenge: string;
  state: string;
  csrfToken: string;
  errorMessage?: string;
  locked?: boolean;
}

export function renderAuthorizePage(params: AuthorizePageParams): string {
  const errorBanner = params.errorMessage
    ? `<div class="alert" role="alert">${Bun.escapeHTML(params.errorMessage)}</div>`
    : "";
  const invalidAttr = params.errorMessage ? ' aria-invalid="true"' : "";
  const disabledAttr = params.locked ? " disabled" : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize JustNewMCP</title>
  <style>${BASE_CSS}</style>
</head>
<body>
  <main class="card">
    <div class="header">
      <span class="brand">JustNewMCP</span>
      <span class="badge">OAuth 2.1</span>
    </div>
    <h1>Approve MCP access</h1>
    <p class="lead">You opened the authorization gate for your local JustNewMCP server. Confirm access with the one-time approval code from your machine.</p>
    <div class="meta">
      <div class="meta-row"><span class="meta-label">Client</span><code>${Bun.escapeHTML(params.clientId)}</code></div>
      <div class="meta-row"><span class="meta-label">Scope</span><code>${Bun.escapeHTML(params.scope)}</code></div>
      <div class="meta-row"><span class="meta-label">Callback</span><code>${Bun.escapeHTML(params.redirectOrigin)}</code></div>
    </div>
    ${errorBanner}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="csrf_token" value="${Bun.escapeHTML(params.csrfToken)}" />
      <input type="hidden" name="client_id" value="${Bun.escapeHTML(params.clientId)}" />
      <input type="hidden" name="redirect_uri" value="${Bun.escapeHTML(params.redirectUri)}" />
      <input type="hidden" name="code_challenge" value="${Bun.escapeHTML(params.codeChallenge)}" />
      <input type="hidden" name="state" value="${Bun.escapeHTML(params.state)}" />
      <input type="hidden" name="scope" value="${Bun.escapeHTML(params.scope)}" />
      <label for="approval_code">One-time approval code</label>
      <input id="approval_code" type="text" name="approval_code" placeholder="XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false" autofocus required${invalidAttr} />
      <p class="hint">Stored locally in <code>~/.justnewmcp/approval-code-&lt;port&gt;-&lt;pid&gt;</code> (mode 0600).</p>
      <button type="submit"${disabledAttr}>Approve connection</button>
    </form>
    <div class="footer">
      <span>Local coding agent bridge</span>
      <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer">Source on GitHub</a>
    </div>
  </main>
</body>
</html>`;
}

export function renderLandingPage(publicUrl: string): string {
  const mcpEndpoint = `${publicUrl.replace(/\/+$/, "")}/mcp`;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>JustNewMCP Server</title>
  <style>${BASE_CSS}</style>
</head>
<body>
  <main class="card">
    <div class="header">
      <span class="brand">JustNewMCP</span>
      <span class="badge">MCP / OAuth 2.1</span>
    </div>
    <h1>Local MCP server is running</h1>
    <p class="lead">This endpoint hosts a self-hosted Model Context Protocol server behind OAuth 2.1. It is meant for MCP-compatible chat clients rather than direct browsing.</p>
    <p class="section-title">Owner quick connect</p>
    <ol class="steps">
      <li>Add <code>${Bun.escapeHTML(mcpEndpoint)}</code> as a custom MCP server in your chat client.</li>
      <li>Enter your <code>clientId</code> and <code>clientSecret</code> from local <code>config.json</code>. OAuth discovery is published at <code>/.well-known/oauth-authorization-server</code>.</li>
      <li>Approve the browser prompt using the one-time code from <code>~/.justnewmcp/approval-code-&lt;port&gt;-&lt;pid&gt;</code>.</li>
    </ol>
    <div class="footer">
      <span>Streamable HTTP at <code>/mcp</code></span>
      <a href="${REPO_URL}" target="_blank" rel="noopener noreferrer">GitHub repository</a>
    </div>
  </main>
</body>
</html>`;
}
