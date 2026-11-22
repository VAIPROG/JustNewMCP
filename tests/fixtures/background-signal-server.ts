import { basename } from "node:path";
import { ConfigSchema } from "../../src/config.ts";
import {
  createAppServer,
  installShutdownSignalHandlers,
} from "../../src/index.ts";

const [workspace, script, marker] = process.argv.slice(2);
if (!workspace || !script || !marker || !process.send) {
  throw new Error(
    "Expected a workspace, a command fixture, and a parent IPC channel.",
  );
}

const command = basename(process.execPath);
const running = createAppServer(
  ConfigSchema.parse({
    port: 0,
    publicUrl: "http://127.0.0.1",
    allowedRoots: [workspace],
    allowedCommands: [{ command, allowedSubcommands: ["-e"] }],
    oauth: {
      clientId: "shutdown-fixture",
      clientSecret: crypto.randomUUID(),
    },
  }),
);
installShutdownSignalHandlers(running.shutdown);

async function call(
  name: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const request = new Request("http://127.0.0.1/mcp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
  const response = await running.mcp.handleRequest(
    request,
    "shutdown-fixture",
    "127.0.0.1",
  );
  const { result } = (await response.json()) as {
    result?: { isError?: boolean; content: Array<{ text: string }> };
  };
  const text = result?.content[0]?.text;
  if (!response.ok || !text || result?.isError) {
    throw new Error(`Fixture tool ${name} failed: ${text ?? response.status}`);
  }
  return JSON.parse(text);
}

await call("workspace_init", { path: workspace });
const job = await call("run_allowed_cmd", {
  command,
  args: ["-e", script, marker],
  background: true,
});
process.send(job);
