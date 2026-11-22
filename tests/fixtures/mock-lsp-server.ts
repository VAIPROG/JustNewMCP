import { appendFileSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [marker, mode, outside = ""] = process.argv.slice(2);
if (marker !== "justnewmcp-mock-lsp" || !outside)
  throw new Error("Invalid mock LSP arguments.");
if (process.env.JUSTNEWMCP_LSP_TEST)
  throw new Error("LSP received a private environment variable.");

type Message = {
  jsonrpc: string;
  id?: number | string;
  method?: string;
  result?: unknown;
  params?: {
    rootUri?: string;
    capabilities?: { general?: { positionEncodings?: string[] } };
    textDocument?: { uri: string; text?: string; version?: number };
    position?: { line: number; character: number };
    context?: { includeDeclaration?: boolean };
    contentChanges?: Array<{ text: string; range?: unknown }>;
    previousResultId?: string;
  };
};

const root = process.cwd();
const uri = (path: string) => pathToFileURL(resolve(root, path)).href;
const traceFile = join(root, "lsp-trace.jsonl");
const trace = (event: string, details?: unknown) => {
  appendFileSync(
    traceFile,
    JSON.stringify({ event, pid: process.pid, details }) + "\n",
  );
};

let outgoing = Promise.resolve();
function send(...messages: unknown[]): Promise<void> {
  const frames = Buffer.concat(
    messages.flatMap((message) => {
      const body = Buffer.from(JSON.stringify(message), "utf8");
      return [
        Buffer.from(
          `Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: ${body.length}\r\n\r\n`,
        ),
        body,
      ];
    }),
  );
  outgoing = outgoing.then(async () => {
    const emoji = frames.indexOf(Buffer.from("🧪"));
    const split = emoji >= 0 ? emoji + 2 : Math.min(35, frames.length);
    for (const part of [
      frames.subarray(0, 7),
      frames.subarray(7, split),
      frames.subarray(split),
    ]) {
      let offset = 0;
      while (offset < part.length) {
        const written = writeSync(1, part, offset, part.length - offset);
        if (written === 0) throw new Error("Mock LSP stdout made no progress.");
        offset += written;
      }
      await Bun.sleep(2);
    }
  });
  return outgoing;
}

const result = (id: Message["id"], value: unknown) => ({
  jsonrpc: "2.0",
  id,
  result: value,
});
const range = (character: number) => ({
  start: { line: 0, character },
  end: { line: 0, character: character + 1 },
});
const diagnostic = (message: string) => ({
  range: range(1),
  severity: 2,
  message,
  source: "mock",
  code: "TS1",
  relatedInformation: [
    { location: { uri: uri(outside), range: range(0) }, message: "private" },
  ],
});

let initialized = false;
let shuttingDown = false;
let heldDefinition: Message["id"];
const documents = new Map<string, { version: number; text: string }>();
function publish(documentUri: string, version: number, text: string): void {
  const notification = (path: string, message: string, revision = version) => ({
    jsonrpc: "2.0",
    method: "textDocument/publishDiagnostics",
    params: {
      uri: path,
      version: revision,
      diagnostics:
        mode === "many" && path === documentUri
          ? Array.from({ length: 205 }, (_, index) =>
              diagnostic(`Diagnostic ${index}: see ${uri(outside)}`),
            )
          : [diagnostic(message)],
    },
  });
  if (version > 1) send(notification(documentUri, "stale", version - 1));
  send(
    notification(documentUri, `🧪 ${text.split(/\r?\n/)[0]}`),
    notification(uri(outside), "outside"),
    notification(uri("hidden.ts"), "denied"),
    notification(uri(".justnewmcp/checkpoints/private.ts"), "internal"),
  );
}

async function handle(message: Message): Promise<void> {
  if (message.jsonrpc !== "2.0") throw new Error("Expected JSON-RPC 2.0.");
  const { id, method, params } = message;
  if (method === "initialize") {
    if (
      !params?.rootUri ||
      fileURLToPath(params.rootUri) !== root ||
      !params.capabilities?.general?.positionEncodings?.includes("utf-16")
    )
      throw new Error("Invalid initialization.");
    trace("initialize");
    send(
      result(id, {
        capabilities: {
          positionEncoding: "utf-16",
          textDocumentSync: {
            openClose: true,
            change: mode === "incremental" ? 2 : 1,
          },
          ...(mode === "pull"
            ? {
                diagnosticProvider: {
                  interFileDependencies: false,
                  workspaceDiagnostics: false,
                },
              }
            : {}),
        },
      }),
    );
    return;
  }
  if (method === "initialized") {
    initialized = true;
    trace("initialized");
    send(
      {
        jsonrpc: "2.0",
        id: "config",
        method: "workspace/configuration",
        params: { items: [{ section: "mock" }] },
      },
      {
        jsonrpc: "2.0",
        id: "edit",
        method: "workspace/applyEdit",
        params: { edit: {} },
      },
    );
    return;
  }
  if (method === undefined) {
    trace(String(id), message.result);
    return;
  }
  if (!initialized) throw new Error("Expected initialized before requests.");
  const doc = params?.textDocument;
  if (
    method === "textDocument/didOpen" &&
    doc?.version !== undefined &&
    doc.text !== undefined
  ) {
    trace("open", doc.version);
    documents.set(doc.uri, { version: doc.version, text: doc.text });
    publish(doc.uri, doc.version, doc.text);
  } else if (
    method === "textDocument/didChange" &&
    doc?.version !== undefined
  ) {
    const change = params?.contentChanges?.[0];
    const previous = documents.get(doc.uri);
    if (
      !previous ||
      !change ||
      doc.version <= previous.version ||
      (mode === "incremental" && !change.range)
    )
      throw new Error("Invalid change.");
    trace("change", { version: doc.version, range: change.range });
    documents.set(doc.uri, { version: doc.version, text: change.text });
    publish(doc.uri, doc.version, change.text);
  } else if (method === "textDocument/didClose" && doc) {
    documents.delete(doc.uri);
  } else if (method === "textDocument/diagnostic" && doc) {
    trace("pull");
    if (params?.previousResultId === "mock-report") {
      trace("unchanged");
      send(result(id, { kind: "unchanged", resultId: "mock-report" }));
      return;
    }
    send(
      result(id, {
        kind: "full",
        resultId: "mock-report",
        items: [diagnostic("pull 🧪")],
        relatedDocuments: {
          [uri(outside)]: { kind: "full", items: [diagnostic("forbidden")] },
        },
      }),
    );
  } else if (method === "textDocument/definition" && doc && params?.position) {
    const { line, character } = params.position;
    if (line === 3) process.exit(4);
    if (line === 4) {
      await outgoing;
      writeSync(1, "Content-Length: 20\r\nContent-Length: 30\r\n\r\n");
      return;
    }
    if (line === 5) return;
    if (line === 6) {
      trace("request-error", id);
      await send({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: uri(outside) },
      });
      trace("sent-error", id);
      return;
    }
    if (line === 1) {
      heldDefinition = id;
      trace("hold-definition");
      return;
    }
    send(
      result(id, [
        {
          targetUri: uri("target 🧪.ts"),
          targetSelectionRange: range(character),
        },
        { uri: uri(outside), range: range(0) },
        { uri: uri("hidden.ts"), range: range(0) },
        { uri: uri("outside-link.ts"), range: range(0) },
        { uri: uri(".justnewmcp/checkpoints/private.ts"), range: range(0) },
        { uri: "file:///not%2Fvalid", range: range(0) },
        { uri: "https://example.invalid/test.ts", range: range(0) },
        {
          uri: uri("target 🧪.ts"),
          range: { start: { line: -1, character: 0 } },
        },
      ]),
    );
  } else if (method === "textDocument/references" && doc) {
    const references = [{ uri: uri("target 🧪.ts"), range: range(2) }];
    if (params?.context?.includeDeclaration)
      references.push({ uri: doc.uri, range: range(0) });
    send(result(id, references));
    if (heldDefinition !== undefined) {
      send(
        result(heldDefinition, { uri: uri("target 🧪.ts"), range: range(9) }),
      );
      heldDefinition = undefined;
    }
  } else if (method === "shutdown") {
    trace(method);
    if (mode !== "unresponsive") {
      shuttingDown = true;
      send(result(id, null));
    }
  } else if (method === "exit") {
    if (!shuttingDown) throw new Error("Missing shutdown handshake.");
    trace(method);
    await outgoing;
    process.exit(0);
  }
}

if (mode === "unresponsive" && process.platform !== "win32")
  process.on("SIGTERM", () => {});
let input = Buffer.alloc(0);
let bodyLength: number | undefined;
for await (const chunk of Bun.stdin.stream()) {
  input = Buffer.concat([input, chunk]);
  for (;;) {
    if (bodyLength === undefined) {
      const end = input.indexOf("\r\n\r\n");
      if (end === -1) break;
      const length = /^Content-Length: (\d+)$/im.exec(
        input.subarray(0, end).toString("ascii"),
      );
      if (!length) throw new Error("Missing Content-Length.");
      bodyLength = Number(length[1]);
      input = input.subarray(end + 4);
    }
    if (input.length < bodyLength) break;
    const body = input.subarray(0, bodyLength);
    input = input.subarray(bodyLength);
    bodyLength = undefined;
    await handle(JSON.parse(body.toString("utf8")) as Message);
  }
}
