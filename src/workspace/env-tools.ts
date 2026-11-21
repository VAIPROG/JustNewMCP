import { chmodSync, existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { createCheckpoint } from "./checkpoints.ts";
import { isEnvSecretPath, isSafeEnvTemplatePath, resolveInsideRoots, resolveWritablePathInsideRoot } from "./paths.ts";

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_ENV_FILE_BYTES = 256 * 1024;

export interface EnvVarSummary {
  name: string;
  valueLength: number;
  isEmpty: boolean;
  line: number;
}

interface ParsedEnvEntry {
  key: string;
  value: string;
  line: number;
  startOffset: number;
  endOffset: number;
}

function stripEnvPatterns(deniedPatterns: string[]): string[] {
  return deniedPatterns.filter((p) => {
    const clean = p.trim().toLowerCase();
    return clean !== ".env" && clean !== ".env.*";
  });
}

function assertEnvFileTarget(inputPath: string): void {
  if (!isEnvSecretPath(inputPath) && !isSafeEnvTemplatePath(inputPath)) {
    throw new Error(`Path "${inputPath}" is not a .env file.`);
  }
}

export function parseEnvEntries(text: string): ParsedEnvEntry[] {
  const entries: ParsedEnvEntry[] = [];
  const len = text.length;
  let pos = 0;
  let line = 1;

  while (pos < len) {
    const lineStart = pos;
    const entryLine = line;

    // Skip leading horizontal whitespace on the line
    while (pos < len && (text[pos] === " " || text[pos] === "\t")) {
      pos += 1;
    }

    // Blank line or comment line
    if (pos >= len || text[pos] === "\n" || text[pos] === "\r" || text[pos] === "#") {
      while (pos < len && text[pos] !== "\n") {
        pos += 1;
      }
      if (pos < len && text[pos] === "\n") {
        pos += 1;
        line += 1;
      }
      continue;
    }

    // Optional `export ` prefix
    if (text.slice(pos, pos + 7) === "export ") {
      pos += 7;
      while (pos < len && (text[pos] === " " || text[pos] === "\t")) {
        pos += 1;
      }
    }

    const keyStart = pos;
    while (pos < len && text[pos] !== "=" && text[pos] !== "\n" && text[pos] !== "\r") {
      pos += 1;
    }

    if (pos >= len || text[pos] !== "=") {
      while (pos < len && text[pos] !== "\n") {
        pos += 1;
      }
      if (pos < len && text[pos] === "\n") {
        pos += 1;
        line += 1;
      }
      continue;
    }

    const key = text.slice(keyStart, pos).trim();
    pos += 1; // consume '='

    while (pos < len && (text[pos] === " " || text[pos] === "\t")) {
      pos += 1;
    }

    let value = "";
    const quote = text[pos];
    if (quote === '"' || quote === "'" || quote === "`") {
      pos += 1;
      const valChars: string[] = [];
      while (pos < len) {
        const ch = text[pos];
        if (ch === "\\" && pos + 1 < len) {
          const next = text[pos + 1];
          if (quote === '"' && next === "n") {
            valChars.push("\n");
            pos += 2;
            continue;
          }
          if (quote === '"' && next === "r") {
            valChars.push("\r");
            pos += 2;
            continue;
          }
          if (next === "$" || next === quote) {
            valChars.push(next);
            pos += 2;
            continue;
          }
        }
        if (ch === quote) {
          pos += 1;
          break;
        }
        if (ch === "\n") {
          line += 1;
        }
        valChars.push(ch ?? "");
        pos += 1;
      }
      value = valChars.join("");
      // Consume remainder of the closing line
      while (pos < len && text[pos] !== "\n") {
        pos += 1;
      }
      if (pos < len && text[pos] === "\n") {
        pos += 1;
        line += 1;
      }
    } else {
      const valStart = pos;
      while (pos < len && text[pos] !== "\n" && text[pos] !== "\r") {
        pos += 1;
      }
      let rawVal = text.slice(valStart, pos).trim();
      const commentIdx = rawVal.search(/\s+#/);
      if (commentIdx !== -1) {
        rawVal = rawVal.slice(0, commentIdx).trim();
      }
      value = rawVal.replaceAll("\\$", "$");
      if (pos < len && text[pos] === "\r") pos += 1;
      if (pos < len && text[pos] === "\n") {
        pos += 1;
        line += 1;
      }
    }

    if (ENV_KEY_RE.test(key)) {
      entries.push({
        key,
        value,
        line: entryLine,
        startOffset: lineStart,
        endOffset: pos,
      });
    }
  }

  return entries;
}

function formatEnvValue(value: string): string {
  const withEscapedDollar = value.replaceAll("$", "\\$");
  const needsQuoting = /[\r\n\s#"'`$]/.test(value);
  if (needsQuoting && withEscapedDollar.endsWith("\\")) {
    throw new Error("Quoted dotenv values ending with a backslash cannot be safely serialized.");
  }
  if (/[\r\n]/.test(withEscapedDollar)) {
    if (!withEscapedDollar.includes("\"")) {
      return `"${withEscapedDollar.replaceAll("\r", "\\r").replaceAll("\n", "\\n")}"`;
    }
    if (!withEscapedDollar.includes("`")) {
      return `\`${withEscapedDollar}\``;
    }
    throw new Error("Value containing both newlines, double quotes, and backticks cannot be safely serialized in dotenv.");
  }
  if (!/[\s#"'`$]/.test(value)) {
    return withEscapedDollar;
  }
  if (!withEscapedDollar.includes("'")) {
    return `'${withEscapedDollar}'`;
  }
  if (!withEscapedDollar.includes("`")) {
    return `\`${withEscapedDollar}\``;
  }
  if (!withEscapedDollar.includes('"') && !/\\[rn]/.test(withEscapedDollar)) {
    return `"${withEscapedDollar}"`;
  }
  throw new Error("Value containing single quotes, double quotes, and backticks simultaneously cannot be safely serialized in dotenv.");
}

export async function readAvailableEnvsTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  inputPath = ".env",
): Promise<{
  path: string;
  totalKeys: number;
  variables: EnvVarSummary[];
}> {
  assertEnvFileTarget(inputPath);
  const nonEnvDenied = stripEnvPatterns(deniedPatterns);
  const candidate = resolve(workspaceRoot, inputPath);
  const { resolvedPath } = resolveInsideRoots(candidate, [workspaceRoot], process.platform, nonEnvDenied);

  const stat = statSync(resolvedPath);
  if (!stat.isFile()) {
    throw new Error(`Path "${inputPath}" is not a regular file.`);
  }
  if (stat.size > MAX_ENV_FILE_BYTES) {
    throw new Error(`Env file "${inputPath}" exceeds ${MAX_ENV_FILE_BYTES} bytes.`);
  }

  const text = await Bun.file(resolvedPath).text();
  const entries = parseEnvEntries(text);

  // Last assignment wins (matching Bun's dotenv loader)
  const effectiveByKey = new Map<string, EnvVarSummary>();
  for (const entry of entries) {
    effectiveByKey.set(entry.key, {
      name: entry.key,
      valueLength: entry.value.length,
      isEmpty: entry.value.length === 0,
      line: entry.line,
    });
  }

  const variables = [...effectiveByKey.values()];
  return {
    path: relative(workspaceRoot, resolvedPath).replaceAll("\\", "/"),
    totalKeys: variables.length,
    variables,
  };
}

export async function setEnvVarTool(
  workspaceRoot: string,
  deniedPatterns: string[],
  opts: {
    path?: string;
    key: string;
    value?: string;
    action?: "set" | "delete";
  },
): Promise<{
  path: string;
  key: string;
  action: "created" | "updated" | "deleted";
  valueLength?: number;
  checkpointId: string;
}> {
  const inputPath = opts.path ?? ".env";
  assertEnvFileTarget(inputPath);
  if (!ENV_KEY_RE.test(opts.key)) {
    throw new Error(`Invalid environment variable name "${opts.key}".`);
  }

  const nonEnvDenied = stripEnvPatterns(deniedPatterns);
  const targetPath = resolveWritablePathInsideRoot(inputPath, workspaceRoot, nonEnvDenied);
  mkdirSync(dirname(targetPath), { recursive: true });

  const existing = existsSync(targetPath) ? await Bun.file(targetPath).text() : "";
  const entries = parseEnvEntries(existing);
  const matches = entries.filter((e) => e.key === opts.key);
  const actionMode = opts.action ?? "set";

  let updatedText = existing;
  let resultAction: "created" | "updated" | "deleted";

  if (actionMode === "delete") {
    if (matches.length === 0) {
      throw new Error(`Environment variable "${opts.key}" not found in "${inputPath}".`);
    }
    for (let i = matches.length - 1; i >= 0; i -= 1) {
      const m = matches[i];
      if (!m) continue;
      updatedText = updatedText.slice(0, m.startOffset) + updatedText.slice(m.endOffset);
    }
    resultAction = "deleted";
  } else {
    const value = opts.value ?? "";
    const formattedLine = `${opts.key}=${formatEnvValue(value)}\n`;

    if (matches.length > 0) {
      const lastIndex = matches.length - 1;
      for (let i = lastIndex; i >= 0; i -= 1) {
        const m = matches[i];
        if (!m) continue;
        const replacement = i === lastIndex ? formattedLine : "";
        updatedText = updatedText.slice(0, m.startOffset) + replacement + updatedText.slice(m.endOffset);
      }
      resultAction = "updated";
    } else {
      const needsNewline = updatedText.length > 0 && !updatedText.endsWith("\n");
      updatedText = `${updatedText}${needsNewline ? "\n" : ""}${formattedLine}`;
      resultAction = "created";
    }
  }

  const existedBefore = existsSync(targetPath);
  const cp = await createCheckpoint(workspaceRoot, targetPath, `set_env_var:${opts.key}`);
  if (!existedBefore && isEnvSecretPath(targetPath) && process.platform !== "win32") {
    writeFileSync(targetPath, updatedText, { encoding: "utf8", mode: 0o600 });
    chmodSync(targetPath, 0o600);
  } else {
    await Bun.write(targetPath, updatedText);
  }

  return {
    path: relative(workspaceRoot, targetPath).replaceAll("\\", "/"),
    key: opts.key,
    action: resultAction,
    ...(actionMode === "set" ? { valueLength: (opts.value ?? "").length } : {}),
    checkpointId: cp.id,
  };
}
