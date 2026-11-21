import { existsSync, mkdirSync, statSync } from "node:fs";
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

function parseEnvLine(line: string): { key: string; value: string } | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const withoutExport = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
  const eqIdx = withoutExport.indexOf("=");
  if (eqIdx <= 0) return null;
  const key = withoutExport.slice(0, eqIdx).trim();
  if (!ENV_KEY_RE.test(key)) return null;
  let value = withoutExport.slice(eqIdx + 1).trim();
  if (
    (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
    (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
  ) {
    value = value.slice(1, -1);
  }
  return { key, value };
}

function formatEnvValue(value: string): string {
  if (/[\r\n]/.test(value)) {
    const escaped = value
      .replaceAll('"', '\\"')
      .replaceAll("\r", "\\r")
      .replaceAll("\n", "\\n");
    return `"${escaped}"`;
  }
  if (!/[\s#"'`$]/.test(value)) {
    return value;
  }
  if (!value.includes("'")) {
    return `'${value}'`;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
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
  const lines = text === "" ? [] : text.replace(/\r?\n$/, "").split(/\r?\n/);
  const variables: EnvVarSummary[] = [];

  for (let i = 0; i < lines.length; i += 1) {
    const parsed = parseEnvLine(lines[i] ?? "");
    if (!parsed) continue;
    variables.push({
      name: parsed.key,
      valueLength: parsed.value.length,
      isEmpty: parsed.value.length === 0,
      line: i + 1,
    });
  }

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
  const lines = existing === "" ? [] : existing.replace(/\r?\n$/, "").split(/\r?\n/);
  const actionMode = opts.action ?? "set";

  let foundIndex = -1;
  for (let i = 0; i < lines.length; i += 1) {
    const parsed = parseEnvLine(lines[i] ?? "");
    if (parsed && parsed.key === opts.key) {
      foundIndex = i;
      break;
    }
  }

  let resultAction: "created" | "updated" | "deleted";
  if (actionMode === "delete") {
    if (foundIndex === -1) {
      throw new Error(`Environment variable "${opts.key}" not found in "${inputPath}".`);
    }
    lines.splice(foundIndex, 1);
    resultAction = "deleted";
  } else {
    const value = opts.value ?? "";
    const formatted = `${opts.key}=${formatEnvValue(value)}`;
    if (foundIndex !== -1) {
      lines[foundIndex] = formatted;
      resultAction = "updated";
    } else {
      lines.push(formatted);
      resultAction = "created";
    }
  }

  const cp = await createCheckpoint(workspaceRoot, targetPath, `set_env_var:${opts.key}`);
  const finalContent = lines.length > 0 ? `${lines.join("\n")}\n` : "";
  await Bun.write(targetPath, finalContent);

  return {
    path: relative(workspaceRoot, targetPath).replaceAll("\\", "/"),
    key: opts.key,
    action: resultAction,
    ...(actionMode === "set" ? { valueLength: (opts.value ?? "").length } : {}),
    checkpointId: cp.id,
  };
}
