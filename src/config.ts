import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { z } from "zod";

export const DEFAULT_DENIED_PATH_PATTERNS = [
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "id_rsa",
  "id_ed25519",
  ".git/config",
];

export const DEFAULT_ALLOWED_REDIRECT_URIS = [
  "https://gemini.google.com/",
  "https://aistudio.google.com/",
  "http://127.0.0.1",
  "http://localhost",
];

export const RateLimitSchema = z.object({
  maxFailures: z.number().int().min(1).default(5),
  windowMs: z.number().int().min(1000).default(60_000),
  lockoutMs: z.number().int().min(1000).default(300_000),
  maxTrackedIps: z.number().int().min(100).default(10_000),
});

export const OAuthConfigSchema = z.object({
  clientId: z.string().min(4),
  clientSecret: z.string().min(16),
  allowedRedirectUris: z
    .array(z.string().min(1))
    .min(1)
    .default(DEFAULT_ALLOWED_REDIRECT_URIS),
  accessTokenTtlSec: z.number().int().min(60).default(3600),
  refreshTokenTtlSec: z.number().int().min(300).default(604_800),
  authCodeTtlSec: z.number().int().min(30).default(300),
  rateLimit: RateLimitSchema.prefault({}),
});

export const AllowedCommandRuleSchema = z.object({
  command: z
    .string()
    .min(1)
    .refine((c) => !c.includes("/") && !c.includes("\\"), {
      message:
        "Command must be a bare executable name without path separators.",
    }),
  allowedSubcommands: z.array(z.string().min(1)).optional(),
  allowedArgs: z.array(z.string().min(1)).optional(),
  deniedArgs: z.array(z.string().min(1)).default([]),
  timeoutMs: z.number().int().min(100).max(600_000).default(30_000),
  maxOutputChars: z.number().int().min(1024).max(150_000).default(30_000),
});

export type AllowedCommandRule = z.infer<typeof AllowedCommandRuleSchema>;

export const LspServerSchema = z.object({
  languageId: z.string().trim().min(1).max(128),
  extensions: z
    .array(
      z
        .string()
        .regex(/^\.?[\w+-]+$/)
        .max(32),
    )
    .min(1)
    .max(32),
  command: z
    .string()
    .min(1)
    .max(256)
    .refine(
      (command) =>
        command.trim() === command &&
        !/[/\\:\x00-\x1f]/.test(command) &&
        command !== "." &&
        command !== "..",
      { message: "Language server command must be a bare executable name." },
    ),
  args: z
    .array(
      z
        .string()
        .max(4096)
        .refine((arg) => !arg.includes("\0")),
    )
    .max(64)
    .default([]),
  idleTimeoutMs: z.number().int().min(5000).max(3_600_000).default(300_000),
  requestTimeoutMs: z.number().int().min(1000).max(120_000).default(15_000),
});

export type LspServerConfig = z.infer<typeof LspServerSchema>;

export const ConfigSchema = z.object({
  host: z.string().default("127.0.0.1"),
  port: z.number().int().min(0).max(65535).default(8787),
  publicUrl: z
    .string()
    .url()
    .transform((u) => u.replace(/\/+$/, "")),
  trustedProxies: z.array(z.string().min(1)).default([]),
  allowedRoots: z.array(z.string().min(1)).min(1),
  memoryDir: z.string().min(1).optional(),
  deniedPathPatterns: z
    .array(z.string().min(1))
    .default(DEFAULT_DENIED_PATH_PATTERNS),
  allowEnvReading: z.boolean().default(false),
  askHumanAllowance: z.boolean().default(false),
  allowedCommands: z.array(AllowedCommandRuleSchema).default([]),
  lspServers: z.array(LspServerSchema).max(8).default([]),
  maxMcpBodyBytes: z.number().int().min(1024).default(1_048_576),
  oauth: OAuthConfigSchema,
});

export type AppConfig = Omit<z.infer<typeof ConfigSchema>, "lspServers"> & {
  lspServers?: LspServerConfig[];
};

export function loadConfig(configPath?: string): AppConfig {
  const filePath = configPath ?? process.env.JUSTNEWMCP_CONFIG;
  let raw: Record<string, unknown> = {};

  if (filePath) {
    const text = readFileSync(resolve(filePath), "utf8");
    raw = JSON.parse(text) as Record<string, unknown>;
  }

  const rawOAuth = (raw.oauth as Record<string, unknown> | undefined) ?? {};
  const merged = {
    ...raw,
    host: process.env.JUSTNEWMCP_HOST ?? raw.host,
    port: process.env.JUSTNEWMCP_PORT
      ? Number(process.env.JUSTNEWMCP_PORT)
      : raw.port,
    publicUrl: process.env.JUSTNEWMCP_PUBLIC_URL ?? raw.publicUrl,
    trustedProxies: process.env.JUSTNEWMCP_TRUSTED_PROXIES
      ? process.env.JUSTNEWMCP_TRUSTED_PROXIES.split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : raw.trustedProxies,
    allowedRoots: process.env.JUSTNEWMCP_ALLOWED_ROOTS
      ? process.env.JUSTNEWMCP_ALLOWED_ROOTS.split(",")
          .map((s) => s.trim())
          .filter(Boolean)
      : raw.allowedRoots,
    memoryDir: process.env.JUSTNEWMCP_MEMORY_DIR ?? raw.memoryDir,
    allowEnvReading:
      process.env.JUSTNEWMCP_ALLOW_ENV_READING !== undefined
        ? process.env.JUSTNEWMCP_ALLOW_ENV_READING === "true"
        : raw.allowEnvReading,
    askHumanAllowance:
      process.env.JUSTNEWMCP_ASK_HUMAN_ALLOWANCE !== undefined
        ? process.env.JUSTNEWMCP_ASK_HUMAN_ALLOWANCE === "true"
        : raw.askHumanAllowance,
    oauth: {
      ...rawOAuth,
      clientId: process.env.JUSTNEWMCP_CLIENT_ID ?? rawOAuth.clientId,
      clientSecret:
        process.env.JUSTNEWMCP_CLIENT_SECRET ?? rawOAuth.clientSecret,
    },
  };

  return ConfigSchema.parse(merged);
}
