export type AuditEventType =
  | "oauth.authorize.approved"
  | "oauth.authorize.denied"
  | "oauth.token.issued"
  | "oauth.token.denied"
  | "oauth.token.revoked"
  | "oauth.rate_limited"
  | "mcp.auth.denied"
  | "mcp.cmd.background_started"
  | "mcp.cmd.background_stopped"
  | "mcp.shell.called"
  | "mcp.plan.entered"
  | "mcp.plan.exited"
  | "mcp.tool.called"
  | "mcp.tool.human_approved"
  | "mcp.tool.denied";

export interface AuditEntry {
  timestamp: string;
  event: AuditEventType;
  ip: string;
  clientId?: string;
  detail?: string;
}

export class AuditLogger {
  private readonly entries: AuditEntry[] = [];

  constructor(private readonly maxEntries = 1000) {}

  record(
    event: AuditEventType,
    ip: string,
    extra?: { clientId?: string; detail?: string },
  ): AuditEntry {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      event,
      ip,
      ...(extra?.clientId ? { clientId: extra.clientId } : {}),
      ...(extra?.detail ? { detail: extra.detail } : {}),
    };

    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }
    return entry;
  }

  list(): readonly AuditEntry[] {
    return this.entries;
  }
}
