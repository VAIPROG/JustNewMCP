export const BASE_SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
};

export function withSecurityHeaders(res: Response, extra?: Record<string, string>): Response {
  const headers = new Headers(res.headers);
  for (const [key, value] of Object.entries(BASE_SECURITY_HEADERS)) {
    if (!headers.has(key)) {
      headers.set(key, value);
    }
  }
  if (extra) {
    for (const [key, value] of Object.entries(extra)) {
      headers.set(key, value);
    }
  }
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
}

export async function readBodyWithinLimit(
  req: Request,
  maxBytes: number,
): Promise<{ ok: true; text: string } | { ok: false; response: Response }> {
  const declared = req.headers.get("content-length");
  if (declared !== null) {
    const parsed = Number(declared);
    if (Number.isFinite(parsed) && parsed > maxBytes) {
      return {
        ok: false,
        response: Response.json({ error: "payload_too_large" }, { status: 413 }),
      };
    }
  }

  const buffer = await req.arrayBuffer();
  if (buffer.byteLength > maxBytes) {
    return {
      ok: false,
      response: Response.json({ error: "payload_too_large" }, { status: 413 }),
    };
  }

  return { ok: true, text: new TextDecoder("utf-8").decode(buffer) };
}
