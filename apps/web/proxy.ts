import { NextRequest, NextResponse } from "next/server";

/**
 * Per-request CSP with a nonce (strict-dynamic). The console can never be framed.
 * Widget pages (/widget/<publicKey>) may only be framed by the origins the tenant approved
 * for that widget key; the list comes from the public gateway and is cached briefly.
 */
const PUBLIC = process.env.PUBLIC_GATEWAY_URL ?? "http://localhost:8000";
const cache = new Map<string, { at: number; origins: string[] }>();

async function widgetOrigins(key: string): Promise<string[]> {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < 60_000) return hit.origins;
  try {
    const res = await fetch(`${PUBLIC}/v1/widget/config?key=${encodeURIComponent(key)}`, {
      cache: "no-store",
    });
    const origins: string[] = res.ok ? ((await res.json()).allowed_origins ?? []) : [];
    const safe = origins.filter((o) => /^https?:\/\/[a-z0-9.-]+(:\d+)?$/i.test(o));
    cache.set(key, { at: Date.now(), origins: safe });
    return safe;
  } catch {
    return [];
  }
}

export async function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const path = request.nextUrl.pathname;
  let frameAncestors = "'none'";
  const widget = path.match(/^\/widget\/(pk_[A-Za-z0-9_-]{16,64})$/);
  if (widget?.[1]) {
    const origins = await widgetOrigins(widget[1]);
    frameAncestors = origins.length ? origins.join(" ") : "'none'";
  }
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    `frame-ancestors ${frameAncestors}`,
    request.nextUrl.protocol === "https:" ? "upgrade-insecure-requests" : "",
  ].filter(Boolean).join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico|widget/loader.js).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
