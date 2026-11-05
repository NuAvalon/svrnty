// src/lib/relay/client-ip.ts
// #707 "client-ip v1" (Flint ruling lane:svrnty #1329; task #707). The relay sits behind Cloudflare → Caddy, and Caddy trusts no proxy
// today, so the leftmost X-Forwarded-For the app used to read is a CLOUDFLARE EDGE address (measured 2026-10-31 on dev: 2208/2208
// relay requests from CF ranges, 262 edges, 5 real clients). Per-IP limits were per-edge: users sharing an edge throttled each other
// and one sender got a fresh budget on every edge. Worse once Caddy trusts CF, a client could forge the leftmost XFF entry.
//
// C3: read ONLY X-Svrnty-Client-IP, which Caddy sets itself (header_up overwrites anything the client sent) from {client_ip}, i.e.
// Cf-Connecting-IP when, and only when, the TCP peer is inside the pinned Cloudflare ranges (C2, trusted_proxies). Never the leftmost
// XFF, never Cf-Connecting-IP directly. Missing or malformed → one shared 'unknown' bucket (fail-closed, strict).
// C5: the value only keys the in-memory limiter. Never log it.
//
// DEPLOY ORDER: Caddy C2 FIRST (the current app ignores the new header), then this. Shipping this first puts every depositor in the
// one 'unknown' bucket.

export const CLIENT_IP_HEADER = 'x-svrnty-client-ip';
export const UNKNOWN_CLIENT = 'unknown';
const IP_CHARS = /^[0-9A-Fa-f:.]{2,45}$/; // IPv4 / IPv6 text forms only; anything else is not something Caddy wrote

export function getClientIP(request: Request): string {
  const v = request.headers.get(CLIENT_IP_HEADER)?.trim();
  return v && IP_CHARS.test(v) ? v : UNKNOWN_CLIENT;
}
