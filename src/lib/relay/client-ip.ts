// src/lib/relay/client-ip.ts
// #707 "client-ip v1" (Flint ruling lane:svrnty #1329; task #707). The relay sits behind Cloudflare → Caddy. When Caddy trusted no proxy,
// the leftmost X-Forwarded-For the app read was a CLOUDFLARE EDGE address (measured 2026-10-31 on dev: 2208/2208 relay requests
// from CF ranges, 262 edges, 5 real clients). Per-IP limits were per-edge: users sharing an edge throttled each other and one sender
// got a fresh budget on every edge. Caddy trusts the CF ranges now, which makes the leftmost XFF entry forgeable, so it is never read.
//
// C3: read ONLY X-Svrnty-Client-IP, which Caddy sets itself (request_header overwrites anything the client sent) from {client_ip}, i.e.
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

/**
 * The budget key for an address: an IPv4 address as is; an IPv6 address by its /64 (one host or subscriber usually owns a whole /64,
 * so per-address keying would give it unlimited budget and let it fill the map); an IPv4-mapped IPv6 address as its IPv4. Anything
 * that doesn't parse is keyed as given.
 */
export function budgetKeyOf(ip: string): string {
  let s = ip.trim().toLowerCase();
  if (s.startsWith('[') && s.includes(']')) s = s.slice(1, s.indexOf(']'));
  if (!s.includes(':')) return s;
  s = s.split('%')[0]; // drop a zone id
  const mapped = /^(?:::|(?:0{1,4}:){5})(?:0{1,4}:)?ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped) return mapped[1];
  const halves = s.split('::');
  if (halves.length > 2) return s;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const width = (parts: string[]) => parts.reduce((w, p) => w + (p.includes('.') ? 2 : 1), 0);
  const fill = halves.length === 2 ? 8 - width(head) - width(tail) : 0;
  if (fill < 0 || (halves.length === 1 && width(head) !== 8)) return s;
  const first4 = [...head, ...Array<string>(fill).fill('0'), ...tail].slice(0, 4);
  if (first4.length < 4 || !first4.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return s;
  return first4.map((g) => parseInt(g, 16).toString(16)).join(':') + '::/64';
}
