// src/lib/satellite/forward-client-ip.ts
// The satellite rate-limits per client address. A request this app proxies to the satellite arrives
// from THIS container, so without a forwarded address every user would share one bucket (one client
// could exhaust /register or /trust/psi/initiate for everyone). The edge overwrites X-Forwarded-For
// with the real client IP, so its FIRST entry is that client: forward exactly that one address, and
// nothing when it isn't a valid IP. The satellite believes the header only from this container's
// exact address (its SATELLITE_TRUSTED_PROXY_NAMES), and takes the rightmost entry.
import { isIP } from 'node:net';
import { getClientIP } from '@/lib/relay/mailbox-rate-limit';

/** `{ 'X-Forwarded-For': <client ip> }` when the inbound request names a valid client IP, else `{}`. */
export function forwardedClientIp(request: Request): Record<string, string> {
  const ip = getClientIP(request);
  return isIP(ip) ? { 'X-Forwarded-For': ip } : {};
}
