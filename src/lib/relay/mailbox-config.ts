// src/lib/relay/mailbox-config.ts
// Per-operator POLICY for the return-channel mailbox — read from env, NEVER hardcoded literals.
//
// Joint design §5.1 + Invariant 8 (no protocol fork
// managed-vs-self-host): the numbers below are the svrnty.is DEFAULT profile, NOT protocol
// constants. A family relay runs the SAME image with different env (door-wide-open); a community
// relay gates to members. Hardcoding svrnty.is's profile would fork the image in practice.
//
// Read per-call (cheap env lookups) so tooling — e.g. an on-demand TTL hook — can shorten a
// value for one run without a rebuild.

function intEnv(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : def;
}

function boolEnv(name: string, def: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  return raw === 'true' || raw === '1';
}

export interface MailboxConfig {
  /** Per-mailbox envelope cap → 429 at-cap (documented bounded I-4 residual). */
  cap: number;
  /** Per-envelope TTL backstop GC in ms (ack-delete is primary; an on-demand hook shortens this). */
  envelopeTtlMs: number;
  /** Opaque blob size cap in bytes. */
  maxPayloadBytes: number;
  /** Per-IP deposit rate ceiling within the window. */
  rateLimitMax: number;
  rateLimitWindowMs: number;
  /** Owner-auth (signed poll/ack) freshness window in ms — bounds replay of a captured request. */
  ownerAuthWindowMs: number;
  /**
   * §5.1 LAUNCH seam: when true (svrnty.is nursery profile), mailbox CREATION is gated behind an
   * explicit owner-claim carrying an invite_token+chain. That claim machinery lands WITH the invite
   * system (launch hardening) and is deliberately NOT retrofitted into the 9/10 build.
   * Default false = door-open lazy-create-on-deposit (demo/family profile).
   */
  inviteRequired: boolean;
}

export function mailboxConfig(): MailboxConfig {
  return {
    cap: intEnv('RELAY_MAILBOX_CAP', 1000),
    envelopeTtlMs: intEnv('RELAY_ENVELOPE_TTL_MS', 7 * 24 * 60 * 60 * 1000),
    maxPayloadBytes: intEnv('RELAY_MAX_PAYLOAD_BYTES', 64 * 1024),
    rateLimitMax: intEnv('RELAY_RATE_LIMIT_MAX', 10),
    rateLimitWindowMs: intEnv('RELAY_RATE_LIMIT_WINDOW_MS', 60_000),
    ownerAuthWindowMs: intEnv('RELAY_OWNER_AUTH_WINDOW_MS', 60_000),
    inviteRequired: boolEnv('INVITE_REQUIRED', false),
  };
}
