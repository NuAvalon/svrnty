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
   * Per-IP ceiling on the OWNER routes (queue / ack / claim) within ownerRateLimitWindowMs, checked before any decode or verify.
   * NOT the deposit budget: a browser polls every 1.5 s when active and every 0.35 s in a burst (live-book-poll.ts), and several
   * clients can share one IP (a household NAT, the fleet host), so 10/min would lock real owners out. 300/min (5/s) covers an
   * active tab in burst plus a few idle clients behind one address.
   */
  ownerRateLimitMax: number;
  ownerRateLimitWindowMs: number;
  /** Most distinct IPs the owner-route limiter tracks; past it (after a sweep) new IPs share one overflow bucket. */
  ownerRateLimitIpCap: number;
  /** Most live (mailbox_id, nonce) entries in the owner replay cache; when full (after a sweep) the one-time check is skipped and logged. */
  replayCacheMax: number;
  /**
   * Whether the owner routes (queue / ack) accept v2 (mbx2_) mailboxes. Default false: no client signs v2 yet, and a v2 owner verify
   * is the costliest request an attacker can send, so until clients move to it these routes refuse v2 with the uniform non-owner 401,
   * before any decode or signature check. Deposits to a v2 id are unaffected. Turning this on needs replay protection in the v2 verifier first.
   */
  ownerV2Enabled: boolean;
  /**
   * §5.1 LAUNCH seam: when true (svrnty.is nursery profile), mailbox CREATION is gated behind an
   * explicit owner-claim carrying an invite_token+chain. That claim machinery lands WITH the invite
   * system (launch hardening) and is deliberately NOT retrofitted into the 9/10 build.
   * Default false = door-open lazy-create-on-deposit (demo/family profile).
   */
  inviteRequired: boolean;
  /** L4: refuse NEW deposits (429) once the relay's data filesystem is at least this % used. Polls/acks never refused. */
  diskWatermarkPct: number;
  /** Bytes one mailbox may hold, alongside the message count. Same 429 as the count cap. */
  mailboxBytesCap: number;
  /** Most deposit addresses tracked at once. Past it, expired ones are swept, then new ones share one overflow bucket. */
  rateLimitIpCap: number;
  /** Accepted deposit bytes per rate-limit window, across every address and mailbox. 0 = derive it from this disk (deposit-budget.ts). */
  globalDepositBytesPerWindow: number;
}

export function mailboxConfig(): MailboxConfig {
  return {
    cap: intEnv('RELAY_MAILBOX_CAP', 1000),
    envelopeTtlMs: intEnv('RELAY_ENVELOPE_TTL_MS', 7 * 24 * 60 * 60 * 1000),
    maxPayloadBytes: intEnv('RELAY_MAX_PAYLOAD_BYTES', 64 * 1024),
    rateLimitMax: intEnv('RELAY_RATE_LIMIT_MAX', 10),
    rateLimitWindowMs: intEnv('RELAY_RATE_LIMIT_WINDOW_MS', 60_000),
    ownerAuthWindowMs: intEnv('RELAY_OWNER_AUTH_WINDOW_MS', 60_000),
    ownerRateLimitMax: intEnv('RELAY_OWNER_RATE_LIMIT_MAX', 300),
    ownerRateLimitWindowMs: intEnv('RELAY_OWNER_RATE_LIMIT_WINDOW_MS', 60_000),
    ownerRateLimitIpCap: intEnv('RELAY_OWNER_RATE_LIMIT_IP_CAP', 50_000),
    replayCacheMax: intEnv('RELAY_REPLAY_CACHE_MAX', 100_000),
    ownerV2Enabled: boolEnv('RELAY_OWNER_V2_ENABLED', false),
    inviteRequired: boolEnv('INVITE_REQUIRED', false),
    diskWatermarkPct: Math.min(intEnv('RELAY_DISK_WATERMARK_PCT', 80), 100),
    mailboxBytesCap: intEnv('RELAY_MAILBOX_BYTES_CAP', 16 * 1024 * 1024),
    rateLimitIpCap: intEnv('RELAY_RATE_LIMIT_IP_CAP', 50_000),
    globalDepositBytesPerWindow: intEnv('RELAY_GLOBAL_DEPOSIT_BYTES_PER_WINDOW', 0),
  };
}
