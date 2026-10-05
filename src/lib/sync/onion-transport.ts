// src/lib/sync/onion-transport.ts
/**
 * Shared onion transport — the #558 keystone K2/K3 EMIT-PATH (piece-2 mutual-block #579 is the first consumer).
 *
 * WHAT IT IS: the client that actually PUTS cells on the wire and TAKES them off — the "separate reviewable
 * unit" that uniform-frame.ts, onion-envelope.ts, route-ratchet.ts, and distress-cadence.ts each deferred
 * ("the EMIT-PATH that drives real timers, holds the per-guardian K1 route-ratchet state, and deposits cells
 * to the satellite"). It is SHARED by construction: piece-2 held-affirmatives (visible-affirm), consent-delta
 * (go-private / scope-change), and the distress cry all ride ONE transport — never a per-feature fork — so a
 * hosted satellite sees a single uniform stream it cannot classify.
 *
 *   payload ──frameUniform(payload, type)──▶ cell[2048B, type hidden inside]
 *           ──sealToMailbox(recipient DEVICE)──▶ inner  (K0 inner — satellite can't read it)
 *           ──sealOnion(satellite, routeId)──▶ OUTER   (K0 outer + K1 route_id)
 *           ──CadenceEmitter.enqueue──▶ [one cell per cadence slot] ──httpOnionRelay.deposit──▶ POST /onion
 *   recipient: httpOnionRelay.poll(myRouteId) ──openOnionInner(DEVICE)──▶ cell ──unframeUniform──▶ {type,payload}
 *
 * ★ §F5 CADENCE-INDISTINGUISHABILITY (NOT size-pad — size is already uniform by frameUniform). The residual
 * classifier after type+size opacity is TIMING: a fan-out of N affirmatives emitted at once is a burst that
 * reads as "a control-plane event just happened". The resolution (Flint §8b, distress-cadence.ts) is a UNIFORM
 * baseline cover cadence — one opaque cell per slot, forever, for everyone — into which a real cell is SWAPPED
 * (cover→real, invisible on the wire). CadenceEmitter is that swap: callers ENQUEUE real sealed cells and the
 * emitter drains exactly ONE per slot (a real cell if queued, else a fresh cover cell). So a fan-out to N
 * recipients trickles across N slots, each slot byte- and timing-identical to a cover slot. Callers MUST NOT
 * call httpOnionRelay.deposit directly for real traffic — that is the burst §F5 forbids.
 *
 * ★ CLAIM BOUNDARY (do-no-harm — stated so §F5 is not silently overclaimed; mirrors every module here that
 * separates mechanism from live-deployment, and the gate-2 life-safety hold in distress-cadence.ts): this
 * module is the §F5 MECHANISM. Cadence-indistinguishability only actually HOLDS once the uniform baseline is
 * RUNNING on the deployed edge for all users (CadenceEmitter.start wired into the app lifecycle). That wiring
 * is the §8-DEPLOYED integration — a ship-time + Flint §8 + Peter call, DEFERRED and flag-gated here, exactly
 * like K0 deferred satellite-serve and K1 deferred Family-B wiring. Mechanism-present ≠ live-sealed. The
 * `start()` runner exists so the mechanism is drivable and the integration seam is explicit — it is a no-op
 * until something turns it on.
 *
 * NO new crypto core: pure composition over the co-verified primitives (uniform-frame / onion-envelope /
 * mailbox-envelope / route-ratchet) + fetch to the same-origin proxies (app/api/satellite/{onion,route}).
 * Alias-free relative `.js` imports so `npx tsx --test` resolves without a tsconfig-paths loader.
 */
import { frameUniform, unframeUniform, type FrameType } from '../crypto/uniform-frame.js';
import { sealOnion, openOnionInner, type StrippedInner } from '../crypto/onion-envelope.js';
import {
  sealToMailbox,
  type MailboxEnvelopePackage,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
} from '../crypto/mailbox-envelope.js';
import { RouteRatchet, directionTag } from '../crypto/route-ratchet.js';
import type { Random } from '../crypto/distress-cadence.js';

/** Same-origin proxy paths (app/api/satellite/*). The proxies forward OPAQUE to the satellite and strip
 *  nothing (the #179 no-strip lesson, both directions). */
const ONION_DEPOSIT_PATH = '/api/satellite/onion';
const ROUTE_POLL_PREFIX = '/api/satellite/route/';

/** route_id = 128-bit tag = 32 LOWERCASE hex (deriveRouteId via bytesToHex). We enforce lowercase client-side
 *  (stricter than the proxy's case-insensitive regex, matching the satellite's `_valid_route_id`) so a
 *  malformed id fails BEFORE a network call rather than round-tripping to a uniform-400. */
const ROUTE_ID_RE = /^[0-9a-f]{32}$/;

export function isValidRouteId(routeId: unknown): routeId is string {
  return typeof routeId === 'string' && ROUTE_ID_RE.test(routeId);
}

/** Default CSPRNG-backed uniform in [0, 1) — used only for cadence jitter (NOT security-critical, same stance
 *  as distress-cadence.ts); avoids a global Math.random. */
const cryptoRandom: Random = () => crypto.getRandomValues(new Uint32Array(1))[0] / 0x1_0000_0000;

// ── Thin wire client ─────────────────────────────────────────────────────────────────────────────────────

/** The low-level wire the proxy routes reference (app/api/satellite/{onion,route} comments). Onion-aware but
 *  crypto-agnostic: deposit a fully-sealed OUTER cell; poll a route for device-sealed inners. It does NOT
 *  pace — pacing is CadenceEmitter's job. Honest failure: throws on a non-OK transport status (the caller /
 *  the cadence engine / receiveFromRoute decides the fail-closed policy). */
export const httpOnionRelay = {
  /** POST one onion-sealed OUTER cell to the satellite via the same-origin proxy. Throws on non-OK (incl the
   *  satellite's uniform-400 peel-fail and 429 rate-limit) — never swallows a failure silently. Re-deposit of
   *  the exact same cell is a server-side no-op (INSERT OR IGNORE on inner_hash), so a retry is idempotent. */
  async deposit(outer: MailboxEnvelopePackage): Promise<void> {
    const res = await fetch(ONION_DEPOSIT_PATH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(outer),
    });
    if (!res.ok) throw new Error(`onion deposit failed: HTTP ${res.status}`);
  },

  /** GET the device-sealed, mailbox_fp-stripped inner cells buffered at a route_id. Returns the raw inners
   *  (the caller opens each with its device key). Throws on a bad route_id or non-OK transport status. */
  async poll(routeId: string): Promise<StrippedInner[]> {
    if (!isValidRouteId(routeId)) throw new Error('onion poll: invalid route_id');
    const res = await fetch(`${ROUTE_POLL_PREFIX}${routeId}`, { method: 'GET' });
    if (!res.ok) throw new Error(`onion poll failed: HTTP ${res.status}`);
    const body: unknown = await res.json().catch(() => null);
    if (!body || typeof body !== 'object') return [];
    const inners = (body as { inners?: unknown }).inners;
    if (!Array.isArray(inners)) return [];
    // defensively keep only object-shaped inners — a hostile/garbled entry is dropped, not opened
    return inners.filter(
      (x): x is StrippedInner => !!x && typeof x === 'object' && !Array.isArray(x),
    );
  },
};

// ── Compose / decompose ──────────────────────────────────────────────────────────────────────────────────

export interface SealForRouteArgs {
  /** The cleartext payload (e.g. a signed visible-affirm). MUST fit one cell (<= FRAME_MAX_PAYLOAD) or
   *  frameUniform throws — a silent truncation of a signed payload would verify wrong, so it is a hard fail. */
  payload: Uint8Array;
  frameType: FrameType;
  /** Recipient DEVICE mailbox public keys — the K0 inner seal target (only they can open it). */
  recipientDevice: MailboxPublicKeys;
  /** Satellite routing public keys — the K0 OUTER seal target (the satellite peels, cannot read the inner). */
  satellite: MailboxPublicKeys;
  /** Blinded rotating K1 route_id (32 lowercase hex) for this sender→recipient direction + window. */
  routeId: string;
}

/**
 * Seal ONE payload into a wire-ready OUTER onion cell for a recipient on a route. Composes the full stack:
 * frameUniform → sealToMailbox(device) → sealOnion(satellite, routeId). Fail-closed by propagation: any throw
 * (oversize payload, unknown frame type, bad key length, bad route_id) means NOTHING is emitted — the caller
 * must not fall back to an unsealed send. Enqueue the result on a CadenceEmitter; do not deposit it directly.
 */
export async function sealForRoute(args: SealForRouteArgs): Promise<MailboxEnvelopePackage> {
  const { payload, frameType, recipientDevice, satellite, routeId } = args;
  if (!isValidRouteId(routeId)) throw new Error('sealForRoute: invalid route_id');
  const cell = frameUniform(payload, frameType); // throws on oversize / unknown type — no silent truncation
  const inner = await sealToMailbox(cell, recipientDevice); // K0 inner (device seal); throws on bad key length
  return sealOnion(inner, satellite, routeId); // K0 outer (satellite seal) + K1 route
}

export interface ReceiveFromRouteArgs {
  routeId: string;
  /** The recipient's OWN device mailbox secret keys (openOnionInner). */
  deviceSecrets: MailboxSecretKeys;
  /** The recipient's OWN mailbox_fp (re-inserted at open; the satellite never saw it — K0-1 blinding). */
  deviceMailboxFpHex: string;
  /** Optional kind filter — keep only cells of this FrameType (e.g. 'visible-affirm'). */
  frameType?: FrameType;
  /** Injectable relay for tests; defaults to the real httpOnionRelay. */
  relay?: Pick<typeof httpOnionRelay, 'poll'>;
}

/**
 * Poll a route and recover every openable cell for this device. FULLY FAIL-CLOSED (never throws to the caller):
 * a bad route_id, a transport error, a non-openable inner (not ours / tampered), a malformed frame, or a
 * wrong-kind cell are each DROPPED and surface nothing. Under-reveal is the safe failure for every one of them
 * (an affirmative you can't read just isn't shown → you under-reveal a mutual, never over-reveal to a blocked
 * party). Returns the recovered { type, payload } cells, optionally filtered to one kind.
 */
export async function receiveFromRoute(
  args: ReceiveFromRouteArgs,
): Promise<Array<{ type: FrameType; payload: Uint8Array }>> {
  const { routeId, deviceSecrets, deviceMailboxFpHex, frameType } = args;
  const relay = args.relay ?? httpOnionRelay;
  if (!isValidRouteId(routeId)) return []; // fail-closed: never poll a malformed id

  let inners: StrippedInner[];
  try {
    inners = await relay.poll(routeId);
  } catch {
    return []; // transport error → surface nothing (under-reveal, the safe failure)
  }

  const out: Array<{ type: FrameType; payload: Uint8Array }> = [];
  for (const inner of inners) {
    let cell: Uint8Array | null;
    try {
      cell = await openOnionInner(inner, deviceSecrets, deviceMailboxFpHex);
    } catch {
      continue; // never throw on a hostile inner
    }
    if (cell === null) continue; // not ours / tamper
    const framed = unframeUniform(cell);
    if (framed === null) continue; // malformed cell
    if (frameType !== undefined && framed.type !== frameType) continue; // wrong kind
    out.push(framed);
  }
  return out;
}

// ── Route-id convenience ─────────────────────────────────────────────────────────────────────────────────

export interface RouteIdForPeerArgs {
  /** s_AB — the mutual shared secret for this pair (mutual-trust.ts deriveSharedSecret). NOT retained by the
   *  ratchet; used only to derive the window's root ratchet key. */
  rootSecret: Uint8Array;
  /** My fingerprint (sender). */
  senderFp: string;
  /** The peer's fingerprint (recipient). directionTag binds a stable per-direction root; throws if equal. */
  recipientFp: string;
  /** The ratchet anchor window (the window the pair's root was anchored at). */
  anchorWindow: number;
  /** Optional "now" window index; defaults to the current wall-clock window (currentWindowIndex). */
  nowWindow?: number;
}

/**
 * Derive the current-window blinded route_id for a sender→recipient direction: directionTag → RouteRatchet.init
 * (fast-forwarded to now) → currentRouteId(). The recipient derives the OPPOSITE direction's ratchet to know
 * which route to poll. Convenience only — a caller holding a RouteRatchet instance can call currentRouteId()
 * directly (and should, to advance windows and rekey on PCS events).
 */
export function routeIdForPeer(args: RouteIdForPeerArgs): string {
  const dir = directionTag(args.senderFp, args.recipientFp);
  return RouteRatchet.init(args.rootSecret, dir, args.anchorWindow, args.nowWindow).currentRouteId();
}

// ── §F5 cadence emitter (cover→real swap) ────────────────────────────────────────────────────────────────

export interface CadenceEmitterOpts {
  /**
   * Produce a fully-sealed OUTER cover cell for an IDLE slot. INJECTED (not defaulted) so the cover threat
   * model — which route/recipient a cover rides, what 'cover'-framed payload it carries — lives with the
   * integration (piece-2 / distress / consent-delta), not baked into the transport. A cover is a real,
   * well-formed onion cell indistinguishable on the wire from a real emit; typically frameUniform(coverBytes,
   * 'cover') sealed to a self/decoy route. Thrown/rejected → that slot simply emits nothing (no crash).
   */
  makeCover: () => Promise<MailboxEnvelopePackage> | MailboxEnvelopePackage;
  /** Deposit fn; defaults to httpOnionRelay.deposit. Injectable for tests. */
  deposit?: (outer: MailboxEnvelopePackage) => Promise<void>;
  /**
   * Max real cells held pending. When exceeded, the OLDEST real cell is dropped (bounded memory; a dropped
   * affirmative under-reveals = safe, and an emit path that re-filters fresh every pass re-enqueues it next
   * round — never a permanent silent loss). Default 1024.
   */
  maxQueue?: number;
}

/**
 * The §F5 cover→real swap engine. Callers ENQUEUE real sealed OUTER cells; the engine drains EXACTLY ONE cell
 * per cadence slot (a real cell if queued, else a fresh cover cell), so real traffic trickles across slots
 * indistinguishably from the uniform cover baseline instead of bursting. `drainSlot()` is the pure mechanism
 * (test it directly with an injected deposit + no timers); `start()/stop()` is the thin, gated runner.
 */
export class CadenceEmitter {
  private readonly queue: MailboxEnvelopePackage[] = [];
  private readonly makeCover: CadenceEmitterOpts['makeCover'];
  private readonly deposit: (outer: MailboxEnvelopePackage) => Promise<void>;
  private readonly maxQueue: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private running = false;

  constructor(opts: CadenceEmitterOpts) {
    this.makeCover = opts.makeCover;
    this.deposit = opts.deposit ?? httpOnionRelay.deposit;
    this.maxQueue = opts.maxQueue ?? 1024;
  }

  /** Enqueue a real sealed OUTER cell (from sealForRoute) to ride the next cadence slot. The fan-out path
   *  enqueues one per non-suppressed recipient and lets the cadence drain them — it MUST NOT deposit directly
   *  (a direct per-recipient deposit is the burst §F5 forbids). Drops the oldest if over maxQueue. */
  enqueue(outer: MailboxEnvelopePackage): void {
    this.queue.push(outer);
    while (this.queue.length > this.maxQueue) this.queue.shift(); // bounded; oldest-dropped under-reveals
  }

  /** Number of real cells currently pending. */
  pending(): number {
    return this.queue.length;
  }

  /**
   * Emit ONE cell for one cadence slot: a queued real cell if present, else a fresh cover cell. This is the
   * cover→real swap — on the wire a real emit is identical to a cover emit (same /onion path, same 2048B cell,
   * same slot timing). Returns whether a real cell rode this slot. Deposit errors are SWALLOWED (a failed emit
   * leaks nothing = under-reveal, the safe failure); the real cell is not re-queued here — the emit path
   * re-filters fresh and re-enqueues next pass, so a dropped affirmative re-emits without a burst-retry.
   */
  async drainSlot(): Promise<{ emittedReal: boolean }> {
    const real = this.queue.shift();
    const emittedReal = real !== undefined;
    let outer: MailboxEnvelopePackage;
    try {
      outer = emittedReal ? (real as MailboxEnvelopePackage) : await this.makeCover();
    } catch {
      return { emittedReal: false }; // couldn't build a cell this slot — skip, no emit
    }
    try {
      await this.deposit(outer);
    } catch {
      // under-reveal: a failed deposit leaks nothing (and re-deposit is idempotent server-side anyway)
    }
    return { emittedReal };
  }

  /**
   * ★ GATED INTEGRATION SEAM (§8-DEPLOYED). Drive drainSlot on the uniform baseline cadence: one slot every
   * `periodMs` with optional bounded jitter in [0, periodMs) — the streaming form of planCoverCadence (one
   * slot per period, jitter below the period so slots never reorder). SSR-safe: a no-op where setTimeout is
   * absent. Idempotent: a second start() while running is ignored. This exists so the mechanism is drivable
   * and the seam is explicit; wiring it always-on for all users is the ship-time Flint §8 + Peter call —
   * cadence-indistinguishability is not LIVE until it runs on the deployed edge.
   */
  start(opts: { periodMs: number; jitterMs?: number; random?: Random }): void {
    if (this.running) return;
    const { periodMs } = opts;
    const jitterMs = opts.jitterMs ?? 0;
    const random = opts.random ?? cryptoRandom;
    if (!(periodMs > 0) || !Number.isFinite(periodMs)) throw new Error('cadence: periodMs must be > 0');
    if (!(jitterMs >= 0) || jitterMs >= periodMs) throw new Error('cadence: jitterMs must be in [0, periodMs)');
    if (typeof setTimeout !== 'function') return; // SSR / non-DOM — nothing to drive
    this.running = true;
    const tick = () => {
      if (!this.running) return;
      const delay = periodMs + (jitterMs > 0 ? random() * jitterMs : 0);
      this.timer = setTimeout(() => {
        void this.drainSlot().finally(tick); // one slot, then re-arm — never two in flight
      }, delay);
    };
    tick();
  }

  /** Stop the runner (clears the pending slot timer). Queued cells remain for a later start()/drainSlot(). */
  stop(): void {
    this.running = false;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }
}
