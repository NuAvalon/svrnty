// src/lib/sync/consent-delta-transport.ts
/**
 * Consent-delta TRANSPORT — wires the EMIT/APPLY crypto leaves (consent-delta-emit.ts, reviewed-green
 * 10/10, NOT touched by this file) onto the ALREADY-DEPLOYED S1 blind relay (POST /onion, GET
 * /route/{route_id}): deposit a sealed outer cell, and poll+open+unframe+apply inbound ones.
 *
 * GROUNDING (file:line, read before writing a line of this module):
 *   - emitConsentDelta / applyInboundConsentDelta ... consent-delta-emit.ts:129 / :242 (UNMODIFIED — this
 *     file only calls them; the two forbidden crypto leaves)
 *   - onion seal/peel/open ........................... onion-envelope.ts sealOnion:65 / peelOnion:82 /
 *     openOnionInner:116 — ★ peelOnion needs the SATELLITE's secret keys (peelOnion(outer, satelliteSecrets,
 *     satelliteMailboxFpHex)) and is the SATELLITE's own operation, not a client one. The consent-delta-
 *     emit.test.ts "(DELIVERY)" test (line 280-315) proves the real pipeline: the RELAY calls peelOnion
 *     server-side, and only the DEVICE calls openOnionInner on what the relay hands back. The task brief
 *     that spawned this file said "peelOnion ... → unframeUniform" for the CONSUME side; that is corrected
 *     here to openOnionInner (see DELIVERABLE REPORT) — calling peelOnion client-side would require the
 *     client to hold the satellite's secret keys, which defeats the entire blind-relay design.
 *   - uniform frame recovery ......................... uniform-frame.ts unframeUniform:130 (operates on the
 *     openOnionInner PLAINTEXT, never on wire bytes — see uniform-frame.ts:124-128 doc)
 *   - K1 route-ratchet (real, rotating route_id) ..... route-ratchet.ts RouteRatchet:129, directionTag:88,
 *     currentWindowIndex:80; the root secret is mutual-trust.ts deriveSharedSecret:63 (the SAME X25519 DH
 *     already used live by trust-rendezvous.ts:169/242/268 for an unrelated channel — "nothing to wire,
 *     just compute it" per the coordinator's grounding). See ★★★ ROUTE_ID GROUNDING below — this is the
 *     single most load-bearing finding in this file; read it before changing anything route-id-shaped.
 *   - S1 blind relay (POST /onion, GET /route/{route_id}) — per the security owner: /onion peels the outer
 *     and deposits the (opaque-to-the-relay) inner into a route_bucket keyed by route_id; the inner is
 *     BLIND to a peer's route_id, no satellite change needed. NO server code for this exists anywhere in
 *     this repo (grepped clean across every branch, including main) — the S1 relay is external to this
 *     Next.js client codebase (consistent with mailbox-registry-client.ts's "satellite.py:1092" citations:
 *     the satellite is a separate server). So, unlike httpMailboxRegistry/httpTrustRelay (which cite an
 *     Athena issue number + exact wire shape), the wire shape below is this file's OWN best-grounded
 *     reconstruction from the task brief's prose ("/onion", "GET /route/{route_id}", "arbitrary sealed
 *     inner cell"), NOT a byte-pinned contract — flagged in the deliverable report as unconfirmed.
 *
 * ★★★ ROUTE_ID GROUNDING (read this before using deriveRotatingRouteId in anything beyond a same-session
 * demo) — the deciding question was: is a REAL per-contact K1 route_id available client-side, or only
 * emitConsentDelta's DEFAULT_ROUTE placeholder (consent-delta-emit.ts: literal constant 'consent-delta-v1'
 * for every peer — not per-pair, not rotating)?
 *
 *   1. The INPUT (s_AB, the per-contact route-root secret) IS available, with zero new wiring: it is
 *      exactly mutual-trust.ts's deriveSharedSecret(myEdPriv, peerEdPub) — the SAME call trust-rendezvous.ts
 *      already makes for a different channel. Any VERIFY'd contact (the exact set a go-private/unfriend
 *      revocation targets) has the peer's Ed25519 pubkey on hand.
 *   2. The DERIVATION CHAIN (s_AB → directionTag → deriveRootRatchetKey → advanceRatchetKey× → deriveRouteId)
 *      is exported, tested, and reused UNMODIFIED here (RouteRatchet class, route-ratchet.ts:129).
 *   3. ★ THE ACTUAL BLOCKER, found by grounding (not assumed): route-ratchet.ts's ONLY public entry point,
 *      RouteRatchet.init(rootSecret, dir, anchorWindow, nowWindow), walks FORWARD one HKDF hop per elapsed
 *      window from `anchorWindow` to `nowWindow` (route-ratchet.ts:149-161, advanceTo:174-181) — there is no
 *      O(1) "jump to window W" primitive (by design: a hash ratchet's one-wayness, the FS mechanism, is
 *      exactly what makes random access impossible). So:
 *        - anchorWindow = 0 (a fixed protocol epoch) ⇒ CORRECT but walks ~497,000 hops as of today
 *          (ROUTE_WINDOW_SECONDS=3600 ⇒ ⌊Date.now()/1000/3600⌋). MEASURED: 89.7 SECONDS for one derivation
 *          on this hardware (benchmarked directly against route-ratchet.ts, not estimated) — not viable to
 *          call live on a deposit/consume path.
 *        - anchorWindow = nowWindow, recomputed fresh every call ⇒ INSTANT, but deriveRootRatchetKey has no
 *          window dependence, so this returns the IDENTICAL value forever — zero rotation, defeating K1's
 *          entire point.
 *      The chain is only CHEAP in steady state (small `nowWindow - anchorWindow`), which requires a
 *      PERSISTED per-contact-direction ratchet checkpoint (anchor once, advance by a few hops thereafter) —
 *      exactly what route-ratchet.ts's own SCOPE note (line 48) defers as "a separate reviewable unit"
 *      ("wiring route_id into the ... send/register path"). That durable checkpoint store does not exist
 *      anywhere in this codebase (grepped: zero production callers of route-ratchet.ts prior to this file).
 *   4. WHAT THIS FILE ACTUALLY DOES (deriveRotatingRouteId, below): bootstraps a RouteRatchet instance
 *      anchored AT THE CURRENT WINDOW the first time a given (peer, direction) needs one (zero-hop, instant
 *      — real math, no new crypto), caches the live INSTANCE (not raw bytes) in an injectable in-memory
 *      cache, and calls .advanceTo() on subsequent calls (cheap incremental hops). This is the REAL K1
 *      chain, correctly composed, and is CORRECT for two parties who both first touch a given pair within
 *      the same ROUTE_WINDOW_SECONDS (1h) window — i.e. exactly a live, back-to-back deposit→consume demo
 *      in one process/session, which is what this file's tests and the live round-trip prove.
 *      ★ IT DOES NOT YET SOLVE THE GENERAL CASE: two independent clients who bootstrap at different real
 *      moments (e.g. the recipient's device is offline when I go private, and first polls hours later) will
 *      anchor at DIFFERENT windows and derive UNRELATED route_ids — not "slightly off", cryptographically
 *      unrelated (advanceRatchetKey chains don't converge). Fixing that needs a durable, MUTUALLY-AGREED
 *      anchor — the natural, already-available candidate is mutual-trust.ts's epoch_week /
 *      TrustCommitment.established semantics (both parties already compute that identically during mutual-
 *      trust establishment, with zero new wire negotiation) — but wiring that is a new, reviewable surface
 *      (persistence schema, bootstrap-for-existing-contacts, cross-device sync) and is OUT OF SCOPE here.
 *      TREAT deriveRotatingRouteId AS A SAME-SESSION/DEMO-GRADE REAL DERIVATION, NOT YET A PRODUCTION
 *      ROUTING LAYER. See the deliverable report for the explicit recommendation.
 *
 * SCOPE: this file = transport (HTTP deposit/poll) + the route_id derivation helper. It does not modify
 * consent-delta-emit.ts's two crypto leaves, and does not implement durable ratchet-checkpoint persistence.
 */
import {
  emitConsentDelta,
  applyInboundConsentDelta,
  type ConsentWithdrawal,
  type EmitPeerTarget,
  type EmitConsentDeltaResult,
  type ApplyConsentDeltaDeps,
} from './consent-delta-emit.js';
import { openOnionInner, type StrippedInner } from '../crypto/onion-envelope.js';
import { unframeUniform } from '../crypto/uniform-frame.js';
import type { MailboxPublicKeys, MailboxSecretKeys, MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';
import { deriveSharedSecret } from '../crypto/mutual-trust.js';
import { directionTag, currentWindowIndex, RouteRatchet } from '../crypto/route-ratchet.js';

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// TRANSPORT — the injected relay interface over the S1 blind relay, mirroring the existing
// httpTrustRelay (trust-rendezvous.ts:80) / httpMailboxRegistry (mailbox-registry-client.ts:110)
// convention: a small injected interface + a concrete http* factory, fail-soft, injectable fetchImpl.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/** Injected transport over the S1 blind relay's two endpoints. */
export interface OnionRelay {
  /** POST /onion — deposit one onion-sealed OUTER cell. The relay peels it with ITS OWN keys and buckets
   *  the (still device-sealed) inner by the route_id it finds inside — opaque to this interface. */
  deposit(cell: MailboxEnvelopePackage): Promise<boolean>;
  /** GET /route/{routeId} — return the inner cells currently buffered at this route_id (already peeled by
   *  the relay; each is a StrippedInner, i.e. a MailboxEnvelopePackage minus mailbox_fp, per K0-1). */
  poll(routeId: string): Promise<StrippedInner[]>;
}

function looksLikeStrippedInner(x: unknown): x is StrippedInner {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    typeof o.alg === 'string' &&
    typeof o.epk === 'string' &&
    typeof o.kem_ct === 'string' &&
    typeof o.nonce === 'string' &&
    typeof o.ct === 'string'
  );
}

/**
 * Concrete OnionRelay over the S1 blind relay (★ wire shape is this file's best-grounded reconstruction
 * from the task brief, NOT a byte-pinned contract — see module header; no server code for /onion or /route
 * exists in this repo to pin against, unlike httpTrustRelay/httpMailboxRegistry which cite an Athena issue):
 *   POST {satelliteUrl}/onion        body = the sealed cell (MailboxEnvelopePackage) itself, no wrapper
 *                                     (mirrors httpMailboxRegistry.register, which POSTs its fields bare).
 *   GET  {satelliteUrl}/route/{id}   → { cells: StrippedInner[] } (a bare array is also tolerated, in case
 *                                     the real contract returns one — defensive, not a confirmed fallback).
 * Fail-soft like every other relay client here: a non-2xx/throw deposit → false; a failed/malformed poll →
 * [] (never throws — the caller re-polls next tick; a hostile/malformed per-cell entry is filtered here,
 * before it ever reaches openOnionInner).
 */
export function httpOnionRelay(satelliteUrl: string, fetchImpl: typeof fetch = fetch): OnionRelay {
  const base = satelliteUrl.replace(/\/$/, '');
  return {
    async deposit(cell) {
      try {
        const res = await fetchImpl(`${base}/onion`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cell),
        });
        return res.ok;
      } catch {
        return false;
      }
    },
    async poll(routeId) {
      try {
        const res = await fetchImpl(`${base}/route/${encodeURIComponent(routeId)}`);
        if (!res.ok) return [];
        const j = (await res.json()) as unknown;
        const raw = Array.isArray(j) ? j : Array.isArray((j as { cells?: unknown })?.cells) ? (j as { cells: unknown[] }).cells : [];
        return raw.filter(looksLikeStrippedInner);
      } catch {
        return [];
      }
    },
  };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// DEPOSIT — emitConsentDelta (untouched) → POST each sealed cell to the relay.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

export interface DepositConsentDeltasArgs {
  relay: OnionRelay;
  withdrawal: ConsentWithdrawal;
  peers: EmitPeerTarget[];
  signerSeed: Uint8Array;
  satellite: MailboxPublicKeys;
}

export interface DepositConsentDeltasResult {
  /** Peers whose sealed cell was successfully POSTed to the relay. */
  deposited: Array<{ fingerprint: string; route: string }>;
  /** Peers emitConsentDelta sealed fine, but the relay deposit call failed (network/non-2xx) — fail-soft
   *  per-peer, mirrors emitConsentDelta's own fail-closed-per-recipient contract. */
  failed: Array<{ fingerprint: string; route: string; reason: 'relay-deposit-failed' }>;
  /** Passthrough of emitConsentDelta's own per-peer skip accounting (bad-fingerprint/bad-epoch/seal-failed). */
  skipped: EmitConsentDeltaResult['skipped'];
}

/**
 * On a go-private/unfriend trigger: call the UNMODIFIED emitConsentDelta to get the per-peer onion-sealed
 * cells, then POST each to the S1 /onion endpoint. A BLOCK withdrawal throws INSIDE emitConsentDelta before
 * this function ever sees a cell or touches the relay — this function does not catch that throw, so "block
 * never deposits" is inherited unweakened from the crypto leaf, not re-implemented here.
 */
export async function depositConsentDeltas(args: DepositConsentDeltasArgs): Promise<DepositConsentDeltasResult> {
  const { deposits, skipped } = await emitConsentDelta({
    withdrawal: args.withdrawal,
    peers: args.peers,
    signerSeed: args.signerSeed,
    satellite: args.satellite,
  });

  const deposited: DepositConsentDeltasResult['deposited'] = [];
  const failed: DepositConsentDeltasResult['failed'] = [];
  for (const d of deposits) {
    let ok = false;
    try {
      ok = await args.relay.deposit(d.cell);
    } catch {
      ok = false;
    }
    if (ok) deposited.push({ fingerprint: d.fingerprint, route: d.route });
    else failed.push({ fingerprint: d.fingerprint, route: d.route, reason: 'relay-deposit-failed' });
  }
  return { deposited, failed, skipped };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// CONSUME — poll each known contact's dedicated route bucket → open → unframe → apply.
//
// Because the REAL derived route_id (below) is pair-specific (s_AB is unique per contact), each contact
// has their OWN "them→me" bucket — this loops per contact (mirrors the existing per-contact loop
// convention: trust-rendezvous.ts pollForPeerTrust, know-layer-sync.ts runPsiCompletionPass), not a
// try-every-pubkey-against-every-cell scan. If the caller is still on emitConsentDelta's DEFAULT_ROUTE
// placeholder, every contact's `routeId` can simply be that same literal — the loop still works (and in
// that fallback mode a hostile/foreign cell is simply rejected at applyInboundConsentDelta's signature
// check, never mis-attributed to the wrong contact).
// ════════════════════════════════════════════════════════════════════════════════════════════════════

export interface ConsumeContactCandidate {
  /** The LOCAL book identifier for this contact — passed straight through to applyMutualResult. */
  peerFingerprint: string;
  /** This contact's identity Ed25519 signing pubkey — verifies their consent-delta signature. */
  signerSignPub: Uint8Array;
  /** Highest epoch already accepted from this contact (§6a anti-rollback; -1 if none ever accepted). */
  lastSeenEpoch: number;
  /** The route_id to GET /route/{routeId} for cells FROM this contact TO me. */
  routeId: string;
}

export interface ConsumeConsentDeltasArgs {
  relay: OnionRelay;
  contacts: ConsumeContactCandidate[];
  myDeviceSecrets: MailboxSecretKeys;
  myDeviceMailboxFpHex: string;
  /** The verifier's OWN stable identity fingerprint bytes (consent-delta.ts recipientBinding contract). */
  myRecipientBinding: Uint8Array;
  deps: ApplyConsentDeltaDeps;
}

export type ConsumeSkipReason =
  | 'relay-poll-failed'
  | 'open-failed'
  | 'not-consent-delta'
  | 'verify-failed'
  | 'unhandled-type'
  | 'apply-failed';

export interface ConsumeConsentDeltasResult {
  applied: Array<{ peerFingerprint: string; epoch: number }>;
  skipped: Array<{ peerFingerprint: string; reason: ConsumeSkipReason }>;
}

/**
 * Poll every candidate contact's route bucket, and for each returned cell: openOnionInner (device-side —
 * NOT peelOnion, see module header ★) → unframeUniform → if type === 'consent-delta', applyInboundConsentDelta
 * (UNMODIFIED). Never throws on hostile/malformed input at ANY stage — a bad cell is skipped with a reason,
 * and the batch (this contact's remaining cells, and every other contact) continues.
 */
export async function consumeConsentDeltas(args: ConsumeConsentDeltasArgs): Promise<ConsumeConsentDeltasResult> {
  const applied: ConsumeConsentDeltasResult['applied'] = [];
  const skipped: ConsumeConsentDeltasResult['skipped'] = [];

  for (const contact of args.contacts) {
    let cells: StrippedInner[];
    try {
      cells = await args.relay.poll(contact.routeId);
    } catch {
      skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'relay-poll-failed' });
      continue;
    }

    for (const inner of cells) {
      let opened: Uint8Array | null;
      try {
        opened = await openOnionInner(inner, args.myDeviceSecrets, args.myDeviceMailboxFpHex);
      } catch {
        opened = null;
      }
      if (!opened) {
        skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'open-failed' });
        continue;
      }

      const framed = unframeUniform(opened);
      if (!framed || framed.type !== 'consent-delta') {
        skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'not-consent-delta' });
        continue;
      }

      let outcome: Awaited<ReturnType<typeof applyInboundConsentDelta>>;
      try {
        outcome = await applyInboundConsentDelta(
          framed.payload,
          contact.signerSignPub,
          {
            recipientBinding: args.myRecipientBinding,
            lastSeenEpoch: contact.lastSeenEpoch,
            peerFingerprint: contact.peerFingerprint,
          },
          args.deps,
        );
      } catch {
        outcome = null;
      }

      if (outcome === null) {
        skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'verify-failed' });
      } else if (outcome.kind === 'applied') {
        applied.push({ peerFingerprint: contact.peerFingerprint, epoch: outcome.epoch });
      } else if (outcome.kind === 'verified-unhandled') {
        skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'unhandled-type' });
      } else {
        skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'apply-failed' });
      }
    }
  }

  return { applied, skipped };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// ROUTE_ID — the REAL K1 derivation (see ★★★ ROUTE_ID GROUNDING above for the full finding). Composition
// only: deriveSharedSecret (mutual-trust.ts) → directionTag/RouteRatchet (route-ratchet.ts). No new crypto.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/** 'outbound' = the "me → contact" channel (what DEPOSIT addresses); 'inbound' = "contact → me" (what
 *  CONSUME polls). These are independent ratchet chains (route-ratchet.ts:73) by design. */
export type RouteDirection = 'outbound' | 'inbound';

/** Caches live RouteRatchet INSTANCES (not raw key bytes) per (peerFp, direction) — advancing the SAME
 *  object over time is what gives real rotation; re-deriving from scratch each call either costs ~90s
 *  (anchor=0) or never rotates (anchor=now every time) — see ★★★ ROUTE_ID GROUNDING. In-memory only: does
 *  NOT survive a process restart, and does NOT solve cross-session anchor agreement (module header ★). */
export interface RouteRatchetCache {
  get(key: string): RouteRatchet | undefined;
  set(key: string, ratchet: RouteRatchet): void;
}

export function createInMemoryRouteRatchetCache(): RouteRatchetCache {
  const m = new Map<string, RouteRatchet>();
  return {
    get: (k) => m.get(k),
    set: (k, v) => void m.set(k, v),
  };
}

export interface DeriveRotatingRouteIdArgs {
  myEdPriv: Uint8Array;
  myFp: string;
  peerEdPub: Uint8Array;
  peerFp: string;
  direction: RouteDirection;
  cache: RouteRatchetCache;
  /** Injectable wall-clock (ms) — defaults to Date.now(). */
  now?: number;
}

/**
 * Derive the REAL rotating K1 route_id for one (contact, direction) pair at the current window.
 *
 * First call for a given (peerFp, direction): bootstraps a RouteRatchet anchored AT the current window
 * (zero hops — instant; `RouteRatchet.init(sAB, dir, nowWindow, nowWindow)`) and caches the instance.
 * Subsequent calls: advances the SAME cached instance forward (cheap — typically 0-few hops since the
 * last call) and reads currentRouteId(). This is CORRECT (byte-identical to what the sender/recipient
 * each independently compute) ONLY when both sides' first bootstrap for this pair falls in the same
 * ROUTE_WINDOW_SECONDS window — i.e. a live, same-session round trip. See ★★★ ROUTE_ID GROUNDING for why
 * the general (asynchronous, cross-restart) case needs a durable, mutually-agreed anchor instead.
 */
export function deriveRotatingRouteId(args: DeriveRotatingRouteIdArgs): string {
  const dir =
    args.direction === 'outbound'
      ? directionTag(args.myFp, args.peerFp)
      : directionTag(args.peerFp, args.myFp);
  const key = `${args.peerFp}:${args.direction}`;
  const nowWindow = currentWindowIndex(args.now ?? Date.now());

  let ratchet = args.cache.get(key);
  if (!ratchet) {
    const sAB = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
    ratchet = RouteRatchet.init(sAB, dir, nowWindow, nowWindow);
    args.cache.set(key, ratchet);
  } else {
    ratchet.advanceTo(nowWindow);
  }
  return ratchet.currentRouteId();
}
