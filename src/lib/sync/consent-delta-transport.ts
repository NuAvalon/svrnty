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
 *   4. v1 OF THIS FILE bootstrapped a RouteRatchet anchored AT "now" on first use per (peer, direction) —
 *      correct only for two parties who happened to first touch a pair within the same ROUTE_WINDOW_SECONDS
 *      window (a same-session demo), NOT the general cross-session case (an offline recipient polling days
 *      later would anchor at a different window and derive a cryptographically UNRELATED route_id — not
 *      "slightly off"). Superseded by the fix below.
 *
 * ★★★ ROUTE_ID GROUNDING v2 (the cross-session fix) — the anchor must be a FIXED point both parties can
 * compute IDENTICALLY, independent of when each happens to run. The coordinator's proposed source,
 * mutual-trust.ts `TrustCommitment.epoch_week` (set once at establishment by buildTrustCommitment), is
 * exactly the right SHAPE of value — but GROUNDING it turned up a real, separate gap (task-2 "STOP and
 * report" case):
 *
 *   • `TrustCommitment` / `buildTrustCommitment` / `submitCommitment` / `checkMutualTrust` (mutual-trust.ts)
 *     are the OLD trust-commit oracle. trust-rendezvous.ts's OWN header (line 5-7) says it
 *     "SUPERSEDES the dead trust-commit oracle (mutual-trust.ts computeCommitment/submitCommitment —
 *     saltless, O(N)-reversible; REMOVED, never re-activated)". Grepped: `TrustCommitment` has ZERO
 *     production callers anywhere in this repo outside mutual-trust.ts's own definitions (and now this
 *     file) — nothing builds one, nothing stores one, nothing threads `.epoch_week` to a contact record.
 *   • The LIVE mutual-trust orchestrator this feature actually sits on (mutual-trust-sync.ts, cited by
 *     consent-delta-emit.ts's own grounding) calls NEITHER mutual-trust.ts's commitment functions NOR
 *     trust-rendezvous.ts's beacon functions (grepped clean) — it uses its own PSI-based mechanism with no
 *     epoch field at all.
 *   • The live per-contact schema (trust/types.ts TrustEdge) has no "mutually-established-at" field either.
 *     `trusted_since` is explicitly UNILATERAL ("when trust was last granted" — i.e. when *I* vouched for
 *     *them*; my `trusted_since` and their `trusted_since` are independently-set, generally DIFFERENT real
 *     moments). `mutual.last_sync` is a rolling "last exchange" timestamp, not a fixed establishment point
 *     — using either would silently reintroduce the exact cross-session mismatch this fix is for, while
 *     LOOKING fixed. trust-rendezvous.ts's `TrustBeacon.epoch` is likewise a rolling current-epoch marker
 *     (recomputed fresh on every rehydrate), not a one-time establishment anchor.
 *
 *   ⇒ THE REAL REMAINING GAP: there is no live, persisted, per-contact, MUTUALLY-SHARED "establishment"
 *   timestamp anywhere in this codebase today, under any name. Fabricating a new store for one here would
 *   be exactly the kind of unreviewed new persistence surface this file has avoided throughout (and route-
 *   ratchet.ts's own SCOPE note at line 48 already defers "wiring route_id into the send/register path" as
 *   a separate reviewable unit).
 *
 *   WHAT THIS FILE DOES INSTEAD: implements the anchor MATH as a generic, explicit input —
 *   `deriveRotatingRouteId` now REQUIRES an `establishedEpochWeek: number` (mutual-trust.ts epoch-week
 *   granularity) and converts it to a route-ratchet window via `epochWeekToAnchorWindow` (604800s/3600s =
 *   168 hourly windows per week — route-ratchet.ts ROUTE_WINDOW_SECONDS=3600, mutual-trust.ts's
 *   EPOCH_WEEK_SECONDS=604800 is NOT exported, so the ratio is mirrored here as a literal — flagged as a
 *   minor drift risk if either constant ever changes independently). `RouteRatchet.init(sAB, dir,
 *   anchorWindow, nowWindow)` is then a PURE function of (sAB, dir, anchorWindow, targetWindow) — EITHER
 *   party can recompute ANY window (the exact one a deposit landed in, or their own current one)
 *   independently, in a fresh process, with NO shared runtime state beyond the (still-missing) shared
 *   epoch_week — proven by the (CROSS-SESSION) test below. The cache (RouteRatchetCache) is kept purely as
 *   a performance optimization (advance an existing instance instead of re-walking from the anchor every
 *   call) — correctness no longer depends on it.
 *
 *   BLOCKER FOR PRODUCTION WIRING: callers cannot yet supply a REAL `establishedEpochWeek` per contact,
 *   because nothing persists one (see gap above). This file's tests inject an explicit value to prove the
 *   math; wiring a real one requires either reviving+actually-calling the commit oracle, adding an
 *   establishment-epoch field to the live mutual-trust-sync/TrustEdge path, or repurposing trust-
 *   rendezvous's beacon epoch into a retained (not rolling) establishment marker — a new, reviewable
 *   decision, out of scope here.
 *
 * SCOPE: this file = transport (HTTP deposit/poll) + the route_id anchor-math derivation helper. It does
 * not modify consent-delta-emit.ts's two crypto leaves, and does not implement per-contact establishment-
 * epoch persistence (the blocker above).
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
import { directionTag, currentWindowIndex, RouteRatchet, ROUTE_WINDOW_SECONDS } from '../crypto/route-ratchet.js';

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

/** Caches live RouteRatchet INSTANCES (not raw key bytes) per (peerFp, direction) — a pure PERFORMANCE
 *  optimization now (advance an existing instance instead of re-walking from the anchor every call);
 *  correctness no longer depends on it (unlike v1) now that the anchor is the fixed establishedEpochWeek,
 *  not "now". In-memory only: does not survive a process restart, but that no longer matters for
 *  correctness either — a fresh cache + the same establishedEpochWeek reproduces the identical route_id
 *  for any target window (proven by the (CROSS-SESSION) test). */
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

/** route-ratchet windows are HOURLY (route-ratchet.ts ROUTE_WINDOW_SECONDS=3600); a mutual-trust epoch_week
 *  is WEEKLY (mutual-trust.ts EPOCH_WEEK_SECONDS=604800 — not exported, mirrored here as a literal ratio;
 *  flagged as a minor drift risk if either constant changes independently). 604800/3600 = 168 hourly
 *  windows per week. */
const ROUTE_WINDOWS_PER_EPOCH_WEEK = 604_800 / ROUTE_WINDOW_SECONDS; // 168

/** Convert a mutual-trust epoch_week (mutual-trust.ts currentEpochWeek() / TrustCommitment.epoch_week — see
 *  ★★★ ROUTE_ID GROUNDING v2 for why no live source of this value exists yet per-contact) into the
 *  equivalent route-ratchet window index: the FIXED, mutually-computable K1 anchor for a contact pair. */
export function epochWeekToAnchorWindow(epochWeek: number): number {
  return epochWeek * ROUTE_WINDOWS_PER_EPOCH_WEEK;
}

export interface DeriveRotatingRouteIdArgs {
  myEdPriv: Uint8Array;
  myFp: string;
  peerEdPub: Uint8Array;
  peerFp: string;
  direction: RouteDirection;
  /** The mutual-trust epoch_week (mutual-trust.ts currentEpochWeek() granularity) this contact pair was
   *  ESTABLISHED in — the FIXED anchor. BOTH parties MUST supply the SAME value for their shared pair (see
   *  ★★★ ROUTE_ID GROUNDING v2: no live per-contact source for this exists yet — tests inject it directly
   *  to prove the derivation math; production wiring is blocked on that gap). */
  establishedEpochWeek: number;
  cache: RouteRatchetCache;
  /** Injectable wall-clock (ms) — defaults to Date.now(). Represents the TARGET window being computed for
   *  (e.g. "now" for a live poll, or a specific past moment to recheck an old bucket during backfill). */
  now?: number;
}

/**
 * Derive the REAL rotating K1 route_id for one (contact, direction) pair at a target window, anchored at
 * `establishedEpochWeek` (converted to a route-ratchet window via epochWeekToAnchorWindow).
 *
 * First call for a given (peerFp, direction) in this cache: bootstraps `RouteRatchet.init(sAB, dir,
 * anchorWindow, targetWindow)` (walks forward from the FIXED anchor — a one-time COLD cost per contact,
 * not per message; MEASURED (isolated-process, this hardware): 1-week-old contact (168 hops) ~86ms,
 * 1-month (730 hops) ~218ms, 6-month (4368 hops) ~919ms, 1-year (8736 hops) ~2.4s, 2-year/TTL-boundary
 * (17472 hops, mutual-trust.ts DEFAULT_TTL_WEEKS=104) ~3.6s — roughly linear in elapsed hops. Sub-second
 * for recent contacts, creeping to a few seconds for very old ones; still 25-1000x faster than the v1
 * anchor-at-0 measurement (89.7s), and a ONE-TIME per-(contact,direction) cost the cache then amortizes —
 * but NOT the "sub-2s even for a year-old contact" originally predicted; flag before relying on it for a
 * synchronous/blocking UI path with many old contacts). Subsequent calls for the SAME cache key: advance
 * the cached instance (cheap incremental hop, milliseconds). Because the
 * anchor is now a value BOTH parties hold identically (once a real source is wired — the open gap), this is
 * CORRECT across independent processes/sessions bootstrapping at arbitrarily different real moments, as
 * long as they agree on establishedEpochWeek and the target window — see the (CROSS-SESSION) test.
 */
export function deriveRotatingRouteId(args: DeriveRotatingRouteIdArgs): string {
  const dir =
    args.direction === 'outbound'
      ? directionTag(args.myFp, args.peerFp)
      : directionTag(args.peerFp, args.myFp);
  const key = `${args.peerFp}:${args.direction}`;
  const targetWindow = currentWindowIndex(args.now ?? Date.now());
  const anchorWindow = epochWeekToAnchorWindow(args.establishedEpochWeek);

  let ratchet = args.cache.get(key);
  if (!ratchet) {
    const sAB = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
    ratchet = RouteRatchet.init(sAB, dir, anchorWindow, targetWindow);
    args.cache.set(key, ratchet);
  } else {
    ratchet.advanceTo(targetWindow);
  }
  return ratchet.currentRouteId();
}
