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
 *   v2's plan: implement the anchor MATH generically, with `establishedEpochWeek` as an explicit REQUIRED
 *   input (not fabricate a new per-contact store). Superseded below by Flint's crypto-blessed interim call.
 *
 * ★★★ ROUTE_ID GROUNDING v3 (Flint-blessed interim: ONE GLOBAL ANCHOR, not per-contact) — since no live
 * per-contact establishment timestamp exists (v2 finding, unchanged), Flint's ruling is: anchor EVERY
 * contact-pair at the SAME fixed, compiled-in constant, `ANCHOR_EPOCH_WEEK` below. This is trivially
 * "mutually computed" — it's not data exchanged over the wire or derived from any per-contact state, it's a
 * literal in the source both parties run, so there is nothing to desync. `deriveRotatingRouteId` no longer
 * takes `establishedEpochWeek` — it always anchors at `ANCHOR_EPOCH_WEEK * 168`, for ALL contacts.
 *
 *   ANCHOR_EPOCH_WEEK = 2961 = floor(Date.now()/1000/604800) computed 2026-10-02 (`node -e
 *   "console.log(Math.floor(Date.now()/1000/604800))"` — NOT the coordinator's ~2909 estimate; use the
 *   measured value). Choosing "now" (launch week) as the anchor means TODAY's hop-from-anchor cost is tiny
 *   (≈40 hops, see benchmark) — but a FIXED constant means that cost only ever GROWS as real time passes
 *   (≈168 more hops every week, forever, since the anchor never moves). This is an INTERIM measure, not a
 *   permanent one — two fast-follows are explicitly NOT built here, flagged per Flint's instruction:
 *     (a) a RE-ANCHOR PROTOCOL to bump ANCHOR_EPOCH_WEEK later without breaking cells deposited/polled
 *         straddling the bump (a hard cutover would silently desync one side mid-transition — e.g. a sender
 *         who updates before a recipient who hasn't would derive from a different anchor than the recipient
 *         still expects; needs an overlap/dual-anchor transition window, not designed here);
 *     (b) a PER-CONTACT establishment anchor (v2's plan) once a mutually-shared timestamp is actually
 *         persisted somewhere (the v2 gap — still open, unchanged by this ruling).
 *
 * ★★★ OFFLINE-POLL-DEPTH (Flint's seal-critical requirement) — a global, non-rotating-relative-to-events
 * anchor fixes CROSS-SESSION MATCHING, but a recipient who was offline during window W and comes back
 * online at W+k must not just poll route_id(W+k) — that's a DIFFERENT bucket than the one the deposit
 * landed in (W). `consumeConsentDeltas` therefore polls the WINDOW RANGE
 * [currentWindow - HORIZON_WINDOWS, currentWindow] per contact (deriveRouteIdWindowRange, below), not just
 * the single current window — see that function's doc for why this is ONE walk from the anchor (not
 * HORIZON_WINDOWS separate walks, which would be catastrophically expensive).
 *
 *   ★ TENSIONS (reported, not silently resolved — Flint/Athena must weigh in):
 *   (a) POLL COST: HORIZON_WINDOWS GETs per contact per catch-up poll (default 336 = 2 weeks of hourly
 *       windows ⇒ up to 336 GETs/contact; 50 contacts ⇒ up to 16,800 GETs in one catch-up cycle). A batch
 *       endpoint (`GET /route?ids=[...]`) would cut this to one request, but a single request naming many
 *       route_ids together RE-LINKS them at the relay/network level — it reveals "all these rotated tags
 *       belong to the same requester polling the same pair across time", exactly the cross-window
 *       unlinkability K1 exists to prevent. So a batch endpoint is probably NOT the right fix. A further,
 *       UNASKED-FOR finding worth flagging alongside it: even WITHOUT a batch endpoint, firing all
 *       HORIZON_WINDOWS GETs back-to-back from the same connection/IP in strict sequential order is ITSELF
 *       a timing/sequence correlation signal to a network observer (if not the relay) — real hardening would
 *       need request jitter/reordering/interleaving with cover traffic (this codebase already has K3
 *       "distress + uniform cover cadence" — distress-cadence.ts — which may be a reusable foundation for
 *       that; not wired here). The practical, NOT-implemented-here optimization for the common case: track
 *       `lastPolledWindow` per contact and only poll `[lastPolledWindow+1, currentWindow]` (capped at
 *       HORIZON_WINDOWS for a never-before-polled/very-stale contact) instead of the full horizon on EVERY
 *       call — this needs a small persisted-per-contact-poll-cursor, another new storage surface, deferred.
 *   (b) RELAY RETENTION: for the catch-up range to find a stale deposit, the relay's /route bucket for
 *       route_id(W) MUST still exist (not expired/GC'd) by the time an offline recipient polls it at W+k,
 *       for k up to HORIZON_WINDOWS. This is a RELAY-SIDE (Athena) requirement to flag explicitly: the S1
 *       relay must retain a bucket for at least HORIZON_WINDOWS hours (2 weeks, at the default), or a
 *       deposit silently expires before an offline recipient can ever see it — the exact silent-failure
 *       this whole mechanism exists to close. Not implementable from this client-only repo.
 *
 * SCOPE: this file = transport (HTTP deposit/poll) + the route_id anchor-math + window-range derivation. It
 * does not modify consent-delta-emit.ts's two crypto leaves, does not implement a re-anchor protocol, a
 * per-contact establishment anchor, a poll-cursor optimization, or relay-side retention (all flagged above).
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
import {
  directionTag,
  currentWindowIndex,
  RouteRatchet,
  ROUTE_WINDOW_SECONDS,
  deriveRootRatchetKey,
  advanceRatchetKey,
  deriveRouteId,
} from '../crypto/route-ratchet.js';

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
// CONSUME — for each known contact, poll the WINDOW RANGE of their dedicated route bucket (★
// OFFLINE-POLL-DEPTH, module header) → open → unframe → apply.
//
// Because the REAL derived route_id is pair-specific (s_AB is unique per contact), each contact has their
// OWN "them→me" bucket sequence — this loops per contact (mirrors the existing per-contact loop convention:
// trust-rendezvous.ts pollForPeerTrust, know-layer-sync.ts runPsiCompletionPass), not a
// try-every-pubkey-against-every-cell scan. The route_id(s) to poll are DERIVED here (not caller-supplied)
// because the offline catch-up range needs the contact's pubkey + the shared anchor, not a single
// precomputed string — see deriveRouteIdWindowRange below.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

export interface ConsumeContactCandidate {
  /** The LOCAL book identifier for this contact — passed straight through to applyMutualResult. */
  peerFingerprint: string;
  /** This contact's identity Ed25519 pubkey — BOTH verifies their consent-delta signature AND (via
   *  deriveSharedSecret's X25519 conversion) derives the K1 route_id range for their "them→me" bucket. */
  signerSignPub: Uint8Array;
  /** Highest epoch already accepted from this contact (§6a anti-rollback; -1 if none ever accepted). */
  lastSeenEpoch: number;
}

export interface ConsumeConsentDeltasArgs {
  relay: OnionRelay;
  contacts: ConsumeContactCandidate[];
  /** My raw Ed25519 seed — needed here (not just at deposit time) to derive each contact's inbound
   *  route_id range via deriveSharedSecret(myEdPriv, contact.signerSignPub). */
  myEdPriv: Uint8Array;
  myFp: string;
  myDeviceSecrets: MailboxSecretKeys;
  myDeviceMailboxFpHex: string;
  /** The verifier's OWN stable identity fingerprint bytes (consent-delta.ts recipientBinding contract). */
  myRecipientBinding: Uint8Array;
  deps: ApplyConsentDeltaDeps;
  /** How many past hourly windows to catch up on, per contact (★ OFFLINE-POLL-DEPTH). Defaults to
   *  HORIZON_WINDOWS. Injectable so callers/tests can tune the cost/coverage tradeoff explicitly. */
  horizonWindows?: number;
  /** Injectable wall-clock (ms) — defaults to Date.now(). The END of the catch-up range (the range is
   *  [currentWindow(now) - horizonWindows, currentWindow(now)]). */
  now?: number;
}

export type ConsumeSkipReason =
  | 'route-derivation-failed'
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
 * For every candidate contact, derive their inbound route_id WINDOW RANGE (deriveRouteIdWindowRange —
 * covers a while-offline deposit, ★ OFFLINE-POLL-DEPTH) and poll each bucket in it; for each returned
 * cell: openOnionInner (device-side — NOT peelOnion, see module header ★) → unframeUniform → if
 * type === 'consent-delta', applyInboundConsentDelta (UNMODIFIED). Never throws on hostile/malformed input
 * at ANY stage — a bad cell is skipped with a reason, and the batch (this contact's remaining windows/
 * cells, and every other contact) continues. Re-polling an already-applied window on a later catch-up is
 * harmless — applyInboundConsentDelta's own §6a monotonic check makes a repeat a no-op, PROVIDED the caller
 * updates `lastSeenEpoch` between poll cycles (same contract as before; this function does not persist it).
 */
export async function consumeConsentDeltas(args: ConsumeConsentDeltasArgs): Promise<ConsumeConsentDeltasResult> {
  const applied: ConsumeConsentDeltasResult['applied'] = [];
  const skipped: ConsumeConsentDeltasResult['skipped'] = [];
  const horizonWindows = args.horizonWindows ?? HORIZON_WINDOWS;

  for (const contact of args.contacts) {
    let routeIds: string[];
    try {
      routeIds = deriveRouteIdWindowRange({
        myEdPriv: args.myEdPriv,
        myFp: args.myFp,
        peerEdPub: contact.signerSignPub,
        peerFp: contact.peerFingerprint,
        direction: 'inbound',
        horizonWindows,
        now: args.now,
      });
    } catch {
      skipped.push({ peerFingerprint: contact.peerFingerprint, reason: 'route-derivation-failed' });
      continue;
    }

    let cells: StrippedInner[] = [];
    let pollFailed = false;
    for (const routeId of routeIds) {
      try {
        cells = cells.concat(await args.relay.poll(routeId));
      } catch {
        pollFailed = true;
        break; // a relay failure on one window of this contact's range is treated as systemic for them —
        // move on to the NEXT CONTACT rather than spamming one skip entry per remaining window.
      }
    }
    if (pollFailed) {
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

/** Convert an epoch-week (mutual-trust.ts currentEpochWeek() granularity) into the equivalent
 *  route-ratchet window index. Used ONLY for the one GLOBAL `ANCHOR_EPOCH_WEEK` below (★★★ ROUTE_ID
 *  GROUNDING v3) — NOT per-contact (v2's per-contact plan is superseded; the gap it was blocked on is
 *  unchanged and still open). */
export function epochWeekToAnchorWindow(epochWeek: number): number {
  return epochWeek * ROUTE_WINDOWS_PER_EPOCH_WEEK;
}

/** THE global, fixed, Flint-blessed K1 anchor (★★★ ROUTE_ID GROUNDING v3) — a compiled-in constant every
 *  client shares by construction, not data exchanged or derived per-contact.
 *  = floor(Date.now() / 1000 / 604800), computed 2026-10-02 via:
 *    `node -e "console.log(Math.floor(Date.now()/1000/604800))"` → 2961
 *  (the coordinator's estimate was ~2909; this is the measured value — use it, not the estimate).
 *  ★ FAST-FOLLOWS, NOT built here (see module header for the full tension writeup): (a) a re-anchor
 *  protocol to bump this without breaking cells straddling the bump; (b) replace with a per-contact
 *  establishment anchor once a mutually-shared timestamp is actually persisted somewhere (still absent). */
export const ANCHOR_EPOCH_WEEK = 2961;

/** How many past hourly windows consumeConsentDeltas catches up on by default (★ OFFLINE-POLL-DEPTH).
 *  336 = 2 weeks of hourly windows. Named/exported so callers can override per their own
 *  cost/coverage tradeoff (see module header ★ TENSIONS — this is NOT free: up to 336 GETs/contact). */
export const HORIZON_WINDOWS = 336;

export interface DeriveRotatingRouteIdArgs {
  myEdPriv: Uint8Array;
  myFp: string;
  peerEdPub: Uint8Array;
  peerFp: string;
  direction: RouteDirection;
  cache: RouteRatchetCache;
  /** Injectable wall-clock (ms) — defaults to Date.now(). Represents the TARGET window being computed for
   *  (e.g. "now" for a live poll, or a specific past moment to recheck an old bucket during backfill). */
  now?: number;
}

/**
 * Derive the REAL rotating K1 route_id for one (contact, direction) pair at a target window, anchored at
 * the GLOBAL `ANCHOR_EPOCH_WEEK` (★★★ ROUTE_ID GROUNDING v3 — NOT a per-contact value; every contact pair
 * shares the same anchor).
 *
 * First call for a given (peerFp, direction) in this cache: bootstraps `RouteRatchet.init(sAB, dir,
 * anchorWindow, targetWindow)` (walks forward from the FIXED anchor — a one-time COLD cost per contact, not
 * per message; see the benchmark in the deliverable report — cost is small TODAY because the anchor is
 * "this launch week", but it is NOT bounded: it grows ~168 hops every week forever absent a re-anchor,
 * eventually reaching the v1-measured 89.7s/anchor-0 scale again after enough calendar time — this is the
 * explicit cost of an interim global anchor vs. a real per-contact one). Subsequent calls for the SAME
 * cache key: advance the cached instance (cheap incremental hop, milliseconds). Because EVERY party anchors
 * at the SAME compiled-in constant, this is CORRECT across independent processes/sessions bootstrapping at
 * arbitrarily different real moments — see the (CROSS-SESSION OFFLINE) test.
 */
export function deriveRotatingRouteId(args: DeriveRotatingRouteIdArgs): string {
  const dir =
    args.direction === 'outbound'
      ? directionTag(args.myFp, args.peerFp)
      : directionTag(args.peerFp, args.myFp);
  const key = `${args.peerFp}:${args.direction}`;
  const targetWindow = currentWindowIndex(args.now ?? Date.now());
  const anchorWindow = epochWeekToAnchorWindow(ANCHOR_EPOCH_WEEK);

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

export interface DeriveRouteIdRangeArgs {
  myEdPriv: Uint8Array;
  myFp: string;
  peerEdPub: Uint8Array;
  peerFp: string;
  direction: RouteDirection;
  /** How many windows before the target window to include (inclusive range: [target-horizon, target]). */
  horizonWindows: number;
  /** Injectable wall-clock (ms) — defaults to Date.now(). Defines the END (most recent window) of the range. */
  now?: number;
}

/**
 * Derive route_id(w) for every window w in [max(ANCHOR_EPOCH_WEEK*168, targetWindow - horizonWindows),
 * targetWindow], oldest first — the ★ OFFLINE-POLL-DEPTH catch-up range a recipient must poll to find a
 * deposit made while they were offline (a deposit at window W has route_id(W); the tag ROTATES, so polling
 * only the CURRENT window after returning online misses it entirely — the exact silent-failure this exists
 * to close).
 *
 * ★ PERFORMANCE: this is ONE walk from the global anchor to targetWindow (the SAME cost as a single
 * deriveRotatingRouteId cold call — see its doc), recording the route_id at each of the last
 * `horizonWindows+1` steps along the way. It is deliberately NOT `horizonWindows` separate calls to
 * RouteRatchet.init (one per target window) — that would re-walk from the anchor EVERY time, costing
 * `horizonWindows × (hops from anchor)` instead of `(hops from anchor) + horizonWindows`, which would be
 * catastrophic once the anchor is more than trivially old (see deriveRotatingRouteId's growth-over-time
 * note). Uses the raw exported primitives directly (deriveRootRatchetKey/advanceRatchetKey/deriveRouteId)
 * rather than the RouteRatchet class, because the class only exposes the CURRENT position's route_id, not a
 * recorded history of the windows walked through — composition only, no new crypto, same chain
 * RouteRatchet.advanceTo uses internally (route-ratchet.ts:174-181).
 *
 * No RouteRatchetCache reuse here — that cache speeds up repeated SINGLE-current-window queries
 * (deriveRotatingRouteId); a historical range walk is a different access pattern and gets no benefit from
 * it (deliberate, not an oversight).
 */
export function deriveRouteIdWindowRange(args: DeriveRouteIdRangeArgs): string[] {
  const dir =
    args.direction === 'outbound'
      ? directionTag(args.myFp, args.peerFp)
      : directionTag(args.peerFp, args.myFp);
  const targetWindow = currentWindowIndex(args.now ?? Date.now());
  const anchor = epochWeekToAnchorWindow(ANCHOR_EPOCH_WEEK);
  if (anchor > targetWindow) {
    throw new Error('deriveRouteIdWindowRange: ANCHOR_EPOCH_WEEK is in the future relative to now');
  }
  const rangeStart = Math.max(anchor, targetWindow - args.horizonWindows);

  const sAB = deriveSharedSecret(args.myEdPriv, args.peerEdPub);
  let rk = deriveRootRatchetKey(sAB, dir);
  let w = anchor;
  const ids: string[] = [];
  if (w >= rangeStart) ids.push(deriveRouteId(rk));
  while (w < targetWindow) {
    rk = advanceRatchetKey(rk, w + 1);
    w += 1;
    if (w >= rangeStart) ids.push(deriveRouteId(rk));
  }
  return ids;
}
