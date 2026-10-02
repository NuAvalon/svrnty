// src/lib/sync/consent-delta-emit.ts
/**
 * Consent-delta EMIT-PATH — the wiring the K2 keystone (consent-delta.ts §6) explicitly deferred:
 * "the emit-path (C's toggle → fan-out → the peer's owner-local apply, extending the §C firewall)...
 * NOT built here" (consent-delta.ts SCOPE note; uniform-frame.ts repeats the same deferral). This module
 * closes that gap: build+seal the outbound cells (emitConsentDelta) and apply a verified inbound one
 * (applyInboundConsentDelta), so a go-private/unfriend withdrawal propagates at DELIVERY speed instead of
 * waiting out the KNOW-layer's 24h staleness window (mutual-trust-sync.ts:656) / 5-min tick
 * (know-layer-sync.ts DEFAULT_KNOW_SYNC_INTERVAL_MS).
 *
 * GROUNDING (file:line, read before writing a line of this module):
 *   - buildConsentDelta / verifyConsentDelta ........ consent-delta.ts:123 / :153 (CONSENT_GO_PRIVATE :57)
 *   - uniform frame (type+size hiding) .............. uniform-frame.ts:105 frameUniform / :130 unframeUniform
 *   - K0 inner (device) + outer (satellite) seal ..... mailbox-envelope.ts:92 sealToMailbox; onion-envelope.ts:65 sealOnion
 *   - KNOW-layer replace-sink (what APPLIES removal) . know-layer-sync.ts:111-147 applyMutualResult
 *     (OrchestratorDeps.applyMutualResult, mutual-trust-sync.ts:96-100) — disclosed ∩ book REPLACES
 *     disclosed_circle, so passing `[]` clears it with the SAME self-heals-on-resync semantics the
 *     existing LOCAL forward-revocation already uses (know-layer-sync.ts:220-224, runPsiCompletionPass).
 *   - existing wake/nudge shape ....................... live-book-poll.ts:165-169 LiveBookPollHandle.burst
 *   - no production consumer of the K0/uniform-frame channel exists yet (grepped clean) — this module is
 *     the FIRST wiring of it; there is no established client→satellite network deposit call for a
 *     sealOnion cell (onion-envelope.ts:24-25: "the server-side peel/route wiring are separate", not
 *     built). So emitConsentDelta is PURE (no fetch): it returns the sealed cells; the caller deposits
 *     them over whatever transport exists/lands (mirrors send-contact-update.ts buildContactUpdateDeposits,
 *     which is pure for the identical reason).
 *
 * ★★ HARD SAFETY INVARIANTS this module enforces (see consent-delta-emit.test.ts for the adversarial gate):
 *   1. BLOCK must NEVER emit a consent-delta. A sudden disappearance from a blocked party's view is
 *      itself a signal (a silence leak) — emitConsentDelta REFUSES (throws) the WHOLE batch before
 *      touching any peer, never a silent partial no-op that could be mistaken for "sent".
 *   2. Anti-replay/rollback is entirely verifyConsentDelta's §6a monotonic-epoch check (consent-delta.ts)
 *      — this module does not weaken or re-implement it; applyInboundConsentDelta calls it unmodified.
 *   3. null-not-throw on malformed/hostile INBOUND input: applyInboundConsentDelta never throws, for any
 *      payload/pubkey/opts shape — the relay (and whoever crafted the bytes) is untrusted.
 *   4. No durable relationship/delivery state: this module persists NOTHING. The outgoing per-peer epoch
 *      counter is caller-owned (buildConsentDelta's existing contract); the inbound apply path only calls
 *      the EXISTING injected sink (deps.applyMutualResult) — it rides the blind mailbox path only.
 */
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  buildConsentDelta,
  verifyConsentDelta,
  CONSENT_GO_PRIVATE,
  type ConsentDelta,
} from '../crypto/consent-delta.js';
import { frameUniform } from '../crypto/uniform-frame.js';
import { sealToMailbox, type MailboxPublicKeys, type MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';
import { sealOnion } from '../crypto/onion-envelope.js';
import { normalizeFingerprintHex } from '../identity/fingerprint.js';
import type { OrchestratorDeps } from '../trust/mutual-trust-sync.js';

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// EMIT (outbound): a withdrawal on C's device → one sealed cell per affected peer, ready to deposit.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/** The only two withdrawal kinds that may EVER reach a consent-delta. */
export type EmittableWithdrawalKind = 'go-private' | 'unfriend';

/** The full withdrawal-kind space a caller may hand in. 'block' is accepted as INPUT only so the guard
 *  below can refuse it explicitly and loudly — it must never be silently filtered upstream and forgotten. */
export type WithdrawalKind = EmittableWithdrawalKind | 'block';

export interface ConsentWithdrawal {
  kind: WithdrawalKind;
  /** Opaque scope handle (consent-delta.ts: "opaque-to-relay... policy is consent-model policy, deferred").
   *  Defaults to the literal 'all' bytes — the only scope this module's two supported kinds need. */
  scope?: Uint8Array;
}

export interface EmitPeerTarget {
  /** The peer's stable identity fingerprint (hex) — becomes recipientBinding (consent-delta.ts:120,
   *  "the recipient's STABLE identity fingerprint bytes", NOT a mailbox fp). */
  fingerprint: string;
  /** The peer's CURRENT device mailbox pubkeys (resolved via mailbox-pointer-transport.ts /
   *  mailbox-registry-client.ts fetchMailbox) — the K0 INNER seal target (sealToMailbox). */
  deviceMailbox: MailboxPublicKeys;
  /** Caller-owned per-(C→peer) monotonic counter (§6a) — MUST be > the epoch this peer has last accepted
   *  from C. This module tracks NO epoch state itself (invariant 4: no durable state introduced here). */
  epoch: number;
  /** K1 blinded rotating route_id — opaque passthrough at K0 (route-ratchet wiring is deferred per
   *  onion-envelope.ts:26). Omit to use a fixed placeholder; pass a real id once K1 lands. */
  route?: string;
}

export interface EmitConsentDeltaArgs {
  withdrawal: ConsentWithdrawal;
  /** The set of peers this withdrawal must propagate to. For 'unfriend' this is normally ONE peer; for
   *  'go-private' it is every peer C currently discloses to. Which peers belong here is a caller/policy
   *  decision — this module does not read or infer the contact book. */
  peers: EmitPeerTarget[];
  /** C's raw 32B Ed25519 seed (in-memory only, e.g. from extractRawSign) — signs each delta. */
  signerSeed: Uint8Array;
  /** The satellite's mailbox pubkeys — the K0 OUTER seal target (sealOnion). */
  satellite: MailboxPublicKeys;
}

/** One sealed, ready-to-deposit cell. The caller POSTs `cell` over whatever satellite-deposit transport
 *  exists (none is wired client→server for the K0/K1 onion channel yet — see module header). */
export interface ConsentDeltaDeposit {
  fingerprint: string;
  route: string;
  cell: MailboxEnvelopePackage;
}

export interface EmitConsentDeltaResult {
  deposits: ConsentDeltaDeposit[];
  /** Fail-closed-per-recipient accounting (mirrors send-contact-update.ts's ContactUpdateSendPlan): one
   *  bad peer is reported and skipped, never sent in a degraded form, and never aborts the batch. */
  skipped: Array<{ fingerprint: string; reason: 'bad-fingerprint' | 'bad-epoch' | 'seal-failed' }>;
}

const DEFAULT_SCOPE = new TextEncoder().encode('all');
/** Placeholder passthrough route (K1 ratchet not wired yet — onion-envelope.ts OnionOuterPayload.route
 *  is "an opaque passthrough string" at K0). Same literal shape the consent-delta.ts DELIVERY test uses. */
const DEFAULT_ROUTE = 'consent-delta-v1';

/**
 * Build one signed consent-delta per affected peer, frame it into a uniform cell, and nest it through the
 * K0 inner (device) + outer (satellite) seal. PURE — no network call (see module header for why: there is
 * no established deposit transport for this channel yet). Returns the sealed cells for the caller to
 * deposit, plus a fail-closed-per-peer skip report.
 *
 * ★ HARD GUARD: throws (refuses the WHOLE batch, before touching any peer) if `withdrawal.kind === 'block'`.
 * A block's entire point is that the blocked party learns nothing; emitting them a consent-delta — even a
 * relay-blind one — would itself be an observable signal ("this contact just silently vanished") that the
 * blind-mailbox design is supposed to prevent. This must fail LOUD (throw), never a quiet empty result that
 * could be misread as "sent to 0 peers because there were none."
 */
export async function emitConsentDelta(args: EmitConsentDeltaArgs): Promise<EmitConsentDeltaResult> {
  if (args.withdrawal.kind === 'block') {
    throw new Error(
      'emitConsentDelta: refusing to emit a consent-delta for a BLOCK withdrawal — a disappearance ' +
        'from a blocked party\'s view is itself a signal (silence leak); block rides no consent channel.',
    );
  }
  if (args.withdrawal.kind !== 'go-private' && args.withdrawal.kind !== 'unfriend') {
    throw new Error(`emitConsentDelta: unknown withdrawal kind '${String(args.withdrawal.kind)}'`);
  }
  if (!Array.isArray(args.peers)) {
    throw new Error('emitConsentDelta: peers must be an array');
  }

  const scope = args.withdrawal.scope ?? DEFAULT_SCOPE;
  const deposits: ConsentDeltaDeposit[] = [];
  const skipped: EmitConsentDeltaResult['skipped'] = [];

  for (const peer of args.peers) {
    const fpRaw = peer?.fingerprint;
    let recipientBinding: Uint8Array;
    try {
      const hex = normalizeFingerprintHex(typeof fpRaw === 'string' ? fpRaw : '');
      if (hex.length === 0 || hex.length % 2 !== 0) throw new Error('empty/odd-length fingerprint');
      recipientBinding = hexToBytes(hex);
    } catch {
      skipped.push({ fingerprint: String(fpRaw), reason: 'bad-fingerprint' });
      continue;
    }

    if (!Number.isInteger(peer.epoch) || peer.epoch < 0) {
      skipped.push({ fingerprint: peer.fingerprint, reason: 'bad-epoch' });
      continue;
    }

    try {
      const delta: ConsentDelta = { typ: CONSENT_GO_PRIVATE, epoch: peer.epoch, scope };
      const payload = buildConsentDelta(delta, args.signerSeed, recipientBinding);
      const cell = frameUniform(payload, 'consent-delta');
      const inner = await sealToMailbox(cell, peer.deviceMailbox);
      const route = peer.route ?? DEFAULT_ROUTE;
      const outer = await sealOnion(inner, args.satellite, route);
      deposits.push({ fingerprint: peer.fingerprint, route, cell: outer });
    } catch {
      // A malformed/mis-sized mailbox pubkey or a sealing error must not abort the rest of the fan-out
      // (one bad peer record cannot block the withdrawal reaching everyone else).
      skipped.push({ fingerprint: peer.fingerprint, reason: 'seal-failed' });
    }
  }

  return { deposits, skipped };
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// APPLY (inbound): a peer's device verifies a received consent-delta and triggers prompt removal.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/** Content-free "re-sync now" signal — the EXACT shape of the existing wake/nudge primitive
 *  (live-book-poll.ts:165-169 LiveBookPollHandle.burst). Carries no consent-delta content whatsoever,
 *  just "something changed, shorten the next cadence" — so a future KnowLayerSyncHandle can grow a
 *  `burst` of this identical shape with zero drift, and callers can pass either handle here today. */
export interface ResyncNudge {
  burst: (durationMs?: number) => void;
}

/** Fire a content-free resync nudge. Never throws (a broken/absent nudge must never undo a successful
 *  apply); returns false if no usable nudge was wired (fine — the normal tick/staleness window still runs). */
export function nudgeResyncNow(nudge: ResyncNudge | null | undefined, durationMs?: number): boolean {
  try {
    if (!nudge || typeof nudge.burst !== 'function') return false;
    nudge.burst(durationMs);
    return true;
  } catch {
    return false;
  }
}

export interface ApplyConsentDeltaDeps {
  /** The EXISTING KNOW-layer replace-sink (know-layer-sync.ts:111-147 buildKnowOverlayDeps →
   *  OrchestratorDeps.applyMutualResult, mutual-trust-sync.ts:96-100). Called with `disclosed: []`, whose
   *  existing semantics (disclosed ∩ book) REPLACE disclosed_circle with the empty set — the identical
   *  write the existing LOCAL forward-revocation already performs (know-layer-sync.ts:220-224) — so
   *  removal self-heals on the next PSI re-sync with zero new persisted field. May reject an unknown peer
   *  (its own documented contract, mutual-trust-sync.ts:469-471) — caught below, not fatal. */
  applyMutualResult: OrchestratorDeps['applyMutualResult'];
  /** Optional: prompt the next KNOW-layer pass instead of waiting out the 24h staleness window / 5-min tick. */
  resync?: ResyncNudge;
}

export type ApplyConsentDeltaOutcome =
  | { kind: 'applied'; typ: string; epoch: number }
  /** Verified cryptographically, but `typ` is not one this module acts on (e.g. CONSENT_SCOPE_CHANGE —
   *  consent-delta.ts leaves scope/typ policy deferred, §11-1). NOT an error: the signature and the
   *  monotonic epoch both checked out; this module just only implements the go-private removal policy. */
  | { kind: 'verified-unhandled'; typ: string; epoch: number }
  /** Verified, but the sink rejected the apply (e.g. peer not in the local book). */
  | { kind: 'apply-failed'; typ: string; epoch: number };

/**
 * Verify an inbound consent-delta payload and, if it is an authentic, non-replayed CONSENT_GO_PRIVATE,
 * trigger prompt removal via the existing replace-semantics sink. Returns `null` on ANY verification
 * failure (malformed wire, wrong signer, cross-peer-bound delta, stale/replayed epoch) — NEVER throws,
 * because `payload`/`signerSignPub` are relay-carried bytes from an untrusted channel (invariant 3).
 *
 * @param payload          the raw consent-delta wire bytes (post onion-peel + uniform-unframe — this
 *                          function does not do channel plumbing, only the consent-delta-specific leaf)
 * @param signerSignPub    C's Ed25519 public key, as already resolved by the caller for this known contact
 * @param opts.recipientBinding  the verifier's OWN stable identity fingerprint bytes (consent-delta.ts §6)
 * @param opts.lastSeenEpoch     highest epoch already accepted from this signer (-1 if none)
 * @param opts.peerFingerprint  the LOCAL book identifier for the signer C — supplied by the caller because
 *                          this module does no book lookups itself (it only verifies+applies); mirrors
 *                          every other per-contact loop in this codebase (pollForPeerTrust, runPsiCompletionPass).
 */
export async function applyInboundConsentDelta(
  payload: Uint8Array,
  signerSignPub: Uint8Array,
  opts: { recipientBinding: Uint8Array; lastSeenEpoch: number; peerFingerprint: string },
  deps: ApplyConsentDeltaDeps,
): Promise<ApplyConsentDeltaOutcome | null> {
  let verified: ConsentDelta | null;
  try {
    verified = verifyConsentDelta(payload, signerSignPub, {
      recipientBinding: opts?.recipientBinding as Uint8Array,
      lastSeenEpoch: opts?.lastSeenEpoch as number,
    });
  } catch {
    // Defense-in-depth only: verifyConsentDelta already null-not-throws on hostile input. A surprise
    // escaping it must still never propagate past this boundary (invariant 3).
    return null;
  }
  if (!verified) return null;

  if (verified.typ !== CONSENT_GO_PRIVATE) {
    return { kind: 'verified-unhandled', typ: verified.typ, epoch: verified.epoch };
  }

  if (typeof opts?.peerFingerprint !== 'string' || opts.peerFingerprint.length === 0) {
    return { kind: 'apply-failed', typ: verified.typ, epoch: verified.epoch };
  }

  try {
    // Replace-semantics clear: '[]' ∩ book = '[]' (mutual-trust-sync.ts applyMutualResult contract) —
    // this IS the removal, reusing the exact sink the existing forward-revocation path uses.
    await deps.applyMutualResult(opts.peerFingerprint, 'know', []);
  } catch {
    return { kind: 'apply-failed', typ: verified.typ, epoch: verified.epoch };
  }

  nudgeResyncNow(deps.resync);
  return { kind: 'applied', typ: verified.typ, epoch: verified.epoch };
}
