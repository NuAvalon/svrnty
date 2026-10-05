// src/lib/crypto/visible-affirm.ts
/**
 * Visible-affirm — the piece-2 mutual-block payload (task #579, spec KB#92246, Flint §F seal KB#92252).
 *
 * WHAT IT IS: a signed, time-EXPIRING "I affirm being visible to YOU" presence token. A person F's client
 * auto-emits one (DEFAULT-ON) to each NON-suppressed contact's blinded route. A viewer (Anna) surfaces F —
 * directly OR transitively as a mutual-of-mutual via anyone's graph — ONLY WHILE it holds a fresh
 * (non-expired) affirmative from F. When F suppresses Anna (per-person block / per-group / global go-private)
 * F STOPS emitting to her → her held affirmative EXPIRES → her reveal of F fails-CLOSED → F drops from her
 * graph, including the transitive mutual-friend path (#156420 — the industry-wide non-transitive-block gap,
 * KB#92243). ABSENCE is indistinguishable from offline ⇒ the block is UNOBSERVABLE (Fork-1a, Peter #159250).
 *
 * ★ WHY EXPIRING, NOT A WITHDRAWAL (grounded design call, KB#92246): consent-delta.ts is a MONOTONIC
 * WITHDRAWAL lever — a withdrawal TO Anna is a signal she RECEIVES → OBSERVABLE (Fork-1b, Peter rejected).
 * An affirmative that simply STOPS being renewed is unobservable-BY-ABSENCE. So this module REUSES
 * consent-delta's proven shape (length-prefixed Ed25519 preimage; recipient-binding signed-but-not-
 * serialized for anti-cross-peer-replay with zero identity on the wire; monotonic epoch anti-rollback) and
 * ADDS the one genuinely new piece consent-delta lacks: a `valid_until` freshness horizon INSIDE the signed
 * preimage. New versioned domain label `svrnty-visible-affirm-v1` — domain-separated from consent-delta /
 * bind / psi-auth / mailbox-reg preimages.
 *
 * ★ §F1 — THE THREE SEALED CONDITIONS (Flint KB#92252, authoritative):
 *   (a) valid_until is INSIDE the signed Ed25519 preimage (length-prefixed / fixed-width) — a relay/attacker
 *       cannot tamper-extend a captured affirmative's validity.
 *   (b) epoch is a per-(F→recipient) MONOTONIC counter COUPLED to valid_until (each renewal: epoch+1 AND a
 *       freshly-slid valid_until). A verifier accepts iff `epoch > lastSeen AND now < valid_until`.
 *   (c) CAP: a verifier REJECTS `valid_until > now + MAX_AFFIRM_TTL` — else a far-future validity would defeat
 *       the block-latency bound. With the cap at MAX_AFFIRM_TTL = 20min (§F4, Athena #159431), the last
 *       affirmative a suppressed viewer can be holding expires within 20min of F's last emit ⇒ block-latency
 *       ≤ 20min BY CONSTRUCTION (Hypatia copy KB#92254: "takes effect quickly, and fully within 20 minutes").
 *
 * ★ CLOCK = the VIEWER's wall-clock, passed in (`now`), never read here — this module is PURE + unit-testable,
 *   and the viewer is the only honest clock for "is F still affirming to ME?". Skew is fail-SAFE by design:
 *   a viewer whose clock runs FAST expires the affirmative EARLY = under-reveal = safe (§F1c). The one hazard
 *   is a viewer clock running BEHIND the emitter tripping the (c) cap and rejecting a legit affirmative — so
 *   the EMIT side (NOT this module) sets valid_until = now + (MAX_AFFIRM_TTL − SKEW_MARGIN), reserving headroom
 *   under the cap for normal positive skew. The cap here stays exactly MAX_AFFIRM_TTL so the ≤20min latency
 *   bound (and Hypatia's copy) is honored verbatim. (Build-decision flagged to Flint §F3 / Athena §F4.)
 *
 * SCOPE OF THIS MODULE: build + verify + the pure freshness predicate. It is DELIVERY-agnostic — the uniform
 * frame (frameUniform), K0 seal, K1 blinded routing, the §F5 byte-length PAD, the default-ON emit fan-out, the
 * receive/store of held affirmatives, and the reveal AND-gate are the EMIT/APPLY units built on top of it.
 * The suppression SCOPE (person/group/global) is an emitter-side owner-local decision about WHOM to emit to;
 * it is deliberately NOT in the payload (minimization — the recipient learns only "F affirms to me, until T").
 */
import { ed25519 } from '@noble/curves/ed25519.js';
// Relative import (NOT the `@/` alias): the crypto layer stays alias-free so `npx tsx --test` resolves it
// without a tsconfig-paths loader (matches consent-delta / mailbox-envelope / onion-envelope).
import { rawSign } from '../identity/raw-sign.js';

/** Versioned domain separator for the visible-affirm signature preimage (never reused across derivations). */
const AFFIRM_SIG_LABEL = 'svrnty-visible-affirm-v1';
/** Wire-format version byte for the serialized payload. */
export const VISIBLE_AFFIRM_WIRE_VERSION = 1;
/** Ed25519 detached signature length. */
const SIG_BYTES = 64;
/**
 * ★ §F1c + §F4 (Athena #159431) — the CAP. A verifier rejects any affirmative whose validity reaches further
 * than this past its own `now`. 20 minutes = TTL == MAX_TTL (one number). This is the HARD block-latency
 * bound: the stalest affirmative a suppressed viewer can still hold expires within MAX_AFFIRM_TTL of F's last
 * emit. The copy ("fully within 20 minutes", KB#92254) is bound to THIS constant — do not loosen it.
 */
export const MAX_AFFIRM_TTL_SECONDS = 20 * 60; // 1200

/**
 * valid_until / epoch are unix-SECONDS and a non-negative counter respectively (matches the satellite's
 * unix-seconds convention; seconds keep the payload — and thus the §F5 pad target — tight). epoch is coupled
 * to valid_until by the emitter (every renewal bumps BOTH): the recipient's monotonic floor on epoch is what
 * stops a relay replaying a stale (shorter-lived / already-near-expiry) affirmative over a fresher one.
 */
export interface VisibleAffirm {
  /** Per-(F→recipient) monotonic counter (anti-rollback). Non-negative safe integer. */
  epoch: number;
  /** Absolute expiry, unix SECONDS. The viewer surfaces F only while `now < valid_until`. */
  validUntil: number;
}

/** length-prefix: u32-BE(len) ‖ bytes. Injective framing (raw-sign.ts guardrail). */
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

/** fixed 8-byte big-endian counter (fixed width ⇒ injective without a length prefix). */
function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const enc = new TextEncoder();

/** A safe non-negative integer within [0, MAX_SAFE_INTEGER]. */
function isCounter(n: unknown): n is number {
  return typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
}

/**
 * The signed preimage: LP(DOMAIN) ‖ u64(epoch) ‖ u64(valid_until) ‖ LP(recipientBinding). Length-prefixed /
 * fixed-width so distinct (epoch, valid_until, recipient) tuples never collide onto the same bytes (Flint
 * guardrail, raw-sign.ts:92-95). valid_until is INSIDE the preimage (§F1a). The recipient binding (their
 * stable identity fp bytes) is signed but NOT serialized — anti cross-peer replay with zero identity on the
 * wire (the verifier supplies its OWN binding, so a delta signed for peer Y will not verify at peer X).
 */
function affirmPreimage(epoch: number, validUntil: number, recipientBinding: Uint8Array): Uint8Array {
  return concat([lp(enc.encode(AFFIRM_SIG_LABEL)), u64be(epoch), u64be(validUntil), lp(recipientBinding)]);
}

/**
 * BUILD a signed visible-affirm PLAINTEXT payload (ready to hand to frameUniform(..,'visible-affirm') then
 * the §F5 pad + K0 seal + K1 routing).
 *
 * @param affirm           { epoch, validUntil } — epoch must be > the recipient's last-seen; validUntil =
 *                         (emit) now + emitTtl where emitTtl ≤ MAX_AFFIRM_TTL_SECONDS. The emitter owns both
 *                         counters and MUST slide them together (§F1b).
 * @param signerSeed       F's raw 32-byte Ed25519 seed (in-memory only; from extractRawSign) — signs the affirm.
 * @param recipientBinding the recipient's STABLE identity fingerprint bytes — bound into the signature (anti
 *                         cross-peer replay). Non-empty.
 * @returns the wire payload: u8(ver) ‖ u64(epoch) ‖ u64(valid_until) ‖ sig(64B). FIXED 81 bytes — note there
 *          is NO variable-length field, so every affirmative is byte-identical in length BEFORE the §F5 pad;
 *          the pad still runs so an affirmative is indistinguishable from F's OTHER K2 traffic, not just from
 *          other affirmatives.
 */
export function buildVisibleAffirm(affirm: VisibleAffirm, signerSeed: Uint8Array, recipientBinding: Uint8Array): Uint8Array {
  if (!isCounter(affirm.epoch)) throw new Error('visible-affirm: epoch must be a non-negative safe integer');
  if (!isCounter(affirm.validUntil)) throw new Error('visible-affirm: validUntil must be a non-negative safe integer (unix seconds)');
  if (!(signerSeed instanceof Uint8Array) || signerSeed.length !== 32) throw new Error('visible-affirm: signerSeed must be 32 bytes');
  if (!(recipientBinding instanceof Uint8Array) || recipientBinding.length === 0) {
    throw new Error('visible-affirm: recipientBinding must be non-empty bytes');
  }
  const sig = rawSign(affirmPreimage(affirm.epoch, affirm.validUntil, recipientBinding), signerSeed);
  return concat([Uint8Array.of(VISIBLE_AFFIRM_WIRE_VERSION), u64be(affirm.epoch), u64be(affirm.validUntil), sig]);
}

/** Exact serialized length: ver(1) ‖ epoch(8) ‖ valid_until(8) ‖ sig(64). */
const WIRE_LEN = 1 + 8 + 8 + SIG_BYTES; // 81

/**
 * Pure freshness predicate — the REVEAL-TIME gate (contactRecordToEdge projection). `now` is the viewer's
 * wall-clock unix seconds. A held affirmative surfaces its signer ONLY while `now < validUntil`. Fail-CLOSED
 * on any malformed input (a non-number validUntil hides the party — never surface on a guess).
 */
export function isAffirmFresh(validUntil: unknown, now: number): boolean {
  return isCounter(validUntil) && typeof now === 'number' && Number.isFinite(now) && now < validUntil;
}

/**
 * VERIFY a visible-affirm payload at ACCEPT time (receive). Returns { epoch, validUntil } ONLY if:
 *   (1) the wire parses cleanly (exact 81 bytes, known version),
 *   (2) the Ed25519 signature verifies under `signerSignPub` over the LP preimage reconstructed with the
 *       VERIFIER's OWN `recipientBinding` (so an affirm signed for a different peer fails here),
 *   (3) epoch > lastSeenEpoch                         (§F1b monotonic anti-rollback),
 *   (4) now < validUntil                               (§F1b freshness — not already expired), AND
 *   (5) validUntil <= now + MAX_AFFIRM_TTL_SECONDS     (§F1c cap — reject far-future validity).
 * Returns null on ANY failure — never throws on hostile input (the relay controls these bytes).
 *
 * NOTE the signer's pubkey (`signerSignPub`) is F's CURRENT signing key (§F2): the caller resolves it via the
 * authority-commitment chain, so a rotated-AWAY key cannot assert. This module verifies the signature it is
 * given; key-currency is the caller's (receive-path's) responsibility.
 *
 * @param recipientBinding the VERIFIER's own stable identity fingerprint bytes (must equal what F signed)
 * @param lastSeenEpoch    the highest epoch already accepted from this signer (-1 if none) — reject <= it
 * @param now              the verifier's wall-clock, unix seconds
 */
export function verifyVisibleAffirm(
  payload: Uint8Array,
  signerSignPub: Uint8Array,
  opts: { recipientBinding: Uint8Array; lastSeenEpoch: number; now: number },
): VisibleAffirm | null {
  if (!(payload instanceof Uint8Array) || payload.length !== WIRE_LEN) return null;
  if (payload[0] !== VISIBLE_AFFIRM_WIRE_VERSION) return null;
  if (!(signerSignPub instanceof Uint8Array) || signerSignPub.length !== 32) return null;
  if (!opts || !(opts.recipientBinding instanceof Uint8Array) || opts.recipientBinding.length === 0) return null;
  if (!Number.isInteger(opts.lastSeenEpoch)) return null;
  if (typeof opts.now !== 'number' || !Number.isFinite(opts.now)) return null;

  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const epoch = Number(dv.getBigUint64(1, false));
  const validUntil = Number(dv.getBigUint64(9, false));
  if (!isCounter(epoch) || !isCounter(validUntil)) return null;
  const sig = payload.slice(1 + 8 + 8);

  // Verify the signature over the reconstructed preimage with the VERIFIER's OWN binding FIRST — the counter
  // and the horizon are only meaningful once the bytes are proven to be F's.
  let ok = false;
  try {
    ok = ed25519.verify(sig, affirmPreimage(epoch, validUntil, opts.recipientBinding), signerSignPub);
  } catch {
    return null; // malformed sig / pubkey point — reject, never throw
  }
  if (!ok) return null;
  if (epoch <= opts.lastSeenEpoch) return null;                        // §F1b monotonic
  if (!(opts.now < validUntil)) return null;                           // §F1b freshness (not expired)
  if (validUntil > opts.now + MAX_AFFIRM_TTL_SECONDS) return null;     // §F1c cap (no far-future validity)

  return { epoch, validUntil };
}
