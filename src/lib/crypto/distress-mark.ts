// src/lib/crypto/distress-mark.ts
/**
 * Distress mark — the #558 keystone K3 (§8), the distress consumer of the uniform frame.
 *
 * WHAT IT IS: the *silent cry* payload. A person C, cornered, emits to each of their guardians an
 * AUTHENTICATED "I am in distress" mark that (1) only the guardian's DEVICE can read, (2) a hosted relay
 * routing it cannot classify as distress (vs a consent-delta vs a message vs cover), and (3) carries NO
 * proof back to C's phone. It is the crypto body that the `src/lib/trust/distress.ts` stub was holding a
 * place for (`sendDistress`: *"Fleet replaces the body with outer-mailbox encrypt + fan-out"*).
 *
 * THE CRYPTO HERE = a detached Ed25519 signature over a length-prefixed preimage, exactly the shape of the
 * K2 consent-delta (consent-delta.ts) — NO new crypto core. It reuses raw-sign.ts `rawSign` (the same
 * Ed25519 the identity / bind / consent path uses). Relay-unreadability is entirely the K0 seal + the
 * uniform frame (uniform-frame.ts) this payload rides in; this module produces the PLAINTEXT cry that gets
 * framed as `'distress'`, then device-sealed (INNER), then onion-sealed to the guardian satellite (OUTER).
 *
 * ──────────────────────────────────────────────────────────────────────────────────────────────────────
 * THE §8 SILENCE INVARIANT this is built to (Flint §8 / KB#91383), four parts — each refuted adversarially
 * in distress-mark.test.ts + distress-cadence.test.ts, NEVER "the cry is signed" (that is the mechanic, not
 * the protection):
 *
 *   (type-opacity, Finding-#1)  a peeling satellite CANNOT tell a distress cry from a consent-delta / message
 *                               / cover by TYPE or SIZE. ── PROVIDED by K2's uniform-frame: the cry is framed
 *                               as `'distress'`, so the type byte lives inside the device-sealed cell and the
 *                               cell is a constant FRAME_BYTES. This module's job is only to keep the cry
 *                               SMALL ENOUGH to be ONE cell (below).
 *   (a) device-sealed auth      the cry's authentication is INNER-sealed to the guardian DEVICE — the
 *                               guardian's *satellite*, which peels the OUTER, never holds the device key, so
 *                               it can neither read nor verify the sender proof. (Proven in the test: a peel
 *                               yields an opaque inner.ct; only openOnionInner at the device recovers+verifies.)
 *   (b) uniform cover cadence   a cry emitted ONLY on a real event is a burst-after-silence that self-classifies
 *                               for a zero-real-traffic user (the DV population). The mark must ride a steady
 *                               baseline of COVER cells. ── buildCoverCell() here; the cadence is distress-cadence.ts.
 *   (c) fan-out jitter          a synchronized N-way fan-out to N guardian satellites is itself a fingerprint.
 *                               ── distress-cadence.ts planFanoutJitter.
 *
 * ★ SINGLE-CELL CAP — the life-safety claims-gate I OWN (Archie #154636, sharpened by Hypatia's life-safety
 * APEX KB#91416). A distress-indistinguishability claim is honest ONLY if the architecture ENFORCES that a cry
 * is always exactly ONE cell: a multi-cell cry would expose a coarse VOLUME signal (cell count) that separates
 * it from a one-cell consent-delta / short message (see uniform-frame.ts claim boundary). So the cry carries NO
 * caller-supplied variable content — it is a FIXED-SHAPE record (version ‖ epoch ‖ sig) → it is single-cell BY
 * CONSTRUCTION, which is stronger than a runtime throw (there is no input that can overflow). The cap is also
 * asserted statically (DISTRESS_MARK_BYTES ≤ FRAME_MAX_PAYLOAD) and the gate test keeps the positive control
 * that frameUniform DOES throw above one cell, so the enforcement is real and non-vacuous.
 *
 * ★★ TWO-GATE on any present-tense "undetectable" claim (Hypatia life-safety APEX, locked all-seats): this
 * module satisfies gate-1 (enforced-in-code: single-cell + type/size opacity via K2). Gate-2 — VERIFIED ON THE
 * DEPLOYED EDGE (a live satellite actually running the uniform cover cadence) — is NOT met by source alone. So
 * the strong "a watcher cannot detect the cry" copy stays HELD until Flint reads the deployed relay. This
 * module's docstrings and the distress UI copy (trust/distress.ts) must not assert undetectability as present
 * tense before that. The silence contract already coded in trust/distress.ts ("This phone keeps no proof",
 * local-only mark, "I went" does not tell the subject) is UNTOUCHED by this primitive.
 *
 * SCOPE (K3 crypto leaf = this signed cry + cover-cell generator + the pure cadence/jitter planners in
 * distress-cadence.ts, each with its adversarial §8 gate). The EMIT-PATH — wiring sendDistress to real timers,
 * the per-guardian K1 route-ratchet state, and the satellite deposit/redirect (fed-addressing §7 forward
 * pointer) — is a separate reviewable unit (Flint §8-DEPLOYED gates it; it also leans on Athena's satellite),
 * NOT built here. Same discipline as K0 deferring satellite-serve and K1 deferring Family-B wiring.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
// Relative import (NOT the `@/` alias): the crypto layer stays alias-free so `npx tsx --test` resolves it
// without a tsconfig-paths loader (matches mailbox-envelope / route-ratchet / onion-envelope / consent-delta).
import { rawSign } from '../identity/raw-sign.js';
import { frameUniform, FRAME_MAX_PAYLOAD, type FrameType } from './uniform-frame.js';

/** Versioned domain separator for the distress signature preimage (never reused across derivations —
 *  domain-separated from svrnty-bind / svrnty-psi-auth / svrnty-consent-delta-v1 / svrnty-mailbox-reg-v1). */
const DISTRESS_SIG_LABEL = 'svrnty-distress-v1';
/** Wire-format version byte for the serialized cry. */
export const DISTRESS_WIRE_VERSION = 1;
const SIG_BYTES = 64; // Ed25519 detached signature
/** The cry is a FIXED-SHAPE record: u8(version) ‖ u64-BE(epoch) ‖ sig(64). No variable field by design
 *  (silence + single-cell-by-construction). 1 + 8 + 64 = 73 bytes, a constant. */
export const DISTRESS_MARK_BYTES = 1 + 8 + SIG_BYTES;
const MAX_EPOCH = Number.MAX_SAFE_INTEGER;

/** The frame type a distress cry rides (it shares the uniform channel; the type lives inside the device seal). */
export const DISTRESS_FRAME_TYPE: FrameType = 'distress';
export const COVER_FRAME_TYPE: FrameType = 'cover';

// STATIC single-cell guarantee (the life-safety cap, enforced at module load, not merely at call time):
// a fixed-shape cry can never exceed one cell. If a future edit added a field that pushed it over, this
// throws at import — the cap cannot be silently regressed.
if (DISTRESS_MARK_BYTES > FRAME_MAX_PAYLOAD) {
  throw new Error(`distress-mark: DISTRESS_MARK_BYTES ${DISTRESS_MARK_BYTES} exceeds one cell (${FRAME_MAX_PAYLOAD})`);
}

const enc = new TextEncoder();

/** length-prefix: u32-BE(len) ‖ bytes. Injective framing (raw-sign.ts:92-95 guardrail — a ':'-joined preimage
 *  is injective only for fixed-width hex; our label + guardian binding are variable-length so MUST be LP). */
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

/** epoch as a fixed 8-byte big-endian counter (fixed width ⇒ injective without a length prefix). */
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

/**
 * The signed preimage: DOMAIN ‖ u64(epoch) ‖ LP(guardianBinding). Length-prefixed so distinct
 * (epoch, guardian) tuples never collide onto the same bytes. The guardian binding (their stable identity
 * fp bytes) is SIGNED but NOT serialized — a cry C signs for guardian Y will not verify at guardian X
 * (X reconstructs the preimage with X's own fp) → anti cross-guardian replay with ZERO identity on the wire.
 */
function distressPreimage(epoch: number, guardianBinding: Uint8Array): Uint8Array {
  return concat([lp(enc.encode(DISTRESS_SIG_LABEL)), u64be(epoch), lp(guardianBinding)]);
}

export interface DistressMark {
  /** Per-(C→guardian) monotonic counter / freshness stamp (anti-replay, §6a shape). Non-negative integer. */
  epoch: number;
}

/**
 * BUILD a signed distress-cry PLAINTEXT payload (ready to hand to frameUniform(.., 'distress')).
 *
 * The cry asserts "C (the signer) is in distress, to THIS guardian, at THIS epoch" — nothing else. It carries
 * no message, no location, no free-text: a silent cry, and single-cell by construction. The guardian learns
 * WHO from the relationship/route + this signature, never from payload content.
 *
 * @param mark             { epoch } — epoch must exceed the guardian's last-seen (caller owns the counter)
 * @param signerSeed       C's raw 32-byte Ed25519 seed (in-memory only; from extractRawSign) — signs the cry
 * @param guardianBinding  the guardian's STABLE identity fingerprint bytes — bound into the signature (anti
 *                         cross-guardian replay), signed but never serialized
 * @returns the wire payload: u8(ver) ‖ u64(epoch) ‖ sig(64) — exactly DISTRESS_MARK_BYTES
 */
export function buildDistressMark(mark: DistressMark, signerSeed: Uint8Array, guardianBinding: Uint8Array): Uint8Array {
  if (!Number.isInteger(mark.epoch) || mark.epoch < 0 || mark.epoch > MAX_EPOCH) {
    throw new Error('distress-mark: epoch must be a non-negative safe integer');
  }
  if (!(guardianBinding instanceof Uint8Array) || guardianBinding.length === 0) {
    throw new Error('distress-mark: guardianBinding must be non-empty bytes');
  }
  if (!(signerSeed instanceof Uint8Array) || signerSeed.length !== 32) {
    throw new Error('distress-mark: signerSeed must be a 32-byte Ed25519 seed');
  }
  const sig = rawSign(distressPreimage(mark.epoch, guardianBinding), signerSeed);
  const payload = concat([Uint8Array.of(DISTRESS_WIRE_VERSION), u64be(mark.epoch), sig]);
  // Defense-in-depth against a future variable field: the cap is also checked at call time. A cry that cannot
  // fit one cell MUST throw (never silently split — a split cry leaks volume, the exact §8 harm).
  if (payload.length > FRAME_MAX_PAYLOAD) {
    throw new Error(`distress-mark: cry ${payload.length} exceeds one cell (${FRAME_MAX_PAYLOAD})`);
  }
  return payload;
}

/** Convenience: build the cry AND frame it into the uniform `'distress'` cell in one step (the form the
 *  emit-path uses before the K0 inner seal). Single-cell guaranteed: frameUniform throws above one cell. */
export function buildDistressCell(mark: DistressMark, signerSeed: Uint8Array, guardianBinding: Uint8Array): Uint8Array {
  return frameUniform(buildDistressMark(mark, signerSeed, guardianBinding), DISTRESS_FRAME_TYPE);
}

/**
 * VERIFY a distress-cry payload — runs at the guardian's DEVICE (after openOnionInner + unframeUniform), never
 * at the satellite. Returns the parsed { epoch } ONLY if:
 *   (1) the wire parses to exactly DISTRESS_MARK_BYTES with the known version,
 *   (2) the Ed25519 signature verifies under `signerSignPub` over the preimage reconstructed with the
 *       VERIFIER's OWN `guardianBinding` (so a cry signed for a different guardian fails here), AND
 *   (3) epoch > lastSeenEpoch (monotonic anti-replay — a relay cannot replay an old sealed cry; a legitimate
 *       repeat cry simply uses a higher epoch).
 * Returns null on ANY failure — never throws on hostile input (the relay controls these bytes).
 *
 * @param signerSignPub   C's 32-byte Ed25519 public key (the guardian knows it from the trust relationship)
 * @param guardianBinding the VERIFIER's own stable identity fingerprint bytes (must equal what C signed)
 * @param lastSeenEpoch   the highest epoch already accepted from this signer (-1 if none) — reject <= it
 */
export function verifyDistressMark(
  payload: Uint8Array,
  signerSignPub: Uint8Array,
  opts: { guardianBinding: Uint8Array; lastSeenEpoch: number },
): DistressMark | null {
  if (!(payload instanceof Uint8Array) || payload.length !== DISTRESS_MARK_BYTES) return null;
  if (payload[0] !== DISTRESS_WIRE_VERSION) return null;
  if (!(signerSignPub instanceof Uint8Array) || signerSignPub.length !== 32) return null;
  if (!(opts?.guardianBinding instanceof Uint8Array) || opts.guardianBinding.length === 0) return null;
  if (!Number.isInteger(opts.lastSeenEpoch)) return null;

  const dv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const epoch = Number(dv.getBigUint64(1, false));
  if (!Number.isSafeInteger(epoch) || epoch < 0) return null;
  const sig = payload.slice(1 + 8);

  const preimage = distressPreimage(epoch, opts.guardianBinding);
  let ok = false;
  try {
    ok = ed25519.verify(sig, preimage, signerSignPub);
  } catch {
    return null; // malformed sig / pubkey point — reject, never throw
  }
  if (!ok) return null;
  if (epoch <= opts.lastSeenEpoch) return null; // §6a monotonic anti-replay

  return { epoch };
}

/**
 * BUILD a cover PLAINTEXT payload — undifferentiated CSPRNG bytes that frame into the SAME uniform `'cover'`
 * cell shape as a real cry. Cover cells are what the §8(b) uniform baseline cadence emits so that a real cry
 * does not stand out as a burst-after-silence (distress-cadence.ts drives the cadence; this makes the cell).
 *
 * The device that opens a cover cell reads type `'cover'` (inside the device-sealed cell, never on the wire)
 * and DISCARDS it. To any on-path observer or peeling satellite a cover cell is byte-indistinguishable from a
 * distress / consent-delta / message cell (constant FRAME_BYTES, type hidden). It is unsigned — it carries no
 * authentication because it carries no meaning; it exists only to occupy the channel.
 *
 * @param nBytes optional payload size (default a small random-ish fixed value); any value ≤ FRAME_MAX_PAYLOAD
 *               frames to the identical constant-size cell, so the size here is NOT observable.
 */
export function buildCoverPayload(nBytes: number = 32): Uint8Array {
  if (!Number.isInteger(nBytes) || nBytes < 0 || nBytes > FRAME_MAX_PAYLOAD) {
    throw new Error(`distress-mark: cover size must be an integer in [0, ${FRAME_MAX_PAYLOAD}]`);
  }
  return crypto.getRandomValues(new Uint8Array(nBytes));
}

/** Convenience: a framed `'cover'` cell ready for the K0 inner seal (constant FRAME_BYTES, type hidden). */
export function buildCoverCell(nBytes: number = 32): Uint8Array {
  return frameUniform(buildCoverPayload(nBytes), COVER_FRAME_TYPE);
}
