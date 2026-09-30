// src/lib/crypto/consent-delta.ts
/**
 * Blinded consent-delta — the #558 keystone K2 §6, the first consumer of the uniform frame.
 *
 * WHAT IT IS: a signed, monotonic-epoch, overwrite-only record by which a person C gives a real "go-private"
 * (or scope-narrow) LEVER that propagates at DELIVERY speed, while the relay routes it BLIND. It closes the
 * KB#91362 agency gap (today consent is 2-way + owner-local; C has no lever, revocation waits for the peer's
 * next sync). C's client emits, to each contact's blinded route_id (K1), an inner-sealed consent-delta; the
 * PEER'S CLIENT — never the relay — verifies it and drops C from its open-visible subset.
 *
 * THE CRYPTO HERE = a detached Ed25519 signature over a length-prefixed preimage + a monotonic-epoch check.
 * NO new crypto core: it reuses raw-sign.ts `rawSign` (the same Ed25519 the identity/bind path uses). The
 * relay-unreadability is entirely the K0 seal + the uniform frame (uniform-frame.ts) this payload rides in;
 * this module produces the PLAINTEXT payload that gets framed then device-sealed.
 *
 * ★ SIGNING GUARDRAIL (raw-sign.ts:92-95, Flint — grounded, not recited): a ':'-joined preimage is injective
 * ONLY for fixed-width hex fields; a variable-length or ':'-bearing field (our `scope`, our `typ`) would let
 * two different (typ, scope) pairs collide onto the same signed bytes. So the preimage here is LENGTH-PREFIXED
 * (every variable field is u32-len ‖ bytes; epoch is a fixed 8-byte counter), with a versioned domain-sep
 * label — injective by construction, and domain-separated from bind / psi-auth / mailbox-reg preimages.
 *
 * ★ ANTI-ROLLBACK (§6a): the epoch is a signed, per-(C→peer) monotonic counter. A verifier rejects any delta
 * with `epoch <= lastSeen(C)` → a relay/attacker CANNOT replay an old "public" delta to roll back a "private"
 * one. (Distinct from the §5 routing window — this is a per-relationship consent counter.) This is why the
 * §6b relay store can be OVERWRITE-ONLY with no seen-set: replay defense is in the signed payload, at the
 * device, not at the relay (spec §5-E).
 *
 * ★ ANTI CROSS-PEER REPLAY: the preimage binds the RECIPIENT (their stable identity fingerprint) — a delta C
 * signs for peer Y will not verify at peer X (X reconstructs the preimage with X's own fp). The binding is
 * NOT on the wire (the verifier supplies its own fp) → minimization + the relay learns no identity.
 *
 * SCOPE: this module = the signed payload (build + verify + the monotonic check). It is payload-kind-agnostic
 * about DELIVERY — framing (frameUniform) + K0 seal + K1 routing + the emit-path (C's toggle → fan-out → the
 * peer's owner-local apply, extending the §C firewall) are the consent EMIT-PATH unit, deferred and gated on
 * Flint §7. The `typ` / `scope` VOCABULARY (what a scope handle means, forced-vs-advisory) is consent-model
 * policy (spec §11-1 ruled HONOR+fast-propagate; taxonomy may take a Peter steer) — so this primitive keeps
 * `typ` a validated bounded string and `scope` opaque bytes, and does not hardcode a policy on top of them.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
// Relative import (NOT the `@/` alias): the crypto layer stays alias-free so `npx tsx --test` resolves it
// without a tsconfig-paths loader (matches mailbox-envelope / route-ratchet / onion-envelope).
import { rawSign } from '../identity/raw-sign.js';

/** Versioned domain separator for the consent-delta signature preimage (never reused across derivations). */
const CONSENT_SIG_LABEL = 'svrnty-consent-delta-v1';
/** Wire-format version byte for the serialized payload. */
export const CONSENT_DELTA_WIRE_VERSION = 1;
/** Bound on the variable-length fields so a single delta stays well within one uniform cell (and so a hostile
 *  length field is rejected before allocation). typ is a short tag; scope is a small opaque handle. */
const MAX_TYP_BYTES = 64;
const MAX_SCOPE_BYTES = 256;
const SIG_BYTES = 64; // Ed25519 detached signature
const MAX_EPOCH = Number.MAX_SAFE_INTEGER;

/** The two known consent-change kinds (spec §6). Exported as constants; `typ` is NOT hard-restricted to these
 *  (forward-compat — an unknown typ still verifies cryptographically; the deferred handler decides policy). */
export const CONSENT_GO_PRIVATE = 'consent/go-private';
export const CONSENT_SCOPE_CHANGE = 'consent/scope-change';

export interface ConsentDelta {
  /** The change kind — e.g. CONSENT_GO_PRIVATE. A bounded UTF-8 tag, opaque to the relay. */
  typ: string;
  /** Per-(C→peer) monotonic counter (anti-rollback, §6a). Non-negative integer. */
  epoch: number;
  /** Opaque-to-relay scope handle (e.g. "all" or a circle handle meaningful only to the peer). */
  scope: Uint8Array;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/** length-prefix: u32-BE(len) ‖ bytes. Injective framing (raw-sign.ts guardrail). */
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

function assertValidFields(typ: string, epoch: number, scope: Uint8Array): Uint8Array {
  if (typeof typ !== 'string' || typ.length === 0) throw new Error('consent-delta: typ must be a non-empty string');
  const typBytes = enc.encode(typ);
  if (typBytes.length > MAX_TYP_BYTES) throw new Error(`consent-delta: typ exceeds ${MAX_TYP_BYTES} bytes`);
  if (!Number.isInteger(epoch) || epoch < 0 || epoch > MAX_EPOCH) throw new Error('consent-delta: epoch must be a non-negative safe integer');
  if (!(scope instanceof Uint8Array)) throw new Error('consent-delta: scope must be a Uint8Array');
  if (scope.length > MAX_SCOPE_BYTES) throw new Error(`consent-delta: scope exceeds ${MAX_SCOPE_BYTES} bytes`);
  return typBytes;
}

/**
 * The signed preimage: DOMAIN ‖ LP(typ) ‖ u64(epoch) ‖ LP(scope) ‖ LP(recipientBinding). Length-prefixed so
 * distinct (typ, epoch, scope, recipient) tuples never collide onto the same bytes (Flint guardrail). The
 * recipient binding (their stable identity fp bytes) is signed but NOT serialized — anti cross-peer replay
 * with zero identity on the wire.
 */
function consentPreimage(typBytes: Uint8Array, epoch: number, scope: Uint8Array, recipientBinding: Uint8Array): Uint8Array {
  return concat([lp(enc.encode(CONSENT_SIG_LABEL)), lp(typBytes), u64be(epoch), lp(scope), lp(recipientBinding)]);
}

/**
 * BUILD a signed consent-delta PLAINTEXT payload (ready to hand to frameUniform(..,'consent-delta')).
 *
 * @param delta            { typ, epoch, scope } — the change (epoch must be > the peer's last-seen; caller owns the counter)
 * @param signerSeed       C's raw 32-byte Ed25519 seed (in-memory only; from extractRawSign) — signs the delta
 * @param recipientBinding the recipient's STABLE identity fingerprint bytes — bound into the signature (anti cross-peer replay)
 * @returns the wire payload: u8(ver) ‖ LP(typ) ‖ u64(epoch) ‖ LP(scope) ‖ sig(64B)
 */
export function buildConsentDelta(delta: ConsentDelta, signerSeed: Uint8Array, recipientBinding: Uint8Array): Uint8Array {
  const typBytes = assertValidFields(delta.typ, delta.epoch, delta.scope);
  if (!(recipientBinding instanceof Uint8Array) || recipientBinding.length === 0) {
    throw new Error('consent-delta: recipientBinding must be non-empty bytes');
  }
  const sig = rawSign(consentPreimage(typBytes, delta.epoch, delta.scope, recipientBinding), signerSeed);
  return concat([Uint8Array.of(CONSENT_DELTA_WIRE_VERSION), lp(typBytes), u64be(delta.epoch), lp(delta.scope), sig]);
}

/** A bounds-checked cursor reader over the wire payload — returns null (never throws) on any overrun. */
function readLp(buf: Uint8Array, offset: number, cap: number): { bytes: Uint8Array; next: number } | null {
  if (offset + 4 > buf.length) return null;
  const len = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(offset, false);
  if (len > cap) return null;
  const start = offset + 4;
  if (start + len > buf.length) return null;
  return { bytes: buf.slice(start, start + len), next: start + len };
}

/**
 * VERIFY a consent-delta payload. Returns the parsed { typ, epoch, scope } ONLY if:
 *   (1) the wire parses cleanly,
 *   (2) the Ed25519 signature verifies under `signerSignPub` over the LP preimage (with the verifier's own
 *       `recipientBinding` reconstructed — so a delta signed for a different peer fails here), AND
 *   (3) epoch > lastSeenEpoch (monotonic anti-rollback, §6a).
 * Returns null on ANY failure — never throws on hostile input (the relay controls these bytes).
 *
 * @param recipientBinding the VERIFIER's own stable identity fingerprint bytes (must equal what C signed)
 * @param lastSeenEpoch    the highest epoch already accepted from this signer (-1 if none) — reject <= it
 */
export function verifyConsentDelta(
  payload: Uint8Array,
  signerSignPub: Uint8Array,
  opts: { recipientBinding: Uint8Array; lastSeenEpoch: number },
): ConsentDelta | null {
  if (!(payload instanceof Uint8Array) || payload.length < 1 + 4 + 8 + 4 + SIG_BYTES) return null;
  if (payload[0] !== CONSENT_DELTA_WIRE_VERSION) return null;
  if (!(signerSignPub instanceof Uint8Array) || signerSignPub.length !== 32) return null;
  if (!(opts?.recipientBinding instanceof Uint8Array) || opts.recipientBinding.length === 0) return null;

  const typR = readLp(payload, 1, MAX_TYP_BYTES);
  if (!typR) return null;
  if (typR.next + 8 > payload.length) return null;
  const epoch = Number(new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getBigUint64(typR.next, false));
  if (!Number.isSafeInteger(epoch) || epoch < 0) return null;
  const scopeR = readLp(payload, typR.next + 8, MAX_SCOPE_BYTES);
  if (!scopeR) return null;
  // Exactly a 64-byte signature must remain — no trailing bytes (a malleable tail would be a parser ambiguity).
  if (payload.length - scopeR.next !== SIG_BYTES) return null;
  const sig = payload.slice(scopeR.next);

  // Monotonic anti-rollback BEFORE trusting anything — but the signature is what makes epoch meaningful, so
  // verify the signature over the reconstructed preimage with the VERIFIER's own binding, then the counter.
  const preimage = consentPreimage(typR.bytes, epoch, scopeR.bytes, opts.recipientBinding);
  let ok = false;
  try {
    ok = ed25519.verify(sig, preimage, signerSignPub);
  } catch {
    return null; // malformed sig / pubkey point — reject, never throw
  }
  if (!ok) return null;
  if (!Number.isInteger(opts.lastSeenEpoch) || epoch <= opts.lastSeenEpoch) return null; // §6a monotonic

  return { typ: dec.decode(typR.bytes), epoch, scope: scopeR.bytes };
}
