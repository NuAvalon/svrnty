// src/lib/crypto/hybrid-envelope-guard.ts
// The §6 WIRE-INVARIANT PREDICATE for the envelope-wiring Tier-0 (Peter #115657).
//
// Asserts "no non-hybrid ciphertext leaves the client": every payload that leaves an
// ENVELOPE path (contact exchange, contact DB, trust-graph) or rests at-rest must be a
// well-formed HybridEnvelope — a recognized suite_id, a NON-EMPTY kem_ct_pq (the PQ leg),
// and NO plaintext / classical-only structure. Format of record: Flint's
// shared/outbox/flint/svrnty_hybrid_envelope_format_v1.md §2 (shape) + §6 (predicate),
// Archie format-ACK'd.
//
// SCOPE: this classifier is applied to the ENVELOPE paths by the invariant test. The
// ContactShare/relay path (createRelay: AES-256-GCM + full-entropy out-of-band key, no
// asymmetric KEM) is a Flint-SIGNED documented EXCEPTION (PQ-safe by construction, no
// HNDL) — it is EXEMPTED at test-wiring scope, not reclassified here. Re-adjudicate that
// exception if the relay ever encapsulates its key to a recipient pubkey.
//
// STATUS: build+verify only — DEPLOY HARD-BLOCKED (model-ratify != deploy-go). The
// concrete send-path wiring (Flint's encrypt/decrypt primitive) plugs the guard into the
// live outbound on his primitive ping; this predicate is format-frozen + standalone.
// The HybridEnvelope shape is declared LOCALLY here and unifies with Flint's exported type
// on merge (import from ./envelope-encrypt) — the declare-locally seam used for
// VerifiedContactUpdate in contacts/apply-contact-update.ts. Shape VERIFIED against Flint's
// envelope-encrypt.ts (branch flint/envelope-hybrid-kem, 97efc63): the concrete on-wire
// HybridEnvelope is {suite_id, epk_classical, kem_ct_pq, aead_iv, aead_ct} — 5 base64 fields,
// the GCM tag folded into aead_ct (no separate aead_tag). HYBRID_SUITE_ID is cat5 today,
// flips to cat3 on Flint's alignment (no shape change) — the guard recognizes both.

/** The wire shape, per format §2. Fields are `unknown` because on the wire they are bytes
 *  encoded as base64 strings (or Uint8Array pre-serialization) — the guard checks presence
 *  + non-emptiness, not the byte semantics (that is the crypto's job, Flint's lane). */
export interface HybridEnvelope {
  suite_id: string;
  epk_classical: unknown; // sender ephemeral X25519 public key (classical KEM contribution)
  kem_ct_pq: unknown;     // ML-KEM-768 encapsulation ciphertext — MUST be present + non-empty
  aead_iv: unknown;       // AES-256-GCM nonce (base64)
  aead_ct: unknown;       // AES-256-GCM(payload)+GCM-tag under hybrid_key — the ONLY payload copy (base64)
}

/** Recognized hybrid suites. §1: cat3 is the launch suite. §7: cat5 is a future EPOCH —
 *  still hybrid, so accepted (never flagged non-hybrid). Any OTHER suite_id is unrecognized
 *  = a possible downgrade → fail-closed. */
export const RECOGNIZED_HYBRID_SUITES: ReadonlySet<string> = new Set([
  'svrnty-hybrid-v1-cat3', // launch (ML-KEM-768 / X25519)
  'svrnty-hybrid-v1-cat5', // future epoch (ML-KEM-1024 / X25519) — §7
]);

export type EnvelopeClass =
  | 'hybrid-envelope' //  PASS: well-formed HybridEnvelope, recognized suite, PQ leg present
  | 'plaintext-json' //   FAIL §6a: parseable JSON that is not a HybridEnvelope
  | 'openpgp-classical' // FAIL §6b: an openpgp classical encrypt() result (armored)
  | 'malformed-hybrid' //  FAIL §6c: HybridEnvelope-shaped but missing/empty kem_ct_pq, or unrecognized suite, or incomplete AEAD
  | 'unknown'; //          FAIL: opaque / unrecognized (neither JSON object nor PGP)

function nonEmpty(v: unknown): boolean {
  if (v == null) return false;
  if (typeof v === 'string') return v.length > 0;
  if (v instanceof Uint8Array) return v.byteLength > 0;
  if (Array.isArray(v)) return v.length > 0;
  return true; // some other truthy byte encoding
}

function isPgpArmored(s: string): boolean {
  return /-----BEGIN PGP (MESSAGE|SIGNED MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----/.test(s);
}

/**
 * Classify an outbound / at-rest payload per format §6. Accepts a string (JSON, PGP armor,
 * or opaque), a parsed object, or bytes. Only `'hybrid-envelope'` is allowed on an envelope
 * path; every other class is a §6 failure.
 */
export function classifyEnvelope(payload: unknown): EnvelopeClass {
  // §6b — openpgp classical armored text (the current exchange.ts path).
  if (typeof payload === 'string' && isPgpArmored(payload)) return 'openpgp-classical';

  // Normalize a JSON string to an object; a non-JSON, non-PGP string is opaque.
  let obj: unknown = payload;
  if (typeof payload === 'string') {
    try {
      obj = JSON.parse(payload);
    } catch {
      return 'unknown';
    }
  }

  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) return 'unknown';
  const rec = obj as Record<string, unknown>;

  // Does it CLAIM to be a HybridEnvelope? (any discriminating field present)
  const looksHybrid =
    'suite_id' in rec || 'kem_ct_pq' in rec || 'aead_ct' in rec || 'epk_classical' in rec;

  if (looksHybrid) {
    const suiteOk = typeof rec.suite_id === 'string' && RECOGNIZED_HYBRID_SUITES.has(rec.suite_id);
    const pqOk = nonEmpty(rec.kem_ct_pq); // §6c / §3 — the PQ leg must be present + non-empty
    const classicalOk = nonEmpty(rec.epk_classical);
    const aeadOk = nonEmpty(rec.aead_ct) && nonEmpty(rec.aead_iv);
    return suiteOk && pqOk && classicalOk && aeadOk ? 'hybrid-envelope' : 'malformed-hybrid';
  }

  // §6a — a parseable object that is not a HybridEnvelope is plaintext
  // (e.g. an identity-exchange card {fingerprint, display_name, public_key, email}).
  return 'plaintext-json';
}

/** Thrown by the guard: the "no non-hybrid ciphertext leaves the client" floor made loud. */
export class NonHybridCiphertextError extends Error {
  constructor(
    public readonly klass: EnvelopeClass,
    public readonly context: string,
  ) {
    super(`non-hybrid ciphertext would leave the client (${klass}) at: ${context}`);
    this.name = 'NonHybridCiphertextError';
  }
}

/**
 * The guard the invariant test calls on every ENVELOPE-path outbound / at-rest write.
 * Throws unless the payload is a well-formed HybridEnvelope. §6: "anything else leaving the
 * client = test failure." (Apply to envelope paths only; the ContactShare relay is exempt —
 * see the module header.)
 */
export function assertHybridOnly(payload: unknown, context = 'envelope-outbound'): void {
  const klass = classifyEnvelope(payload);
  if (klass !== 'hybrid-envelope') throw new NonHybridCiphertextError(klass, context);
}
