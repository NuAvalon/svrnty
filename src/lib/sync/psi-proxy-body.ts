// Allowlist for the same-origin PSI proxy body. Device-local tags / blocked
// flags / group labels must never be copied onto the satellite request.
//
// Two body shapes ride this proxy (PSISyncOptions.pqWrap, mutual-trust-sync.ts) — a given request is
// ALWAYS exactly one shape, never both:
//  - CLASSICAL (pqWrap absent — today's live wire): plaintext PSI_BODY_KEYS below.
//  - SEALED (pqWrap set — dark until isPSIDiscoveryLive flips, psi-wire-seal.ts): the body IS a
//    MailboxEnvelopePackage {v,alg,mailbox_fp,epk,kem_ct,nonce,ct} (mailbox-envelope.ts) — opaque
//    ML-KEM+X25519 ciphertext. The blinded_set/signature/etc. fields live INSIDE `ct`, encrypted; this
//    proxy never sees them again once PQ-wrap is live. It forwards the fixed envelope shape through
//    byte-for-byte, same allowlist discipline as the classical fields — nothing outside either known
//    shape is ever copied onto the satellite request.

export const PSI_BODY_KEYS = [
  'initiator_fingerprint',
  'responder_fingerprint',
  'blinded_set',
  'reblinded_initiator_set',
  'signature',
] as const;

/** MailboxEnvelopePackage field names (mailbox-envelope.ts) — opaque sealed-envelope passthrough. */
export const PSI_ENVELOPE_KEYS = ['v', 'alg', 'mailbox_fp', 'epk', 'kem_ct', 'nonce', 'ct'] as const;

const MAX_STRING_LEN = 8192;
// `ct` carries the whole AES-256-GCM ciphertext of the PSI body (a blinded_set can run to many
// contacts) — an order of magnitude above the classical per-field cap, not unbounded.
const MAX_CT_LEN = 1_048_576;

function pickSealedEnvelope(raw: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const key of PSI_ENVELOPE_KEYS) {
    if (!(key in raw)) continue;
    const value = raw[key];
    if (key === 'v') {
      if (value === 1) body[key] = value;
      continue;
    }
    if (typeof value !== 'string') continue;
    const cap = key === 'ct' ? MAX_CT_LEN : MAX_STRING_LEN;
    if (value.length <= cap) body[key] = value;
  }
  return body;
}

export function pickPsiBody(raw: Record<string, unknown>): Record<string, unknown> {
  // Sealed envelope: discriminate on the pinned `v:1` tag + `alg` (MailboxEnvelopePackage). This only
  // ever SELECTS which strict allowlist applies — it can't widen either one, so a caller trying to ride
  // extra fields in on a forged `v`/`alg` pair still gets nothing beyond the 7 known envelope keys.
  if (raw.v === 1 && typeof raw.alg === 'string') {
    return pickSealedEnvelope(raw);
  }

  const body: Record<string, unknown> = {};
  for (const key of PSI_BODY_KEYS) {
    if (!(key in raw)) continue;
    const value = raw[key];
    if (typeof value === 'string' && value.length <= MAX_STRING_LEN) body[key] = value;
    else if (Array.isArray(value) && value.every((x) => typeof x === 'string')) {
      body[key] = value.slice(0, 4096);
    }
  }
  return body;
}
