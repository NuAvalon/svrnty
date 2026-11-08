// src/lib/identity/pq-signing-secret.ts
// Which PQ signing secret (if any) the contact-update SEND path signs with. A move of the inline lookup that lived in
// SoverentityFrontend, BEHAVIOUR UNCHANGED, so it can be pinned by a test (pq-signing-secret.test.ts).
//
// ⚠ DO NOT "FIX" THIS TO READ THE NESTED BUNDLE (`stored.signing.secretKey`) UNTIL RECEIVERS MAP THE SENDER'S pq_sig_public_key.
// Today this returns undefined for every normal identity (genesis stores the nested shape, this reads a flat field), so contact updates are
// signed CLASSICAL and every receiver applies them. If it started returning a key, updates would be signed HYBRID, and a receiver built as
// today (live-book-poll.ts recordToKnownContact omits the PQ key by design) refuses a hybrid signature it cannot check (hybrid.ts: "hybrid sig
// but no PQ public key"): EVERY update from that sender would be silently dropped while the relay still answers 200 and the sender sees "sent".
// Rollout rule: verifiers first, signers later (#775 part 2: receiver maps pq_sig_public_key under the conditions Flint set), THEN change this
// and flip pq-signing-secret.test.ts T1 and T5 together.

import { base64ToUint8 } from '@/lib/crypto/pq';

/** The flat field name of the PrivateKeyBundle shape. Genesis does NOT store this shape in pq_keys. */
export function pqSigningSecretForSend(stored: unknown): Uint8Array | undefined {
  const flat = (stored as { pq_signing_secret_key?: unknown } | null | undefined)?.pq_signing_secret_key;
  if (typeof flat !== 'string' || flat.length === 0) return undefined;
  try {
    return base64ToUint8(flat);
  } catch {
    return undefined; // classical-only if the PQ half can't be read: never block the send on it
  }
}
