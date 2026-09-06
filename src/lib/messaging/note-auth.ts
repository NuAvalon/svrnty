// src/lib/messaging/note-auth.ts
// Sender AUTHENTICATION for notes v0 — closes the forgeable-sender gap (Flint #55, Apollo client-owner).
//
// THE GAP. sealNoteTo only ENCRYPTS to the recipient's key; it does not SIGN. So `from_fingerprint`
// on the wire is attacker-chosen, and acceptInboundNote's only gate was isAdmitted(from_fingerprint)
// — but admission ≠ authentication. Anyone who knows a recipient's public key and an admitted
// contact's (public) fingerprint could deposit a note "from" that contact. This module makes the
// sender PROVE possession of the identity key behind `from_fingerprint` before a note is admitted,
// restoring the claim-ladder's Rung-1 ("strangers cannot place a note").
//
// EXACT MIRROR of relay/mailbox-auth.ts verifyOwner (the proven template): sign a canonical() input
// under a domain tag with signWithEnvelope; on receipt bind public_key↔fingerprint with
// fingerprintMatchesKey (Canon Invariant-1) THEN verify with verifyWithEnvelope. The identity key is
// openpgp (fingerprint.ts / sign-envelope.ts) — the SAME model mailbox-auth uses, NOT the
// ratified-but-unshipped raw-Ed25519 model-B. Classical-only signing at launch (mailbox-auth is
// classical too); hybrid note-signing is a later, additive change (carry the sender's pq pubkey +
// pass pqSigningSecretKey/pqSigningPublicKey through — the 0.1 envelope already binds the suite).
//
// Run tests: npx tsx --test src/lib/messaging/note-auth.test.ts

import { signWithEnvelope, verifyWithEnvelope } from '@/lib/crypto/sign-envelope';
import { fingerprintMatchesKey, KEM_PUB_LEN, SIG_PUB_LEN } from '@/lib/identity/fingerprint';
import { DOMAIN_NOTE } from './domains';
import { noteSigningInput } from './canonical';
import type { NoteWireV0 } from './types';

/**
 * Sign a note wire and attach the sender's {public_key, signature}. The signature is over
 * noteSigningInput(wire) — which EXCLUDES `signature`/`public_key` — so it is stable whether or not
 * the attachment is present, and it commits to `from_fingerprint` and `body`. The returned wire is
 * what gets sealed + deposited.
 */
export async function signNoteWire(
  wire: NoteWireV0,
  senderPublicKeyArmored: string,
  senderPrivateKeyArmored: string,
  passphrase: string,
  senderPqKemPublicKey?: string, // §5: sender's ML-KEM-1024 public (base64) — canonical-fp binding
  senderPqSigPublicKey?: string, // §5: sender's ML-DSA-87 public (base64) — canonical-fp binding
): Promise<NoteWireV0> {
  // Sign over noteSigningInput(wire) — computed on the base wire so the pinned DOMAIN_NOTE preimage is
  // byte-unchanged (public_key + the §5 PQ pubkeys are all EXCLUDED from the preimage; see canonical.ts).
  const signature = await signWithEnvelope(
    DOMAIN_NOTE,
    noteSigningInput(wire),
    senderPrivateKeyArmored,
    passphrase,
  );
  const signed: NoteWireV0 = { ...wire, public_key: senderPublicKeyArmored, signature };
  // §5: carry the sender's PQ pubkeys so verifyNoteSender can recompute a 64-hex canonical fp. They bind
  // via the fp-match, NOT the signature. Only when BOTH are present (a canonical identity); a classical
  // sender omits them → the verifier's 40-hex OpenPGP fallback.
  if (senderPqKemPublicKey && senderPqSigPublicKey) {
    signed.pq_kem_public_key = senderPqKemPublicKey;
    signed.pq_sig_public_key = senderPqSigPublicKey;
  }
  return signed;
}

/**
 * True iff the note carries a valid sender signature AND its public_key binds to `from_fingerprint`.
 * Returns false (never throws) on any missing field, fp↔key mismatch, or bad signature.
 *
 * This is the AUTHENTICATION floor only — it proves WHO signed. Whether that authenticated sender is
 * allowed to reach you (isAdmitted) is a SEPARATE, later check (see acceptInboundNote). The two
 * failures are distinct: an unsigned/forged note fails HERE; a genuine stranger fails at admit.
 */
export async function verifyNoteSender(wire: NoteWireV0): Promise<boolean> {
  if (!wire.public_key || !wire.signature) return false; // unsigned ⇒ unauthenticated
  try {
    // (0) §5 defense-in-depth: length-gate the PQ pubkeys at the boundary (fail-loud). A CANONICAL note
    //     carries BOTH kem+sig at FIPS length; a half-present or wrong-length pair is malformed ⇒ refuse
    //     rather than silently fall back to the 40-hex OpenPGP path. (atob throws on bad base64 → caught.)
    const hasKem = typeof wire.pq_kem_public_key === 'string';
    const hasSig = typeof wire.pq_sig_public_key === 'string';
    if (hasKem !== hasSig) return false; // half-present ⇒ malformed
    if (hasKem && hasSig) {
      if (atob(wire.pq_kem_public_key!).length !== KEM_PUB_LEN) return false;
      if (atob(wire.pq_sig_public_key!).length !== SIG_PUB_LEN) return false;
    }
    // (1) fp↔key binding (Canon Invariant-1): the carried key MUST hash to the claimed sender
    //     fingerprint — else an attacker pairs a victim's fingerprint with the attacker's own key. §5:
    //     thread the PQ pubkeys so a 64-hex CANONICAL id recomputes SHA256(sign‖enc‖kem‖sig) and matches;
    //     a classical (40-hex) sender omits them → fingerprintMatchesKey falls back to the OpenPGP path.
    //     This binding runs BEFORE the signature (step 2): the PQ pubkeys are self-protected by the fp-match.
    if (!(await fingerprintMatchesKey(wire.from_fingerprint, wire.public_key, {
      kem_public_key: wire.pq_kem_public_key,
      sig_public_key: wire.pq_sig_public_key,
    }))) return false;
    // (2) possession: the note content (incl. from_fingerprint) was signed by that key under DOMAIN_NOTE.
    return await verifyWithEnvelope(
      DOMAIN_NOTE,
      noteSigningInput(wire),
      wire.signature,
      wire.public_key,
    );
  } catch {
    return false; // any crypto/parse failure ⇒ refuse (fail-closed)
  }
}
