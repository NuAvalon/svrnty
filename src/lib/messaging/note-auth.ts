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
import { fingerprintMatchesKey } from '@/lib/identity/fingerprint';
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
): Promise<NoteWireV0> {
  const signature = await signWithEnvelope(
    DOMAIN_NOTE,
    noteSigningInput(wire),
    senderPrivateKeyArmored,
    passphrase,
  );
  return { ...wire, public_key: senderPublicKeyArmored, signature };
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
    // (1) fp↔key binding (Canon Invariant-1): the carried key MUST hash to the claimed sender
    //     fingerprint — else an attacker pairs a victim's fingerprint with the attacker's own key.
    if (!(await fingerprintMatchesKey(wire.from_fingerprint, wire.public_key))) return false;
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
