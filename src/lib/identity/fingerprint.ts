// src/lib/identity/fingerprint.ts
//
// Shared fingerprint↔key binding verification — C2 / Canon Invariant-1 (Flint KB#85781).
//
// A fingerprint is a *commitment* to a public key: it is minted as
// getFingerprint(public_key) (see browser-identity.ts / core.ts). Any path that imports a
// contact from an untrusted source (a relay link, a pasted card, a bulk import) must
// recompute the fingerprint from the presented key and refuse a mismatch — otherwise an
// attacker who pairs a victim's REAL fingerprint with their OWN key (and the victim's name)
// defeats the out-of-band "is this your fingerprint?" verification the whole trust model
// rests on: the user confirms a real fingerprint while the stored key is the attacker's.
//
// Mirrors the proven verified add-path in lib/contacts/robust-db.ts
// (readKey → getFingerprint().toUpperCase() → compare).
import { readKey } from 'openpgp';

/**
 * True iff `publicKey` actually hashes to `claimedFingerprint`.
 * Returns false (never throws) on a mismatch, an unreadable key, or a missing input —
 * callers decide whether a false result is a hard refusal or a loud UI warning.
 */
export async function fingerprintMatchesKey(
  claimedFingerprint: string,
  publicKey: string,
): Promise<boolean> {
  if (!claimedFingerprint || !publicKey) return false;
  try {
    const key = await readKey({ armoredKey: publicKey });
    return key.getFingerprint().toUpperCase() === claimedFingerprint.toUpperCase();
  } catch {
    return false; // unreadable key → binding cannot be established → refuse
  }
}
