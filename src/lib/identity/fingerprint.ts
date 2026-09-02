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
// (readKey → getFingerprint() → compare). Store the DERIVED fingerprint, never a pasted string.
import { readKey } from 'openpgp';

/** Lowercase hex only — strips spaces, colons, 0x, etc. */
export function normalizeFingerprintHex(raw: string): string {
  return (raw || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

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
    const derived = normalizeFingerprintHex(key.getFingerprint());
    const claimed = normalizeFingerprintHex(claimedFingerprint);
    return derived.length === 40 && claimed === derived;
  } catch {
    return false; // unreadable key → binding cannot be established → refuse
  }
}

/**
 * Link / paste path: derive fingerprint from the armored public key and require the
 * pasted fingerprint to match (full 40 hex, or suffix ≥32 hex). Always returns the
 * DERIVED 40-char fingerprint — never the pasted string.
 *
 * Throws with honest UI copy on malformed key or mismatch.
 */
export async function bindPastedFingerprintToKey(
  pastedFingerprint: string,
  publicKey: string,
): Promise<string> {
  const pk = (publicKey || '').trim();
  if (!pk) {
    throw new Error('not a valid public key');
  }

  let derived: string;
  try {
    const key = await readKey({ armoredKey: pk });
    derived = normalizeFingerprintHex(key.getFingerprint());
  } catch {
    throw new Error('not a valid public key');
  }
  if (derived.length !== 40) {
    throw new Error('not a valid public key');
  }

  const pasted = normalizeFingerprintHex(pastedFingerprint);
  if (!pasted) {
    throw new Error('Paste their SVRNTY fingerprint and public key.');
  }

  const fullMatch = pasted === derived;
  const suffixOk =
    pasted.length >= 32 && pasted.length <= 40 && derived.endsWith(pasted);
  if (!fullMatch && !suffixOk) {
    throw new Error(
      'Fingerprint does not match this public key — paste the key that belongs to that fingerprint.',
    );
  }

  return derived;
}
