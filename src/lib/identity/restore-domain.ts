// src/lib/identity/restore-domain.ts
// One rule for every path that restores an owner onto this device: never write an owner's records under a different passphrase than
// that owner's existing records use. Records aren't tagged with the passphrase that wrote them, so a row either decrypts under the
// current passphrase or fails. A restore that re-keyed the session left the old rows intact and unreadable: the contact book showed
// All (0), the old passphrase stopped working, and nothing said why.
//
// A restore proceeds only when it stays in the owner's existing domain, or when the device has never held this owner. Everything else
// refuses before any key is derived or any record is written. Which passphrase should win when the two differ is a separate product
// decision; this rule doesn't make it, so it is safe under either answer.
//
// The two uses differ in which key the path then writes under:
//  - keeps-open-session: an open session is kept (vault restore, key-file import, plain-backup import). If a session is open, it is
//    the key that will be used, so it must be the owner's. If not, the incoming passphrase becomes the key, so it must open the rows.
//  - always-derives: the session is always re-derived from the typed passphrase (recovery-code restore), so only that passphrase counts.

export const RESTORE_DOMAIN_CODE = 'restore-domain';

export type RestoreKeyUse = 'keeps-open-session' | 'always-derives';

export interface RestoreDomainFacts {
  /** The device holds at least one record for this owner. */
  held: boolean;
  /** A session key is in memory. */
  unlocked: boolean;
  /** The open session decrypts this owner's key record. */
  sessionOpens: boolean;
  /** The incoming passphrase decrypts this owner's key record. */
  passphraseOpens: boolean;
}

export function restoreDomainDecision(use: RestoreKeyUse, facts: RestoreDomainFacts): 'proceed' | 'refuse' {
  if (!facts.held) return 'proceed';
  if (use === 'always-derives') return facts.passphraseOpens ? 'proceed' : 'refuse';
  if (facts.unlocked) return facts.sessionOpens ? 'proceed' : 'refuse';
  return facts.passphraseOpens ? 'proceed' : 'refuse';
}

/**
 * Does this AES key decrypt this stored key record? Fail-closed: a missing, legacy-unencrypted or malformed record is false, and so is
 * any decrypt failure (a GCM tag failure is what "the wrong key" looks like). Reads only.
 */
export async function keyRecordOpens(record: unknown, key: CryptoKey, encVersion: number): Promise<boolean> {
  const r = record as { enc_version?: unknown; iv?: unknown; ciphertext?: unknown } | null | undefined;
  if (!r || r.enc_version !== encVersion || typeof r.iv !== 'string' || typeof r.ciphertext !== 'string') return false;
  try {
    const bytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(r.iv) }, key, bytes(r.ciphertext));
    return true;
  } catch {
    return false;
  }
}

const LEAD = 'This device already has this identity, protected by a different passphrase than the one this restore would use. Restoring would hide the contacts already here, so nothing was changed.';
const WAY_FORWARD: Record<RestoreKeyUse, string> = {
  'keeps-open-session': "Unlock with this device's passphrase first, or restore in a new browser profile.",
  'always-derives': "Use this device's current passphrase here instead, or restore in a new browser profile.",
};

export class RestoreDomainRefused extends Error {
  readonly code = RESTORE_DOMAIN_CODE;

  constructor(use: RestoreKeyUse) {
    super(`${LEAD} ${WAY_FORWARD[use]}`);
    this.name = 'RestoreDomainRefused';
  }
}

/** By code, not instanceof: the restore paths load through dynamic imports. */
export function isRestoreDomainRefusal(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === RESTORE_DOMAIN_CODE;
}
