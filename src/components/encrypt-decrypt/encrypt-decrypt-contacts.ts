// Filter address-book rows the Encrypt tab may offer.
// Encryptable = SVRNTY (fingerprint + public_key) + stored PQ pubs.
// PQ pubs are only persisted from a signature-verified card (client-store).
// Classical / keyless / blocked / missing-PQ rows are omitted — fail loud in the UI, never listed as encryptable.

import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';
import type { ContactKeys } from '@/lib/crypto/contact-message';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { boundDisplayText } from './encrypt-decrypt-text';

export type EncryptableContact = {
  id: string;
  name: string;
  fingerprint: string;
  keys: ContactKeys;
};

export type ContactRow = {
  id?: string;
  name?: string | null;
  fingerprint?: string | null;
  public_key?: string | null;
  pq_kem_public_key?: string | null;
  pq_sig_public_key?: string | null;
  peer_public_key?: string | null;
  peer_pq_kem_public_key?: string | null;
  peer_pq_sig_public_key?: string | null;
  peer_fingerprint?: string | null;
  peer_name?: string | null;
  blocked?: boolean;
  metadata?: { blocked?: boolean } | null;
};

function isBlocked(row: ContactRow): boolean {
  return row.blocked === true || row.metadata?.blocked === true;
}

function contactKeysFromRow(row: ContactRow): ContactKeys | null {
  const public_key = String(row.public_key || row.peer_public_key || '').trim();
  const pq_kem_public_key = String(row.pq_kem_public_key || row.peer_pq_kem_public_key || '').trim();
  const pq_sig_public_key = String(row.pq_sig_public_key || row.peer_pq_sig_public_key || '').trim();
  const fingerprint = normalizeFingerprintHex(String(row.fingerprint || row.peer_fingerprint || ''));
  if (!public_key || !pq_kem_public_key || !pq_sig_public_key || fingerprint.length < 16) return null;
  if (!isSvrnNetworkContact({ fingerprint, public_key })) return null;
  return { public_key, pq_kem_public_key, pq_sig_public_key, fingerprint };
}

export function isEncryptableContact(row: ContactRow): boolean {
  if (isBlocked(row)) return false;
  return contactKeysFromRow(row) != null;
}

export function toEncryptableContacts(rows: ContactRow[]): EncryptableContact[] {
  const out: EncryptableContact[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    if (isBlocked(row)) continue;
    const keys = contactKeysFromRow(row);
    if (!keys || !keys.fingerprint) continue;
    if (seen.has(keys.fingerprint)) continue;
    seen.add(keys.fingerprint);
    const name =
      boundDisplayText(row.name || row.peer_name) || formatFallbackName(keys.fingerprint);
    out.push({
      id: String(row.id || keys.fingerprint),
      name,
      fingerprint: keys.fingerprint,
      keys,
    });
  }
  return out;
}

function formatFallbackName(fp: string): string {
  return `Contact ${fp.slice(0, 8)}`;
}

/** After decrypt, look up the claimed sender in the encryptable book (exact 64-hex). */
export function findSenderCard(
  contacts: EncryptableContact[],
  claimedFingerprint: string,
): EncryptableContact | null {
  const claimed = normalizeFingerprintHex(claimedFingerprint);
  if (claimed.length !== 64) return null;
  return contacts.find((c) => c.fingerprint === claimed) ?? null;
}
