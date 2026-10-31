// Filter address-book rows the Notes inbox may send to.
// Sendable = SVRN network contact (fingerprint + public_key) and not blocked.
// Peer PQ pubs are NOT required here — sendNoteToPeer seals to the armored OpenPGP key.
// Classical / keyless / blocked rows are omitted.

import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';
import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { boundDisplayText } from './notes-text';

export type NoteableContact = {
  id: string;
  name: string;
  fingerprint: string;
  publicKeyArmored: string;
  /** The recipient's verified ML-KEM-1024 pubkey (base64), if any. Present ⇒ the note is sealed PQ-hybrid
   *  (HNDL); absent ⇒ the send site fail-closed-skips (never downgrades to classical). */
  pqKemPublicKey?: string;
  /** The recipient's ML-DSA-87 pubkey (base64), if any. With the KEM key it binds the canonical fingerprint
   *  (isCanonicalNoteSender); the send site threads BOTH. */
  pqSigPublicKey?: string;
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
  metadata?: { blocked?: boolean; sample_fingerprint?: string } | null;
};

function isBlocked(row: ContactRow): boolean {
  return row.blocked === true || row.metadata?.blocked === true;
}

function noteableFromRow(row: ContactRow): NoteableContact | null {
  if (isBlocked(row)) return null;
  const publicKeyArmored = String(row.public_key || row.peer_public_key || '').trim();
  const fingerprint = normalizeFingerprintHex(String(row.fingerprint || row.peer_fingerprint || ''));
  if (!publicKeyArmored || fingerprint.length < 16) return null;
  if (!isSvrnNetworkContact({ fingerprint, public_key: publicKeyArmored })) return null;
  // Same admitted record, read tolerantly: a contact row carries the PQ keys as pq_* OR (edge-shaped rows) peer_pq_*.
  const pqKemPublicKey = String(row.pq_kem_public_key || row.peer_pq_kem_public_key || '').trim() || undefined;
  const pqSigPublicKey = String(row.pq_sig_public_key || row.peer_pq_sig_public_key || '').trim() || undefined;
  return {
    id: String(row.id || fingerprint),
    name: boundDisplayText(row.name || row.peer_name) || `Contact ${fingerprint.slice(0, 8)}`,
    fingerprint,
    publicKeyArmored,
    ...(pqKemPublicKey ? { pqKemPublicKey } : {}),
    ...(pqSigPublicKey ? { pqSigPublicKey } : {}),
  };
}

export function isNoteableContact(row: ContactRow): boolean {
  return noteableFromRow(row) != null;
}

export function toNoteableContacts(rows: ContactRow[]): NoteableContact[] {
  const out: NoteableContact[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const contact = noteableFromRow(row);
    if (!contact || seen.has(contact.fingerprint)) continue;
    seen.add(contact.fingerprint);
    out.push(contact);
  }
  return out;
}
