// src/lib/sync/contact-update-gate.ts
// Who an outbound message may go to (contact updates, notes, an agent's notes), decided from the address book as it stands when Send runs,
// whatever list the caller was handed. A block is what someone uses against a person who harmed them, so anything that reaches a blocked
// contact hands them a way back in. Fail-closed: someone not in the book is refused, and one blocked row refuses that person however many clean rows exist.
import { admitContact } from '../trust/admit-contact';
import { normalizeFingerprintHex } from '../identity/fingerprint';

export type RecipientGate = (fingerprint: string) => boolean;

const norm = (v: unknown) => normalizeFingerprintHex(String(v ?? ''));

/** The person a row is about, read the way the notes list reads it (a row may carry them as peer_fingerprint). */
function rowFingerprint(row: { fingerprint?: unknown; peer_fingerprint?: unknown; id?: unknown }): string {
  return norm(row.fingerprint || row.peer_fingerprint || row.id);
}

export function recipientGateFromBook(rows: unknown): RecipientGate {
  const admitted = new Set<string>();
  const refused = new Set<string>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (row == null || typeof row !== 'object') continue;
    const fp = rowFingerprint(row as { fingerprint?: unknown; peer_fingerprint?: unknown; id?: unknown });
    if (fp) (admitContact(row) ? admitted : refused).add(fp);
  }
  return (fingerprint) => {
    const fp = norm(fingerprint);
    return admitted.has(fp) && !refused.has(fp);
  };
}

/**
 * For a flow where someone new is normal: a joiner has usually never met the giver of an invite, so absence from the book proves nothing.
 * True only for someone with a blocked row. A book that isn't a list can't vouch for anyone, so everyone reads as blocked.
 */
export function blockedInBook(rows: unknown): RecipientGate {
  if (!Array.isArray(rows)) return () => true;
  const blocked = new Set<string>();
  for (const row of rows) {
    if (row == null || typeof row !== 'object' || admitContact(row)) continue;
    const fp = rowFingerprint(row as { fingerprint?: unknown; peer_fingerprint?: unknown; id?: unknown });
    if (fp) blocked.add(fp);
  }
  return (fingerprint) => blocked.has(norm(fingerprint));
}
