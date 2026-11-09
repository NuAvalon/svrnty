// src/lib/sync/contact-update-gate.ts
// Who a contact update may go to, decided from the address book as it stands when Send runs, whatever list the caller was handed.
// A block is what someone uses against a person who harmed them, so an update that reaches a blocked contact hands them the new
// number. Fail-closed: someone not in the book is refused, and one blocked row refuses that person however many clean rows exist.
import { admitContact } from '../trust/admit-contact';

export type RecipientGate = (fingerprint: string) => boolean;

const norm = (v: unknown) => String(v ?? '').trim().toLowerCase();

export function recipientGateFromBook(rows: unknown): RecipientGate {
  const admitted = new Set<string>();
  const refused = new Set<string>();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (row == null || typeof row !== 'object') continue;
    const c = row as { fingerprint?: unknown; id?: unknown };
    const fp = norm(c.fingerprint || c.id);
    if (fp) (admitContact(row) ? admitted : refused).add(fp);
  }
  return (fingerprint) => {
    const fp = norm(fingerprint);
    return admitted.has(fp) && !refused.has(fp);
  };
}
