// src/lib/contacts/book-import.ts
// The .json contact-book IMPORT. Sibling of book-export.ts (the export firewall), and the same rule in the other direction.
//
// A plaintext file is an untrusted input: anyone can hand you one. So an import carries IDENTITY and nothing else.
//   - Every imported contact lands 'unverified', whatever the file says. Moving trust to a new device is the encrypted vault's job, not this file's.
//   - Nothing about trust, verification, blocking, notes, tags or sync state is read from the file: no `metadata`, no `trusted`, no `verification`, no
//     `epoch` / `version` / `psi_epoch`. The object handed to the store is built field by field (NO spread), so a key the file adds cannot ride along.
//   - The store's own checks stay exactly as strict: addContact refuses any contact whose fingerprint does not match its keys (the post-quantum
//     keys are part of that match, so they are passed through for the check to use), and refuses to create a trusted contact without a real
//     owner verification. This module adds no way around either.
//
// One contact at a time: a contact that fails is counted and named, and the rest are still imported.
// Run: npx tsx --test src/lib/contacts/book-import.test.ts

/** What an import hands the store. Nothing else is ever passed. */
export interface ImportedContact {
  name: string;
  email: string;
  fingerprint: string;
  public_key: string;
  pq_kem_public_key?: string;
  pq_sig_public_key?: string;
  trust_level: 'unverified';
}

export interface ImportFailure {
  /** The name the file gave the contact, made safe to show (control characters removed, length capped). */
  label: string;
  reason: string;
}

export interface ImportSummary {
  total: number;
  /** Contacts the store now holds (newly added, or already there under the same fingerprint). */
  imported: number;
  failed: ImportFailure[];
}

const MAX_LABEL = 60;
const SHOWN = 5;

const asString = (v: unknown): string => (typeof v === 'string' ? v : '');

function safeLabel(v: unknown): string {
  const s = asString(v).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (!s) return 'Unnamed contact';
  return s.length > MAX_LABEL ? `${s.slice(0, MAX_LABEL)}…` : s;
}

/** Plain words for why the store refused; the raw error text is never shown. */
function reasonFor(err: unknown): string {
  const m = err instanceof Error ? err.message : '';
  if (m.includes('binding failed')) return 'its key does not match its fingerprint';
  if (m.includes('Session locked')) return 'the app is locked';
  return 'could not be saved';
}

/**
 * The entries of a parsed contact-book file: the export's `{ contacts: [...] }`, or a bare array. Throws SyntaxError on text that is not JSON,
 * which is the caller's "Invalid JSON format".
 */
export function contactBookEntries(text: string): unknown[] {
  const parsed: unknown = JSON.parse(text);
  if (Array.isArray(parsed)) return parsed;
  const list = (parsed as { contacts?: unknown } | null)?.contacts;
  return Array.isArray(list) ? list : [];
}

/** Project one file entry onto what an import may hand the store, or null when it names no fingerprint and key. */
export function toImportedContact(entry: unknown): ImportedContact | null {
  if (!entry || typeof entry !== 'object') return null;
  const c = entry as Record<string, unknown>;
  const fingerprint = asString(c.fingerprint);
  const public_key = asString(c.public_key);
  if (!fingerprint || !public_key) return null;
  const out: ImportedContact = {
    name: asString(c.name) || asString(c.display_name) || 'Unknown',
    email: asString(c.email),
    fingerprint,
    public_key,
    trust_level: 'unverified',
  };
  const kem = asString(c.pq_kem_public_key);
  const sig = asString(c.pq_sig_public_key);
  if (kem) out.pq_kem_public_key = kem;
  if (sig) out.pq_sig_public_key = sig;
  return out;
}

export async function importContactBook(entries: unknown[], add: (contact: ImportedContact) => Promise<unknown>): Promise<ImportSummary> {
  const summary: ImportSummary = { total: entries.length, imported: 0, failed: [] };
  for (const entry of entries) {
    const contact = toImportedContact(entry);
    const label = safeLabel((entry as { name?: unknown } | null)?.name ?? (entry as { display_name?: unknown } | null)?.display_name);
    if (!contact) {
      summary.failed.push({ label, reason: 'it has no fingerprint and key' });
      continue;
    }
    try {
      await add(contact);
      summary.imported++;
    } catch (err) {
      summary.failed.push({ label, reason: reasonFor(err) });
    }
  }
  return summary;
}

/** One line for the dialog, or null when everything imported. */
export function importMessage(s: ImportSummary): string | null {
  if (s.failed.length === 0) return null;
  const shown = s.failed.slice(0, SHOWN).map((f) => `${f.label} (${f.reason})`).join('; ');
  const more = s.failed.length > SHOWN ? `; and ${s.failed.length - SHOWN} more` : '';
  return `Imported ${s.imported} of ${s.total}. Not imported: ${shown}${more}.`;
}
