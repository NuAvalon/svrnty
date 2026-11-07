// src/lib/contacts/book-import.ts
// The .json contact-book IMPORT. Sibling of book-export.ts (the export firewall), and the same rule in the other direction.
//
// A plaintext file is an untrusted input: anyone can hand you one. So an import carries IDENTITY and nothing else.
//   - Every imported contact lands 'unverified', whatever the file says. Moving trust to a new device is the encrypted vault's job, not this file's.
//   - Nothing about trust, verification, blocking, notes, tags or sync state is read from the file: no `metadata`, no `trusted`, no `verification`, no
//     `epoch` / `version` / `psi_epoch`. The object handed to the store is built field by field (NO spread), so a key the file adds cannot ride along.
//   - The fingerprint must be in the one standard form (64 lowercase hex). The store's binding check accepts respelled forms (upper case, punctuation,
//     a shorter prefix) and stores the raw string it was given, so a respelled fingerprint of someone already in the book would miss the store's
//     one-record-per-fingerprint index and create a SECOND, unblocked record for them. Our own export only ever writes the standard form.
//   - The store's own checks stay exactly as strict: addContact refuses any contact whose fingerprint does not match its keys (the post-quantum
//     keys are part of that match, so they are passed through for the check to use), and refuses to create a trusted contact without a real
//     owner verification. This module adds no way around either.
//   - Size is bounded before any work is done: text over 52 million characters is refused before it is parsed, a file with too many contacts is refused whole, and a contact with an oversized key is refused
//     before the store's (expensive) binding check runs on it. Text fields are cleaned and capped.
//
// One contact at a time: a contact that fails is counted and named, and the rest are still imported.
// Run: npx tsx --test src/lib/contacts/book-import.test.ts

/** The pasted text is too large to parse. The message is shown to the user as it is. */
export class ContactBookTooLarge extends Error {
  constructor() {
    super('That file is too large to import.');
    this.name = 'ContactBookTooLarge';
  }
}

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

/** What the store did with a contact: made a new record, or already had one under that fingerprint. A store that says nothing is counted as added. */
export type AddOutcome = 'added' | 'existing';

export interface ImportSummary {
  total: number;
  added: number;
  /** Contacts the book already had under the same fingerprint (nothing was written for them). */
  existing: number;
  failed: ImportFailure[];
  /** Set when the whole file was refused before any contact was tried. */
  refused?: string;
}

export const MAX_CONTACTS_PER_FILE = 5000;
/**
 * The text-size cap agrees with the contact cap. MEASURED, not guessed: a canonical exported contact is about 6,750 characters (public key 840, ML-KEM key 2,092,
 * ML-DSA key 3,456, plus fingerprint, name, email and the export's indentation), so MAX_CONTACTS_PER_FILE contacts is about 33.7 million characters. This cap is
 * that times 1.5, rounded up: a legitimate full export is never refused here, and anything beyond it is not a contact book.
 */
export const MAX_FILE_CHARS = 52_000_000;
const MAX_KEY_CHARS = 16384;
const MAX_NAME = 120;
const MAX_EMAIL = 254;
const MAX_LABEL = 60;
/** At most this many names are listed in a message; the rest are counted ("and K more"). */
export const MAX_NAMED = 5;
const CANONICAL_FP = /^[0-9a-f]{64}$/;

const asString = (v: unknown): string => (typeof v === 'string' ? v : '');

function cleanText(v: unknown, max: number): string {
  return asString(v).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/** A name from an untrusted file or backup, made safe to show: control characters removed, length capped. */
export function safeContactLabel(v: unknown): string {
  const s = cleanText(v, 100000);
  if (!s) return 'Unnamed contact';
  return s.length > MAX_LABEL ? `${s.slice(0, MAX_LABEL)}…` : s;
}

/** Plain words for why the store refused; the raw error text is never shown. */
export function storeRefusalReason(err: unknown): string {
  const m = err instanceof Error ? err.message : '';
  if (m.includes('binding failed')) return 'its key does not match its fingerprint';
  if (m.includes('verify-before-trust')) return 'it was marked trusted without a recorded verification';
  if (m.includes('Session locked')) return 'the app is locked';
  return 'could not be saved';
}

/**
 * The entries of a parsed contact-book file: the export's `{ contacts: [...] }`, or a bare array. Throws SyntaxError on text that is not JSON,
 * which is the caller's "Invalid JSON format".
 */
export function contactBookEntries(text: string): unknown[] {
  // Refused BEFORE the parse: JSON.parse of a huge paste would freeze the tab long before the per-file contact cap could be asked.
  if (text.length > MAX_FILE_CHARS) throw new ContactBookTooLarge();
  const parsed: unknown = JSON.parse(text);
  if (Array.isArray(parsed)) return parsed;
  const list = (parsed as { contacts?: unknown } | null)?.contacts;
  return Array.isArray(list) ? list : [];
}

/** Why an entry cannot be imported, in plain words, or null when it can. */
export function entryProblem(entry: unknown): string | null {
  if (!entry || typeof entry !== 'object') return 'it has no fingerprint and key';
  const c = entry as Record<string, unknown>;
  const fingerprint = asString(c.fingerprint);
  const publicKey = asString(c.public_key);
  if (!fingerprint || !publicKey) return 'it has no fingerprint and key';
  if (!CANONICAL_FP.test(fingerprint)) return 'its fingerprint is not in the standard form';
  if (publicKey.length > MAX_KEY_CHARS || asString(c.pq_kem_public_key).length > MAX_KEY_CHARS || asString(c.pq_sig_public_key).length > MAX_KEY_CHARS) {
    return 'it has a key that is too long';
  }
  return null;
}

/** Project one file entry onto what an import may hand the store, or null when the entry cannot be imported. */
export function toImportedContact(entry: unknown): ImportedContact | null {
  if (entryProblem(entry) !== null) return null;
  const c = entry as Record<string, unknown>;
  const out: ImportedContact = {
    name: cleanText(c.name, MAX_NAME) || cleanText(c.display_name, MAX_NAME) || 'Unknown',
    email: cleanText(c.email, MAX_EMAIL),
    fingerprint: asString(c.fingerprint),
    public_key: asString(c.public_key),
    trust_level: 'unverified',
  };
  const kem = asString(c.pq_kem_public_key);
  const sig = asString(c.pq_sig_public_key);
  if (kem) out.pq_kem_public_key = kem;
  if (sig) out.pq_sig_public_key = sig;
  return out;
}

export async function importContactBook(entries: unknown[], add: (contact: ImportedContact) => Promise<AddOutcome | void>): Promise<ImportSummary> {
  const summary: ImportSummary = { total: entries.length, added: 0, existing: 0, failed: [] };
  if (entries.length > MAX_CONTACTS_PER_FILE) {
    summary.refused = `That file has more than ${MAX_CONTACTS_PER_FILE.toLocaleString('en-US')} contacts, so nothing was imported.`;
    return summary;
  }
  for (const entry of entries) {
    const label = safeContactLabel((entry as { name?: unknown } | null)?.name ?? (entry as { display_name?: unknown } | null)?.display_name);
    const problem = entryProblem(entry);
    const contact = problem === null ? toImportedContact(entry) : null;
    if (!contact) {
      summary.failed.push({ label, reason: problem ?? 'it cannot be imported' });
      continue;
    }
    try {
      const outcome = await add(contact);
      if (outcome === 'existing') summary.existing++;
      else summary.added++;
    } catch (err) {
      summary.failed.push({ label, reason: storeRefusalReason(err) });
    }
  }
  return summary;
}

/** The line for the dialog when something did not go cleanly (a refusal, a failure, or contacts that were already there), or null when every contact was new. */
export function importMessage(s: ImportSummary): string | null {
  if (s.refused) return s.refused;
  const counts = `Added ${s.added}, already in your contacts ${s.existing}`;
  if (s.failed.length === 0) return s.existing > 0 ? `${counts}.` : null;
  const shown = s.failed.slice(0, MAX_NAMED).map((f) => `${f.label} (${f.reason})`).join('; ');
  const more = s.failed.length > MAX_NAMED ? `; and ${s.failed.length - MAX_NAMED} more` : '';
  return `${counts}, not imported ${s.failed.length} of ${s.total}. Not imported: ${shown}${more}.`;
}
