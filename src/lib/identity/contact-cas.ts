// Compare-and-swap for a contact write, as pure orchestration over an injected store, so the interleavings can be tested without IndexedDB.
//
// A contact write touches TWO records: the contact itself and the book manifest (one MAC over every contact's id and version, rebuilt from a
// read of the whole book). A writer that read the book and then lost a race can leave a manifest that does not match the book, and a second
// writer to the same contact overwrites the first. So each attempt:
//   1. reads the contact's stored envelope and the manifest value, and decrypts the contact;
//   2. builds the next record from THAT record (so a retry decides again on the newer one);
//   3. encrypts it and builds the manifest over the post-write book;
//   4. commits in one transaction that first re-reads the envelope and the manifest and writes only if both are exactly what step 1 saw.
// A changed envelope or manifest means someone else wrote in between: the attempt writes nothing and the whole thing runs again. After
// CAS_MAX_ATTEMPTS the call throws ContactConflictError and nothing has been written: never last-writer-wins.
//
// THE BUILD FUNCTION MUST BE PURE. It runs once per attempt, so it can run more than once for one call. It may read the record it is given
// and nothing else; a counter, a push into an outer array or any I/O inside it happens once per attempt.
//
// Run: npx tsx --test src/lib/identity/contact-cas.test.ts

export const CAS_MAX_ATTEMPTS = 5;

/** A write was abandoned after CAS_MAX_ATTEMPTS lost comparisons. Nothing was written. */
export class ContactConflictError extends Error {
  readonly contactId: string;
  readonly attempts: number;
  constructor(contactId: string, attempts: number) {
    super(`contact ${contactId} changed ${attempts} times while it was being updated; nothing was written`);
    this.name = 'ContactConflictError';
    this.contactId = contactId;
    this.attempts = attempts;
  }
}

export type StoredRow = Record<string, unknown> | null;
export interface Expect { store: string; key: string; expected: StoredRow }
export type PutOp = { store: string; value: unknown } | { store: string; delete: string };

/**
 * Whether two stored rows are the same write. An encrypted envelope is compared by iv and ciphertext: every write uses a fresh iv, so no
 * rewrite (even of identical plaintext) reproduces the bytes, and a delete followed by a re-add differs too. Any other row (a legacy
 * plaintext contact, the manifest record) is compared by its JSON. Absent equals absent.
 */
export function sameStoredRow(a: StoredRow, b: StoredRow): boolean {
  if (a === null || b === null) return a === b;
  if (a.enc_version !== undefined || b.enc_version !== undefined) {
    return a.enc_version === b.enc_version && a.iv === b.iv && a.ciphertext === b.ciphertext;
  }
  return JSON.stringify(a) === JSON.stringify(b);
}

export interface CasIO<R extends { id: string }> {
  readRaw(id: string): Promise<StoredRow>;
  manifestKey(owner: string): string;
  readManifest(owner: string): Promise<StoredRow>;
  decrypt(raw: Record<string, unknown>): Promise<R>;
  /** The gates that must hold on the finished record (key binding, verify-before-trust); throws to refuse. Runs on every attempt. */
  finalize(existing: R, next: R): Promise<R>;
  encrypt(next: R): Promise<Record<string, unknown>>;
  /** The manifest write over the post-write book (the target replaced by `next`). */
  manifestOp(owner: string, next: R): Promise<PutOp>;
  /** One transaction: write `ops` only if every `expects` row is still exactly what was read. false = a row changed, nothing was written. */
  commit(expects: Expect[], ops: PutOp[]): Promise<boolean>;
}

export interface CasResult { applied: boolean; attempts: number }

/**
 * The retry rule for a book write that is not an update of one contact (add, remove): run `attempt` until it reports that it committed (or
 * had nothing left to do) by returning true; false means its compare was lost and it runs again from fresh reads. Returns the number of
 * attempts used; throws ContactConflictError after `maxAttempts` lost comparisons, with nothing written. Errors thrown by `attempt` propagate
 * at once.
 */
export async function casRetry(subject: string, attempt: () => Promise<boolean>, maxAttempts: number = CAS_MAX_ATTEMPTS): Promise<number> {
  for (let n = 1; n <= maxAttempts; n++) {
    if (await attempt()) return n;
  }
  throw new ContactConflictError(subject, maxAttempts);
}

/**
 * Update one contact by compare-and-swap. `build` returns the next record, or null for "decided not to write" (nothing is written and it is
 * NOT a conflict). Throws 'Contact not found' if the contact is absent, ContactConflictError after CAS_MAX_ATTEMPTS lost comparisons, and
 * whatever finalize throws.
 */
export async function casUpdateWith<R extends { id: string }>(
  io: CasIO<R>,
  id: string,
  build: (existing: R) => R | null,
  maxAttempts: number = CAS_MAX_ATTEMPTS,
): Promise<CasResult> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const raw = await io.readRaw(id);
    if (!raw) throw new Error('Contact not found');
    const owner = raw.owner_fingerprint as string;
    const manifestBefore = await io.readManifest(owner);
    const existing = await io.decrypt(raw);
    const built = build(existing);
    if (built === null) return { applied: false, attempts: attempt };
    const next = await io.finalize(existing, built);
    const stored = await io.encrypt(next);
    const manifest = await io.manifestOp(owner, next);
    const ok = await io.commit(
      [
        { store: 'contacts', key: id, expected: raw },
        { store: 'settings', key: io.manifestKey(owner), expected: manifestBefore },
      ],
      [{ store: 'contacts', value: stored }, manifest],
    );
    if (ok) return { applied: true, attempts: attempt };
  }
  throw new ContactConflictError(id, maxAttempts);
}
