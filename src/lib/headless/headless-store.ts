// src/lib/headless/headless-store.ts
// Node-backed store for a headless (CLI/docker) svrnty client — the storage half of L2b (headless
// receive/poll/send). The browser client persists contacts + notes in IndexedDB (client-store.ts +
// messaging/store.ts); a headless client has no IndexedDB, so this provides the SAME surfaces the consume
// seams + admit + mutual-apply + note-persist need, backed by an in-memory map with OPTIONAL JSON-file
// persistence. Dependency-light (node:fs only) + storage-agnostic, so a sqlite backend can replace the
// file later with zero caller change.
//
// NOTE: this is a HEADLESS-ONLY module (imports node:fs) — never import it into the browser bundle.

import { readJsonStrict, writeFileAtomic } from './atomic-file';
import { withWriterLock } from './writer-lock';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import type { KnownContact, ContactStore } from '@/lib/sync/consume-mailbox';
import type { NoteRecord, NoteThread } from '@/lib/messaging/types';

/** A stored contact in the headless book — the fields the consume seams + admit + mutual-apply touch. */
export interface HeadlessContact {
  id: string;
  fingerprint: string;
  name?: string;
  email?: string;
  public_key: string; // armored classical (OpenPGP) public key
  trusted?: boolean;
  trust_level?: string;
  epoch?: number;
  version?: number;
  pq_sig_public_key?: string; // base64
  pq_kem_public_key?: string; // base64
  mutual?: { they_trust_me: boolean | null; last_sync: string | null; reciprocal: boolean; last_affirm_at?: string };
  [key: string]: unknown;
}

interface HeadlessData {
  contacts: HeadlessContact[];
  notes: NoteRecord[];
  threads: NoteThread[];
}

/**
 * At-rest encryption envelope for the headless book. When the agent supplies an at-rest key (32 bytes,
 * derived ONCE upstream from its custody master-secret), the on-disk file is an AES-256-GCM envelope
 * instead of plaintext JSON, so a headless agent's notes/contacts are not plaintext on a volume that
 * iCloud/Android auto-backup can copy (the book and its .bak are both sealed; Flint
 * #168811). Symmetric + SYNCHRONOUS (node:crypto) so flush() stays sync (no ripple into the consume seams);
 * the key is already KDF-derived upstream, this is not a per-flush KDF. No key → plaintext JSON (dev/test
 * parity). The HNDL hybrid envelope is a WIRE concern and is stripped on receive — at rest we keep ONE
 * symmetric key, not per-message hybrid (Peter #168761 / Flint #168811 / Archie: keep-at-rest-enc).
 *
 * NOT covered (known residuals, Flint #275 N1/N2): this is confidentiality + per-file integrity only. A writer on
 * the filesystem can still roll the book back to an older valid envelope (e.g. the .bak), and with a key present a
 * plaintext file is still accepted as a one-way migration.
 */
interface AtRestEnvelope {
  svrnty_at_rest: 1;
  alg: 'aes-256-gcm';
  iv: string; // base64, 12 bytes
  ct: string; // base64 ciphertext
  tag: string; // base64, 16-byte GCM auth tag
}

function encryptAtRest(plaintext: string, key: Uint8Array): AtRestEnvelope {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    svrnty_at_rest: 1,
    alg: 'aes-256-gcm',
    iv: Buffer.from(iv).toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

function decryptAtRest(env: AtRestEnvelope, key: Uint8Array): string {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(env.tag, 'base64'));
  // GCM auth failure (wrong key / tampered file) THROWS here — the caller must not swallow it into a
  // fresh-start, or the agent silently loses its book. decryptAtRest never returns garbage.
  return Buffer.concat([decipher.update(Buffer.from(env.ct, 'base64')), decipher.final()]).toString('utf8');
}

function isAtRestEnvelope(obj: unknown): obj is AtRestEnvelope {
  return !!obj && typeof obj === 'object' && (obj as { svrnty_at_rest?: unknown }).svrnty_at_rest === 1;
}

/**
 * The previous file kept as <path>.bak must never be MORE exposed than the file it backs up. When we hold an
 * at-rest key and the previous file is still plaintext (the first flush after migrating), keep it sealed with the
 * same key: still restorable with that key, but no plaintext copy of the book stays on disk (Flint R3 on #275).
 */
function sealBackup(previousText: string, key: Uint8Array): string {
  try {
    if (isAtRestEnvelope(JSON.parse(previousText))) return previousText; // already sealed
  } catch { /* not JSON: seal it anyway */ }
  return JSON.stringify(encryptAtRest(previousText, key));
}

/**
 * In-memory book with optional JSON-file persistence. Writes are atomic (tmp + rename, previous good copy
 * kept as .bak) and an existing file that won't parse is an error, never "start fresh" (atomic-file.ts).
 * With lockDir set, every mutation is one locked unit: take the agent-dir writer lock, RE-READ the file,
 * apply this one change, flush, release. A concurrent writer's records survive (writer-lock.ts). Reads use
 * the snapshot from the last load or mutation. The consume core (consume-mailbox.ts) drives this ONLY through asContactStore() + the
 * note/affirm seams (headless-client.ts), so the shape stays swappable.
 */
export class HeadlessStore {
  private data: HeadlessData = { contacts: [], notes: [], threads: [] };
  private readonly path: string | null;
  private readonly lockDir: string | null;
  private readonly atRestKey: Uint8Array | null;

  constructor(opts: { path?: string; lockDir?: string; atRestKey?: Uint8Array } = {}) {
    this.path = opts.path ?? null;
    this.lockDir = opts.lockDir ?? null;
    this.atRestKey = opts.atRestKey ?? null;
    if (this.atRestKey && this.atRestKey.length !== 32) {
      throw new Error('HeadlessStore atRestKey must be 32 bytes (AES-256-GCM)');
    }
    this.load();
  }

  private load(): void {
    if (!this.path) return;
    // A torn or corrupt book must stop the command: "start fresh" here meant the next flush
    // persisted an empty book over the real one (Flint 2026-10-24). Main's fail-closed read wins over the
    // S14 branch's old "unparseable -> start fresh".
    let parsed = readJsonStrict<Partial<HeadlessData> | AtRestEnvelope | null>(this.path, null);
    if (isAtRestEnvelope(parsed)) {
      // Encrypted file. Refuse to clobber it: no key, or a wrong key (GCM auth throws), must NOT
      // silently start-fresh — that would delete the agent's book. Surface the error to the caller.
      if (!this.atRestKey) {
        throw new Error('HeadlessStore: file is encrypted at rest but no atRestKey was supplied');
      }
      parsed = JSON.parse(decryptAtRest(parsed, this.atRestKey)) as Partial<HeadlessData>;
    }
    // plaintext file + atRestKey present = legacy/migration: the next flush() re-writes it encrypted.
    const book = parsed as Partial<HeadlessData> | null;
    this.data = {
      contacts: book?.contacts ?? [],
      notes: book?.notes ?? [],
      threads: book?.threads ?? [],
    };
  }

  private flush(): void {
    if (!this.path) return;
    const json = JSON.stringify(this.data, null, 2);
    // at-rest: encrypt when a key is present (prod agents MUST pass one); plaintext only for dev/test parity.
    const key = this.atRestKey;
    writeFileAtomic(
      this.path,
      key ? JSON.stringify(encryptAtRest(json, key)) : json,
      key ? { backupTransform: (prev) => sealBackup(prev, key) } : {},
    );
  }

  /** One read-modify-write unit: under the writer lock, re-read, apply, flush (see class doc). */
  private mutate(apply: () => void): void {
    if (!this.path || !this.lockDir) {
      apply();
      this.flush();
      return;
    }
    withWriterLock(this.lockDir, () => {
      this.load();
      apply();
      this.flush();
    });
  }

  // --- contacts ---
  getContactByFingerprint(fingerprint: string): HeadlessContact | null {
    return this.data.contacts.find((c) => c.fingerprint === fingerprint) ?? null;
  }

  /**
   * Add or merge a contact, keyed by FINGERPRINT only (#724). A row's identity never changes here:
   *  - an id already held by a DIFFERENT fingerprint is refused (that collision used to overwrite the other contact's
   *    fingerprint and keys while keeping its trust: a substitution);
   *  - on a fingerprint match the row keeps its own id, and the key set (public_key + both PQ keys) is replaced as ONE
   *    unit when the incoming record carries any key field, so an old key can't survive under a new one (a mixed set
   *    hashes to nothing). A record with no key fields (a metadata/trust update) leaves the keys untouched.
   * The fingerprint↔key binding itself is checked by the callers that take a card from outside (admit, join, gate).
   */
  upsertContact(c: HeadlessContact): void {
    this.mutate(() => {
      const i = this.data.contacts.findIndex((x) => x.fingerprint === c.fingerprint);
      const clash = this.data.contacts.findIndex((x) => x.id === c.id && x.fingerprint !== c.fingerprint);
      if (clash !== -1) {
        throw new Error('headless upsertContact: that id belongs to a different fingerprint; refusing (a new fingerprint is a new contact)');
      }
      if (i === -1) {
        this.data.contacts.push(c);
        return;
      }
      const old = this.data.contacts[i];
      const keyed = 'public_key' in c || 'pq_sig_public_key' in c || 'pq_kem_public_key' in c;
      const keys = keyed
        ? { public_key: c.public_key, pq_sig_public_key: c.pq_sig_public_key, pq_kem_public_key: c.pq_kem_public_key }
        : {};
      this.data.contacts[i] = { ...old, ...c, ...keys, id: old.id, fingerprint: old.fingerprint };
    });
  }

  updateContact(id: string, patch: Partial<HeadlessContact>): void {
    this.mutate(() => {
      const i = this.data.contacts.findIndex((x) => x.id === id);
      if (i === -1) throw new Error(`headless updateContact: contact ${id} not found`);
      this.data.contacts[i] = { ...this.data.contacts[i], ...patch, id };
    });
  }

  listContacts(): HeadlessContact[] {
    return [...this.data.contacts];
  }

  // --- notes (mirror the messaging store surface the note-accept uses) ---
  putNote(n: NoteRecord): void {
    this.mutate(() => {
      // note_id is sender-chosen: keyed on it alone, a peer who knew one of our ids (our outbound copies)
      // could replace that row. Same sender + direction + id = redelivery, re-persisted harmlessly (Chaos #170).
      const i = this.data.notes.findIndex((x) =>
        x.note_id === n.note_id && x.direction === n.direction && x.from_fingerprint === n.from_fingerprint);
      if (i === -1) this.data.notes.push(n);
      else this.data.notes[i] = n;
    });
  }
  listNotes(): NoteRecord[] {
    return [...this.data.notes];
  }
  putThread(t: NoteThread): void {
    this.mutate(() => {
      const i = this.data.threads.findIndex((x) => x.thread_id === t.thread_id);
      if (i === -1) this.data.threads.push(t);
      else this.data.threads[i] = t;
    });
  }
  listThreads(): NoteThread[] {
    return [...this.data.threads];
  }

  /**
   * The ContactStore seam consumeInboundContactUpdates needs for the contact-update path. lookup returns
   * the verify-seam identity + the record to apply onto; persist writes an applied contact-update back.
   */
  asContactStore(): ContactStore {
    return {
      lookup: async (fingerprint: string): Promise<KnownContact | null> => {
        const rec = this.getContactByFingerprint(fingerprint);
        if (!rec) return null; // whitelist-on-fetch (I-2): not in book → dropped unread
        return { known: toKnownContact(rec), current: rec as unknown as StoredContact };
      },
      persist: async (id: string, next: StoredContact): Promise<void> => {
        this.updateContact(id, next as Partial<HeadlessContact>);
      },
    };
  }
}

/** Project a headless contact onto the verify seam's KnownContactIdentity (pure — mirrors recordToKnownContact). */
export function toKnownContact(rec: HeadlessContact): KnownContactIdentity {
  return {
    fingerprint: rec.fingerprint,
    epoch: rec.epoch ?? 0,
    version: rec.version ?? 0,
    classicalPublicKeyArmored: rec.public_key,
  };
}
