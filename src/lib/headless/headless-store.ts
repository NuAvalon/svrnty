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
import { mergeKeyFieldsGroup } from './key-field-merge';
import { withWriterLock } from './writer-lock';
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

  constructor(opts: { path?: string; lockDir?: string } = {}) {
    this.path = opts.path ?? null;
    this.lockDir = opts.lockDir ?? null;
    this.load();
  }

  private load(): void {
    if (!this.path) return;
    // A torn or corrupt book must stop the command: "start fresh" here meant the next flush
    // persisted an empty book over the real one (Flint 2026-10-24).
    const parsed = readJsonStrict<Partial<HeadlessData> | null>(this.path, null);
    this.data = {
      contacts: parsed?.contacts ?? [],
      notes: parsed?.notes ?? [],
      threads: parsed?.threads ?? [],
    };
  }

  private flush(): void {
    if (!this.path) return;
    writeFileAtomic(this.path, JSON.stringify(this.data, null, 2));
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

  /** Add or merge a contact (by id, else by fingerprint). */
  upsertContact(c: HeadlessContact): void {
    this.mutate(() => {
      const i = this.data.contacts.findIndex((x) => x.id === c.id || x.fingerprint === c.fingerprint);
      if (i === -1) { this.data.contacts.push(c); return; }
      const old = this.data.contacts[i];
      // admit-card-key-hash-bind-001 (convergent w/ flint #2068): an id
      // match carrying a DIFFERENT fingerprint is a row-takeover shape —
      // refuse, never merge (fp is the member's identity; durable_id
      // collisions must not hand the row + its trust to another fp).
      if (old.id === c.id && old.fingerprint !== c.fingerprint) {
        throw new Error(
          `upsertContact refused: id ${c.id} held by fp ` +
          `${old.fingerprint?.slice(0, 12)} — incoming fp ` +
          `${c.fingerprint?.slice(0, 12)} differs (row-takeover)`);
      }
      // key material moves as ONE epoch — a shallow overlay used to let a
      // partial card Frankenstein the row's quad (the ember 19:27
      // stale-card wound).
      this.data.contacts[i] = mergeKeyFieldsGroup(old, c);
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
