// src/lib/headless/headless-store.ts
// Node-backed store for a headless (CLI/docker) svrnty client — the storage half of L2b (headless
// receive/poll/send). The browser client persists contacts + notes in IndexedDB (client-store.ts +
// messaging/store.ts); a headless client has no IndexedDB, so this provides the SAME surfaces the consume
// seams + admit + mutual-apply + note-persist need, backed by an in-memory map with OPTIONAL JSON-file
// persistence. Dependency-light (node:fs only) + storage-agnostic, so a sqlite backend can replace the
// file later with zero caller change.
//
// NOTE: this is a HEADLESS-ONLY module (imports node:fs) — never import it into the browser bundle.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
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
  mutual?: { they_trust_me: boolean | null; last_sync: string | null; reciprocal: boolean };
  [key: string]: unknown;
}

interface HeadlessData {
  contacts: HeadlessContact[];
  notes: NoteRecord[];
  threads: NoteThread[];
}

/**
 * In-memory book with optional JSON-file persistence. Not concurrency-safe across processes (a headless
 * agent is single-process); within a process all mutations are synchronous + flush atomically-enough for
 * an agent's scale. The consume core (consume-mailbox.ts) drives this ONLY through asContactStore() + the
 * note/affirm seams (headless-client.ts), so the shape stays swappable.
 */
export class HeadlessStore {
  private data: HeadlessData = { contacts: [], notes: [], threads: [] };
  private readonly path: string | null;

  constructor(opts: { path?: string } = {}) {
    this.path = opts.path ?? null;
    if (this.path && existsSync(this.path)) {
      try {
        const parsed = JSON.parse(readFileSync(this.path, 'utf8')) as Partial<HeadlessData>;
        this.data = {
          contacts: parsed.contacts ?? [],
          notes: parsed.notes ?? [],
          threads: parsed.threads ?? [],
        };
      } catch {
        /* corrupt file → start fresh (don't crash the agent on a bad book) */
      }
    }
  }

  private flush(): void {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.data, null, 2));
  }

  // --- contacts ---
  getContactByFingerprint(fingerprint: string): HeadlessContact | null {
    return this.data.contacts.find((c) => c.fingerprint === fingerprint) ?? null;
  }

  /** Add or merge a contact (by id, else by fingerprint). */
  upsertContact(c: HeadlessContact): void {
    const i = this.data.contacts.findIndex((x) => x.id === c.id || x.fingerprint === c.fingerprint);
    if (i === -1) this.data.contacts.push(c);
    else this.data.contacts[i] = { ...this.data.contacts[i], ...c };
    this.flush();
  }

  updateContact(id: string, patch: Partial<HeadlessContact>): void {
    const i = this.data.contacts.findIndex((x) => x.id === id);
    if (i === -1) throw new Error(`headless updateContact: contact ${id} not found`);
    this.data.contacts[i] = { ...this.data.contacts[i], ...patch, id };
    this.flush();
  }

  listContacts(): HeadlessContact[] {
    return [...this.data.contacts];
  }

  // --- notes (mirror the messaging store surface the note-accept uses) ---
  putNote(n: NoteRecord): void {
    const i = this.data.notes.findIndex((x) => x.note_id === n.note_id);
    if (i === -1) this.data.notes.push(n);
    else this.data.notes[i] = n; // idempotent on note_id (redelivery re-persists harmlessly)
    this.flush();
  }
  listNotes(): NoteRecord[] {
    return [...this.data.notes];
  }
  putThread(t: NoteThread): void {
    const i = this.data.threads.findIndex((x) => x.thread_id === t.thread_id);
    if (i === -1) this.data.threads.push(t);
    else this.data.threads[i] = t;
    this.flush();
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
