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
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';
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
 * At-rest encryption envelope for the headless book. When the agent supplies an at-rest key (32 bytes,
 * derived ONCE upstream from its custody master-secret), the on-disk file is an AES-256-GCM envelope
 * instead of plaintext JSON — closing the device-at-rest + cloud-backup-exfil leak (a headless agent's
 * notes/contacts must not sit plaintext on a volume that iCloud/Android auto-backup can exfiltrate; Flint
 * #168811). Symmetric + SYNCHRONOUS (node:crypto) so flush() stays sync (no ripple into the consume seams);
 * the key is already KDF-derived upstream, this is not a per-flush KDF. No key → plaintext JSON (dev/test
 * parity). The HNDL hybrid envelope is a WIRE concern and is stripped on receive — at rest we keep ONE
 * symmetric key, not per-message hybrid (Peter #168761 / Flint #168811 / Archie: keep-at-rest-enc).
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
 * Derive the 32-byte at-rest key for the headless book from the agent's ROOT secret (the custody
 * master-secret the serve-daemon unlocks). HKDF-SHA256, domain-separated ('svrnty-headless-at-rest-v1')
 * so it's INDEPENDENT of the vault key and any wire key — one's compromise is not the other's. The daemon
 * derives this ONCE at unlock → new HeadlessStore({ path, atRestKey }). Deterministic: same rootSecret →
 * same key → the store re-opens across respawns (durable). Pure (no I/O).
 */
export function deriveAtRestKey(rootSecret: Uint8Array): Uint8Array {
  if (!rootSecret || rootSecret.length === 0) throw new Error('deriveAtRestKey: empty rootSecret');
  return new Uint8Array(hkdfSync('sha256', rootSecret, new Uint8Array(0), 'svrnty-headless-at-rest-v1', 32));
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
  private readonly atRestKey: Uint8Array | null;

  constructor(opts: { path?: string; atRestKey?: Uint8Array } = {}) {
    this.path = opts.path ?? null;
    this.atRestKey = opts.atRestKey ?? null;
    if (this.atRestKey && this.atRestKey.length !== 32) {
      throw new Error('HeadlessStore atRestKey must be 32 bytes (AES-256-GCM)');
    }
    if (this.path && existsSync(this.path)) {
      let obj: unknown;
      try {
        obj = JSON.parse(readFileSync(this.path, 'utf8'));
      } catch {
        return; /* genuinely unparseable → start fresh (don't crash the agent on a bad book) */
      }
      if (isAtRestEnvelope(obj)) {
        // Encrypted file. Refuse to clobber it: no key, or a wrong key (GCM auth throws), must NOT
        // silently start-fresh — that would delete the agent's book. Surface the error to the caller.
        if (!this.atRestKey) {
          throw new Error('HeadlessStore: file is encrypted at rest but no atRestKey was supplied');
        }
        const parsed = JSON.parse(decryptAtRest(obj, this.atRestKey)) as Partial<HeadlessData>;
        this.data = { contacts: parsed.contacts ?? [], notes: parsed.notes ?? [], threads: parsed.threads ?? [] };
      } else {
        const parsed = obj as Partial<HeadlessData>;
        this.data = { contacts: parsed.contacts ?? [], notes: parsed.notes ?? [], threads: parsed.threads ?? [] };
        // plaintext file + atRestKey present = legacy/migration → the next flush() re-writes it encrypted.
      }
    }
  }

  private flush(): void {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    const json = JSON.stringify(this.data, null, 2);
    // at-rest: encrypt when a key is present (prod agents MUST pass one); plaintext only for dev/test parity.
    writeFileSync(this.path, this.atRestKey ? JSON.stringify(encryptAtRest(json, this.atRestKey)) : json);
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
