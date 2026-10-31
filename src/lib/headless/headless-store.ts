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
import type { KnownContact, ContactStore, ChunkTxn, ListingScope } from '@/lib/sync/consume-mailbox';
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
  // #712 C1: envelopes whose contents a chunk commit already holds, keyed by consume's envelopeDedupeKey (a hash, never the raw id).
  // A redelivered one (killed between commit and ack) is acked WITHOUT being opened again. Bounded: see commitChunk.
  applied_envelopes?: AppliedEnvelope[];
}

interface AppliedEnvelope {
  key: string;
  at: string; // ISO, when the commit that holds it ran
}

/** = the relay's envelope TTL: an entry older than this can no longer match a live envelope, and is never trusted to skip an open. */
const APPLIED_TTL_MS = 7 * 24 * 3600e3;

function freshEntry(e: AppliedEnvelope, nowMs: number): boolean {
  const at = Date.parse(e.at);
  return Number.isFinite(at) && nowMs - at < APPLIED_TTL_MS;
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
  private writeCount = 0;
  // #712: while a chunk is open, mutations apply to the in-memory copy AND are recorded (closures over their ARGUMENTS) for the commit.
  private chunk: { ops: Array<{ key: string | null; op: () => unknown }>; key: string | null; stored: Set<string>; acked: Set<string> } | null = null;

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
      ...(Array.isArray(book?.applied_envelopes) ? { applied_envelopes: book.applied_envelopes } : {}),
    };
  }

  /** How many times this instance wrote the book (counts only; #712 S3/S5). */
  get writes(): number {
    return this.writeCount;
  }

  /** Size of the #712 dedupe set on this copy (counts only). */
  appliedEnvelopeCount(): number {
    return this.data.applied_envelopes?.length ?? 0;
  }

  private flush(): void {
    if (!this.path) return;
    this.writeCount++;
    const json = JSON.stringify(this.data, null, 2);
    // at-rest: encrypt when a key is present (prod agents MUST pass one); plaintext only for dev/test parity.
    const key = this.atRestKey;
    writeFileAtomic(
      this.path,
      key ? JSON.stringify(encryptAtRest(json, key)) : json,
      key ? { backupTransform: (prev) => sealBackup(prev, key) } : {},
    );
  }

  /**
   * One read-modify-write unit: under the writer lock, re-read, apply, flush (see class doc). Inside an open chunk (#712) the change
   * applies to the in-memory copy now and is re-applied onto a fresh read at commitChunk, so `apply` must compute everything it needs
   * from this.data and its own arguments, never from a value read before it ran.
   */
  private mutate<T>(apply: () => T): T {
    if (this.chunk) {
      const r = apply();
      this.chunk.ops.push({ key: this.chunk.key, op: apply });
      return r;
    }
    if (!this.path || !this.lockDir) {
      const r = apply();
      this.flush();
      return r;
    }
    return withWriterLock(this.lockDir, () => {
      this.load();
      const r = apply();
      this.flush();
      return r;
    });
  }

  /**
   * #712: write one ack chunk. Under the writer lock ONCE: re-read, re-apply the chunk's ops in order (a concurrent writer's records
   * survive; a block it wrote wins, C2), record the chunk's stored envelopes in the dedupe set (C1, same write = S3), write once.
   * Returns the keys whose note a re-apply refused (the sender is no longer admitted). Throws if the write fails: the caller acks NONE
   * of the chunk, and this copy is rolled back to the disk.
   * The dedupe set keeps an entry only while it is younger than the relay TTL, was not acked by this process, and (when `live` is
   * given) is still in the poll's listing IF it belongs to that listing's relay + mailbox: the relay lists a mailbox WHOLE
   * (mailbox-store.ts pollMailbox has no LIMIT, pinned by a test), so an id missing from it was acked or expired and can never be
   * redelivered. Another relay's or mailbox's entries are never pruned by it (Flint #2417).
   */
  commitChunk(now: string, live?: ListingScope): { refused: string[] } {
    const c = this.chunk;
    this.chunk = null;
    // nothing consumed into this chunk: no write (the dedupe set is pruned at the next real commit)
    if (!c || (c.ops.length === 0 && c.stored.size === 0)) return { refused: [] };
    const nowMs = Date.parse(now);
    const run = (reapply: boolean) => {
      // Without the lock nothing else writes this copy, so the ops already ran on it (a refusal then was returned to its caller).
      // A refusal only counts for an envelope consume marked stored: one refused on its first apply never was.
      const refused = new Set<string>();
      if (reapply) for (const { key, op } of c.ops) if (op() === false && key && c.stored.has(key)) refused.add(key);
      const listed = (e: AppliedEnvelope) => !live || !e.key.startsWith(`${live.scope}.`) || live.keys.has(e.key);
      const keep = (this.data.applied_envelopes ?? []).filter((e) => freshEntry(e, nowMs) && !c.acked.has(e.key) && listed(e));
      for (const k of c.stored) if (!refused.has(k) && !keep.some((e) => e.key === k)) keep.push({ key: k, at: now });
      this.data.applied_envelopes = keep;
      this.flush();
      return [...refused];
    };
    try {
      if (!this.path || !this.lockDir) return { refused: run(false) };
      return { refused: withWriterLock(this.lockDir, () => {
        this.load();
        return run(true);
      }) };
    } catch (err) {
      try {
        this.load(); // drop the chunk's in-memory changes: nothing of it was written
      } catch {
        /* the book is unreadable: the next command stops on it (fail-closed load) */
      }
      throw err;
    }
  }

  /** Drop an open chunk without writing it (consume exited mid-chunk). The copy goes back to the disk. */
  abortChunk(): void {
    if (!this.chunk) return;
    this.chunk = null;
    if (this.path) this.load();
  }

  /**
   * The #712 transaction seam consume drives (ConsumeDeps.chunk). `now` stamps dedupe entries. Mutations through this store between
   * enter() and commit() belong to the entered envelope.
   */
  asChunkTxn(now: () => string): ChunkTxn {
    const open = () => (this.chunk ??= { ops: [], key: null, stored: new Set(), acked: new Set() });
    let pendingAcked = new Set<string>();
    return {
      enter: (key) => {
        open().key = key;
      },
      isStored: (key) => {
        const nowMs = Date.parse(now());
        return (this.data.applied_envelopes ?? []).some((e) => e.key === key && freshEntry(e, nowMs));
      },
      stored: (key) => {
        open().stored.add(key);
      },
      acked: (keys) => {
        for (const k of keys) pendingAcked.add(k);
      },
      commit: (live) => {
        const c = open();
        for (const k of pendingAcked) c.acked.add(k);
        const r = this.commitChunk(now(), live);
        pendingAcked = new Set();
        return r;
      },
      abort: () => this.abortChunk(),
    };
  }

  // --- contacts ---
  getContactByFingerprint(fingerprint: string): HeadlessContact | null {
    return this.data.contacts.find((c) => c.fingerprint === fingerprint) ?? null;
  }

  /** Add or merge a contact (by id, else by fingerprint). */
  upsertContact(c: HeadlessContact): void {
    this.mutate(() => {
      const i = this.data.contacts.findIndex((x) => x.id === c.id || x.fingerprint === c.fingerprint);
      if (i === -1) this.data.contacts.push(c);
      else this.data.contacts[i] = { ...this.data.contacts[i], ...c };
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

  /**
   * Store an inbound note and its thread as ONE change, admitted against the copy it is applied to (#712 C2): re-applied at a chunk
   * commit, a sender blocked by a concurrent writer since the note was opened is refused there, exactly as before the poll. `threadFor`
   * builds the thread from the CURRENT one on that copy. Returns false (nothing stored) when the sender is not admitted.
   */
  acceptInboundNote(n: NoteRecord, threadFor: (existing: NoteThread | undefined) => NoteThread, admit: (c: HeadlessContact | null) => boolean): boolean {
    return this.mutate(() => {
      if (!admit(this.getContactByFingerprint(n.from_fingerprint))) return false;
      // same key as putNote: sender + direction + id (Chaos #170)
      const i = this.data.notes.findIndex((x) =>
        x.note_id === n.note_id && x.direction === n.direction && x.from_fingerprint === n.from_fingerprint);
      if (i === -1) this.data.notes.push(n);
      else this.data.notes[i] = n;
      const t = threadFor(this.data.threads.find((x) => x.thread_id === n.thread_id));
      const j = this.data.threads.findIndex((x) => x.thread_id === t.thread_id);
      if (j === -1) this.data.threads.push(t);
      else this.data.threads[j] = t;
      return true;
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
