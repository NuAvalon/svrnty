// src/lib/sync/consume-mailbox-blocked.test.ts
// A contact the owner has blocked sends nothing that changes their record. The update is dropped for good: acked, not written, not retried,
// and nothing queued during the block is replayed on unblock. Real crypto for the signed update; injected transport, decrypt and store.
//
// Run: npx tsx --test src/lib/sync/consume-mailbox-blocked.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { admitContact } from '@/lib/trust/admit-contact';
import { consumeInboundContactUpdates, type ConsumeDeps, type ContactStore, type KnownContact, type NoteResponseSeam, type ChunkTxn } from './consume-mailbox';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0 } from '@/lib/messaging/types';

interface Identity { fingerprint: string; publicKey: string; privateKey: string; passphrase: string }

async function makeIdentity(name: string): Promise<Identity> {
  const passphrase = `pass-${name}`;
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name, email: `${name}@t.test` }], passphrase, format: 'armored' });
  const key = await readKey({ armoredKey: publicKey });
  return { fingerprint: key.getFingerprint(), publicKey, privateKey, passphrase };
}

let alice: Identity;
let bob: Identity;
before(async () => {
  alice = await makeIdentity('alice');
  bob = await makeIdentity('bob');
});

async function nameChange(version: number, name: string): Promise<SignedContactUpdate> {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: name },
  };
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), bob.privateKey, bob.passphrase);
  return { envelope: env, signature };
}

// A relay that forgets what is acked, so a second poll sees only what was left behind.
function relay(initial: Array<{ envelope_id: string; blob: string }>, ackLog: string[][]) {
  let queue = [...initial];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(queue), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/ack')) {
      const ids: string[] = JSON.parse(String(init?.body ?? '{}')).envelope_ids;
      ackLog.push(ids);
      queue = queue.filter((e) => !ids.includes(e.envelope_id));
      return new Response(JSON.stringify({ deleted: ids.length }), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, left: () => queue.map((e) => e.envelope_id) };
}

// One held record, like the book: lookup reads it, persist decides on it AGAIN when it writes (the way updateContactIf does).
function heldBook(initial: Partial<StoredContact> & Record<string, unknown> = {}) {
  const held: Record<string, unknown> = {
    id: 'contact-bob', fingerprint: bob.fingerprint, name: 'Bob (old name)', email: 'bob@old.test', public_key: '', trust_level: 'verified',
    added_at: '2026-01-01T00:00:00.000Z', version: 0, ...initial,
  };
  let writes = 0;
  const store: ContactStore = {
    lookup: async (fp: string): Promise<KnownContact | null> => {
      if (fp !== bob.fingerprint) return null;
      const known: KnownContactIdentity = { fingerprint: bob.fingerprint, epoch: 0, version: Number(held.version), classicalPublicKeyArmored: bob.publicKey };
      return { known, current: { ...held, public_key: bob.publicKey } as unknown as StoredContact };
    },
    persist: async (_id: string, changes: StoredContact) => {
      if (!admitContact(held)) return { applied: false };
      Object.assign(held, changes);
      writes++;
      return { applied: true };
    },
  };
  return { held, store, writes: () => writes };
}

function deps(over: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    ...over,
  };
}

test('NEG a: a blocked contact’s update is not written, the envelope is acked, the card is unchanged', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook({ blocked: true });
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  const emitted: unknown[] = [];
  const s = await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: book.store, emit: (e) => emitted.push(e), fetchImpl: r.fetchImpl }));
  assert.equal(book.writes(), 0, 'no write');
  assert.equal(book.held.name, 'Bob (old name)', 'the card is unchanged');
  assert.equal(book.held.version, 0);
  assert.equal(s.applied, 0);
  assert.equal(emitted.length, 0, 'no repaint for a write that did not happen');
  assert.deepEqual(acks, [['e1']], 'acked, so it is not retried');
  assert.deepEqual(r.left(), []);
});

test('NEG a (metadata flag): a contact blocked only in metadata is dropped the same way', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook({ metadata: { blocked: true } });
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: book.store, fetchImpl: r.fetchImpl }));
  assert.equal(book.writes(), 0);
  assert.deepEqual(acks, [['e1']]);
});

test('NEG b: a block that lands between the poll’s read and its write stops the update; blocked stays true; it is acked, not retried', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook();
  // the block lands AFTER lookup returned an unblocked record, BEFORE persist runs
  const inner = book.store.persist.bind(book.store);
  const racing: ContactStore = { ...book.store, persist: async (id, ch) => { book.held.blocked = true; return inner(id, ch); } };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  const emitted: unknown[] = [];
  const s = await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: racing, emit: (e) => emitted.push(e), fetchImpl: r.fetchImpl }));
  assert.equal(book.writes(), 0);
  assert.equal(book.held.blocked, true, 'the block survives');
  assert.equal(book.held.name, 'Bob (old name)');
  assert.equal(s.applied, 0);
  assert.equal(emitted.length, 0);
  assert.deepEqual(acks, [['e1']], 'terminal: acked');
  assert.deepEqual(r.left(), [], 'not left on the relay for a retry');
});

test('NEG c: unblocking replays nothing that arrived during the block', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook({ blocked: true });
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  const d = deps({ decrypt: async () => signed, store: book.store, fetchImpl: r.fetchImpl });
  await consumeInboundContactUpdates(d);
  delete book.held.blocked; // the owner unblocks
  const s2 = await consumeInboundContactUpdates(d);
  assert.equal(s2.applied, 0, 'nothing is left to apply');
  assert.equal(book.writes(), 0);
  assert.equal(book.held.name, 'Bob (old name)');
});

test('control d: an unblocked contact’s update still applies', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook();
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  const s = await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: book.store, fetchImpl: r.fetchImpl }));
  assert.equal(s.applied, 1);
  assert.equal(book.writes(), 1);
  assert.equal(book.held.name, 'Bob (NEW name)');
  assert.deepEqual(acks, [['e1']]);
});

test('NEG e: in one batch, the update before the block applies and the one after it is dropped; both are acked', async () => {
  const first = await nameChange(1, 'Bob v1');
  const second = await nameChange(2, 'Bob v2');
  const book = heldBook();
  // the block lands right after the first update is written
  const inner = book.store.persist.bind(book.store);
  const store: ContactStore = { ...book.store, persist: async (id, ch) => { const r0 = await inner(id, ch); book.held.blocked = true; return r0; } };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }, { envelope_id: 'e2', blob: 'B2' }], acks);
  const s = await consumeInboundContactUpdates(deps({ decrypt: async (b) => (b === 'B1' ? first : second), store, fetchImpl: r.fetchImpl }));
  assert.equal(s.applied, 1);
  assert.equal(book.writes(), 1);
  assert.equal(book.held.name, 'Bob v1', 'the earlier update applied, the later one did not');
  assert.equal(book.held.version, 1);
  assert.deepEqual(acks.flat().sort(), ['e1', 'e2']);
  assert.deepEqual(r.left(), []);
});

function recordingSink() {
  const rows: Array<{ reason?: string }> = [];
  const sink = {
    record: async (row: never) => { rows.push(row as { reason?: string }); return row; },
    clear: async () => {},
  } as unknown as NonNullable<ConsumeDeps['deadLetter']>;
  return { rows, sink };
}

test('a blocked contact’s update writes no dead-letter row (the benign class, not a loss); the same sink DOES record a stranger’s frame', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const blockedAtRead = heldBook({ blocked: true });
  const a = recordingSink();
  const r1 = relay([{ envelope_id: 'e1', blob: 'B1' }], []);
  const s1 = await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: blockedAtRead.store, fetchImpl: r1.fetchImpl, deadLetter: a.sink }));
  assert.equal(a.rows.length, 0, 'blocked at the read');
  assert.equal(s1.acked, 1);

  const racing = heldBook();
  const inner = racing.store.persist.bind(racing.store);
  const b = recordingSink();
  const r2 = relay([{ envelope_id: 'e1', blob: 'B1' }], []);
  const s2 = await consumeInboundContactUpdates(deps({
    decrypt: async () => signed, fetchImpl: r2.fetchImpl, deadLetter: b.sink,
    store: { ...racing.store, persist: async (id, ch) => { racing.held.blocked = true; return inner(id, ch); } },
  }));
  assert.equal(b.rows.length, 0, 'blocked between the read and the write');
  assert.equal(s2.acked, 1);

  const c = recordingSink();
  const r3 = relay([{ envelope_id: 'e1', blob: 'B1' }], []);
  await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: { lookup: async () => null, persist: async () => {} }, fetchImpl: r3.fetchImpl, deadLetter: c.sink }));
  assert.equal(c.rows.length, 1, 'control: a frame from a stranger is recorded, so this sink would have shown a row');
});

test('a contact blocked only in metadata, with a store that reports nothing from persist, is dropped on the read side alone', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook({ metadata: { blocked: true } });
  let writes = 0;
  const silent: ContactStore = { lookup: book.store.lookup, persist: async () => { writes++; } };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: silent, fetchImpl: r.fetchImpl }));
  assert.equal(writes, 0);
  assert.deepEqual(acks, [['e1']]);
});

test('a store that reports nothing from persist: a contact already blocked at the read is still not written (the read-side drop stands alone)', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook({ blocked: true });
  let writes = 0;
  const silent: ContactStore = { lookup: book.store.lookup, persist: async () => { writes++; } };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: silent, fetchImpl: r.fetchImpl }));
  assert.equal(writes, 0);
  assert.deepEqual(acks, [['e1']]);
});

test('the headless store decides again when it writes: a contact blocked since the lookup is not written', async () => {
  const { HeadlessStore } = await import('@/lib/headless/headless-store');
  const s = new HeadlessStore({});
  s.upsertContact({ id: 'c1', fingerprint: 'fp1', name: 'one', public_key: 'k' } as never);
  const cs = s.asContactStore();
  assert.deepEqual(await cs.persist('c1', { name: 'two' } as never), { applied: true });
  assert.equal(s.getContactByFingerprint('fp1')?.name, 'two');
  s.upsertContact({ id: 'c1', fingerprint: 'fp1', blocked: true } as never);
  assert.deepEqual(await cs.persist('c1', { name: 'three' } as never), { applied: false });
  assert.equal(s.getContactByFingerprint('fp1')?.name, 'two', 'nothing written once blocked');
});

test('GUARD: the browser store writes a poll update only through updateContactIf, deciding on the held record with admitContact', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('./live-book-poll.ts', import.meta.url), 'utf8');
  const a = src.indexOf('export function buildContactStore');
  const b = src.indexOf('/**', a);
  const body = src.slice(a, b);
  assert.match(body, /return updateContactIf\(id, \(existing\) => \(admitContact\(existing\) \? \(next as Partial<ContactRecord>\) : null\)\);/);
  assert.doesNotMatch(body, /\bupdateContact\(/, 'no plain read-merge-put for a contact’s update');
});

test('NEG b through a guard (the shape the browser store has): the not-applied answer travels back out of the guard', async () => {
  const signed = await nameChange(1, 'Bob (NEW name)');
  const book = heldBook();
  const inner = book.store.persist.bind(book.store);
  const guarded: ContactStore = {
    lookup: book.store.lookup,
    persist: async (id, ch) => { book.held.blocked = true; return inner(id, ch); },
    guard: async (run) => ({ deferred: false, value: await run() }),
  };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'B1' }], acks);
  const emitted: unknown[] = [];
  const s = await consumeInboundContactUpdates(deps({ decrypt: async () => signed, store: guarded, emit: (e) => emitted.push(e), fetchImpl: r.fetchImpl }));
  assert.equal(s.applied, 0);
  assert.equal(emitted.length, 0);
  assert.deepEqual(acks, [['e1']]);
  assert.equal(book.held.name, 'Bob (old name)');
});

// ── notes from a blocked sender: the same policy, a different channel ──────────────────────────────────────────────────

function noteWire(from: string): NoteWireV0 {
  return { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: from, sent_at: '2026-10-09T00:00:00.000Z', body: 'hello', participant_kind: 'human' };
}
// A note seam whose accept refuses the sender as "not in book" (what admit says for a stranger AND for a blocked contact).
const refusingNotes = (from: string): NoteResponseSeam => ({
  verify: async (blob) => (blob === 'NOTE' ? noteWire(from) : null),
  accept: async () => ({ dropped: 'not-in-book', fp: from }),
});
const noteStore = (lookup: ContactStore['lookup']): ContactStore => ({ lookup, persist: async () => {} });

test('NOTE: a blocked sender’s note is dropped and acked with NO row and no counted loss; a real stranger’s note still gets its row', async () => {
  const blocked = heldBook({ blocked: true });
  const a = recordingSink();
  const acksA: string[][] = [];
  const sA = await consumeInboundContactUpdates(deps({ note: refusingNotes(bob.fingerprint), store: noteStore(blocked.store.lookup), deadLetter: a.sink, fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], acksA).fetchImpl }));
  assert.equal(a.rows.length, 0, 'no row: nothing at rest about the blocked contact');
  assert.equal(sA.acked, 1);
  assert.deepEqual(acksA, [['e1']]);
  assert.equal(sA.lost['not-in-book'], undefined, 'not counted as a lost message');
  assert.equal(sA.notes, 0);

  const b = recordingSink();
  const sB = await consumeInboundContactUpdates(deps({ note: refusingNotes('STRANGERFP'), store: noteStore(async () => null), deadLetter: b.sink, fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], []).fetchImpl }));
  assert.equal(b.rows.length, 1, 'control: a stranger’s note keeps its record (and with it the stranger notice)');
  assert.equal(b.rows[0].reason, 'not-in-book');
  assert.equal(sB.lost['not-in-book'], 1);
});

test('NOTE: a contact blocked only in metadata is dropped the same way', async () => {
  const blocked = heldBook({ metadata: { blocked: true } });
  const a = recordingSink();
  const s = await consumeInboundContactUpdates(deps({ note: refusingNotes(bob.fingerprint), store: noteStore(blocked.store.lookup), deadLetter: a.sink, fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], []).fetchImpl }));
  assert.equal(a.rows.length, 0);
  assert.equal(s.acked, 1);
});

test('NOTE: a store that cannot answer the lookup keeps the loss record (never silently drops a note it cannot classify)', async () => {
  const a = recordingSink();
  const s = await consumeInboundContactUpdates(deps({
    note: refusingNotes(bob.fingerprint), deadLetter: a.sink, fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], []).fetchImpl,
    store: noteStore(async () => { throw new Error('book unreadable'); }),
  }));
  assert.equal(a.rows.length, 1);
  assert.equal(s.lost['not-in-book'], 1);
});

test('NOTE: unblocking replays nothing that was sent during the block', async () => {
  const blocked = heldBook({ blocked: true });
  const r = relay([{ envelope_id: 'e1', blob: 'NOTE' }], []);
  const accepted: string[] = [];
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? noteWire(bob.fingerprint) : null),
    accept: async (w) => (blocked.held.blocked ? { dropped: 'not-in-book', fp: bob.fingerprint } : (accepted.push(w.note_id), { note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint })),
  };
  const d = deps({ note, store: noteStore(blocked.store.lookup), fetchImpl: r.fetchImpl });
  await consumeInboundContactUpdates(d);
  delete blocked.held.blocked;
  const s2 = await consumeInboundContactUpdates(d);
  assert.equal(s2.notes, 0);
  assert.deepEqual(accepted, []);
  assert.deepEqual(r.left(), []);
});

// C2: a note accepted in memory, then refused at the chunk commit because the sender was blocked (or removed) meanwhile.
function refusingChunk(): ChunkTxn {
  const stored: string[] = [];
  return {
    enter: () => {}, isStored: () => false, stored: (k) => { stored.push(k); }, acked: () => {}, abort: () => {},
    commit: () => ({ refused: [...stored] }),
  };
}
const acceptingNotes = (from: string): NoteResponseSeam => ({
  verify: async (blob) => (blob === 'NOTE' ? noteWire(from) : null),
  accept: async (w) => ({ note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }),
});

test('NOTE C2: refused at the commit because the sender is BLOCKED → acked, no row, no counted loss', async () => {
  const blocked = heldBook({ blocked: true });
  const a = recordingSink();
  const acks: string[][] = [];
  const s = await consumeInboundContactUpdates(deps({
    note: acceptingNotes(bob.fingerprint), chunk: refusingChunk(), deadLetter: a.sink, store: noteStore(blocked.store.lookup),
    fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], acks).fetchImpl,
  }));
  assert.equal(a.rows.length, 0);
  assert.equal(s.lost['not-in-book'], undefined);
  assert.equal(s.deadLettered, 0);
  assert.equal(s.notes, 0, 'the note was not kept');
  assert.deepEqual(acks, [['e1']], 'consumed');
});

test('NOTE C2: refused at the commit because the sender was REMOVED (not blocked) keeps the honest not-in-book loss row', async () => {
  const a = recordingSink();
  const acks: string[][] = [];
  const s = await consumeInboundContactUpdates(deps({
    note: acceptingNotes(bob.fingerprint), chunk: refusingChunk(), deadLetter: a.sink, store: noteStore(async () => null),
    fetchImpl: relay([{ envelope_id: 'e1', blob: 'NOTE' }], acks).fetchImpl,
  }));
  assert.equal(a.rows.length, 1);
  assert.equal(a.rows[0].reason, 'not-in-book');
  assert.equal(s.lost['not-in-book'], 1);
  assert.deepEqual(acks, [['e1']]);
});
