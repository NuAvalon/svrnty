// src/lib/messaging/note-id-collision.test.ts
// Launch gate (Archie #2110, Hypatia #2108, Flint #2109): note_id is chosen by the SENDER, and the PWA notes store is keyed on note_id ALONE.
// A contact B who reuses a note_id must NOT replace a row that is not B's: A's own outbound copy of a note A sent B (B holds that id), or
// another contact's inbound note. NEG: B's note carrying A's note_id => A's note unchanged. Real signatures (real acceptInboundNote); the
// store is an in-memory map with the SAME semantics as the IndexedDB 'notes' object store (put by note_id replaces).
// Run: npx tsx --test src/lib/messaging/note-id-collision.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import { HeadlessStore } from '@/lib/headless/headless-store';
import type { NoteRecord, NoteWireV0, NoteThread } from './types';

type Id = { fp: string; pub: string; priv: string; pass: string; kem: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, pass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, sig: id.pq_sig_public_key };
}
const signedFrom = (s: Id, note_id: string, body = 'hello', extra: Partial<NoteWireV0> = {}) =>
  signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id: 'thr_b', from_fingerprint: s.fp, sent_at: '2026-10-30T12:00:00.000Z', body, participant_kind: 'human', ...extra }, s.pub, s.priv, s.pass, s.kem, s.sig);

/** The IndexedDB 'notes' store, as far as this matters: put replaces by note_id. */
function idbLikeStore() {
  const rows = new Map<string, NoteRecord>();
  const threads: NoteThread[] = [];
  const calls = { gets: 0 };
  const io = {
    putNote: (async (n: NoteRecord) => { rows.set(n.note_id, structuredClone(n)); }) as never,
    getNote: (async (id: string) => { calls.gets++; return rows.get(id) ? structuredClone(rows.get(id)!) : null; }) as never,
    putThread: (async (t: NoteThread) => { threads.push(t); }) as never,
    listThreads: (async () => threads) as never,
  };
  return { rows, io, calls };
}
const accept = (wire: NoteWireV0, io: unknown, extra: Record<string, unknown> = {}) =>
  acceptInboundNote({ wire, isAdmitted: async () => true, io: io as never, ...extra } as never);

const OUT = (id: string, toFp: string): NoteRecord => ({
  note_id: id, thread_id: 'thr_a', direction: 'outbound', from_fingerprint: 'a-self', to_fingerprints: [toFp], sent_at: '2026-10-30T11:00:00.000Z',
  body: 'what A said to B', participant_kind: 'human', retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE, receipt_key: 'ab'.repeat(32),
} as NoteRecord);

test('K1 NEG: B (who holds the id because A sent it to B) sends a note with that SAME note_id => A\'s outbound copy is UNCHANGED (body, key, direction), and B\'s note is refused', async () => {
  const B = await mint();
  const st = idbLikeStore();
  const original = OUT('shared_id', B.fp);
  st.rows.set('shared_id', structuredClone(original));
  const r = await accept(await signedFrom(B, 'shared_id', 'B rewrites history'), st.io);
  assert.equal(r, null, 'refused');
  assert.deepEqual(st.rows.get('shared_id'), original, 'A\'s row is byte-for-byte what it was (receipt_key included)');
  assert.equal(st.rows.size, 1);
});

test('K2 NEG: a note from contact B that reuses contact C\'s stored INBOUND note_id is refused and C\'s note is unchanged', async () => {
  const [B, C] = [await mint(), await mint()];
  const st = idbLikeStore();
  assert.ok(await accept(await signedFrom(C, 'c_note', 'C says hi'), st.io));
  const before = structuredClone(st.rows.get('c_note')!);
  assert.equal(await accept(await signedFrom(B, 'c_note', 'B overwrites C'), st.io), null);
  assert.deepEqual(st.rows.get('c_note'), before);
  assert.equal(st.rows.get('c_note')!.from_fingerprint, C.fp);
});

test('K3 control: the SAME sender\'s redelivery of its own note is idempotent (accepted, still one row); a fresh id is stored normally', async () => {
  const B = await mint();
  const st = idbLikeStore();
  const w = await signedFrom(B, 'b_note', 'first');
  assert.ok(await accept(w, st.io));
  assert.ok(await accept(w, st.io), 'redelivery of the same note is accepted');
  assert.equal(st.rows.size, 1);
  assert.ok(await accept(await signedFrom(B, 'another_id', 'second'), st.io));
  assert.equal(st.rows.size, 2);
});

test('K4: the collision is refused BEFORE any ratchet work (openRatchet is never called), and a store read error is RETRYABLE (throws, nothing stored)', async () => {
  const B = await mint();
  const st = idbLikeStore();
  st.rows.set('x', OUT('x', B.fp));
  let opened = 0;
  const ratchetBody = JSON.stringify({ type: 'svrnty-tr-v1', packet: 'AAAA' });
  const w = await signedFrom(B, 'x', ratchetBody);
  assert.equal(await accept(w, st.io, { openRatchet: async () => { opened++; return null; } }), null);
  assert.equal(opened, 0, 'no ratchet open, so no session state was touched for a refused frame');
  const broken = { ...st.io, getNote: (async () => { throw new Error('IndexedDB read failed'); }) as never };
  const before = st.rows.size;
  const fresh = await signedFrom(B, 'fresh');
  await assert.rejects(() => accept(fresh, broken), /IndexedDB/);
  assert.equal(st.rows.size, before);
});

test('K5 HEADLESS store (Chaos #170, pinned): a colliding id from another sender, or one matching our outbound copy, lands as its OWN row and never replaces; the same sender\'s redelivery replaces only its own', () => {
  const s = new HeadlessStore();
  const base = (over: Partial<NoteRecord>): NoteRecord => ({ note_id: 'dup', thread_id: 't', direction: 'inbound', from_fingerprint: 'fp-A', to_fingerprints: [], sent_at: '2026-10-30T12:00:00.000Z', body: 'A', participant_kind: 'human', retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE, ...over } as NoteRecord);
  s.putNote(base({ direction: 'outbound', from_fingerprint: 'self', to_fingerprints: ['fp-B'], body: 'our outbound' }));
  s.putNote(base({ from_fingerprint: 'fp-B', body: 'B reuses the id' }));
  s.putNote(base({ from_fingerprint: 'fp-C', body: 'C reuses the id' }));
  s.putNote(base({ from_fingerprint: 'fp-B', body: 'B redelivers (updated)' }));
  const rows = s.listNotes().filter((n) => n.note_id === 'dup');
  assert.equal(rows.length, 3, 'outbound + B + C, each its own row');
  assert.equal(rows.find((n) => n.direction === 'outbound')!.body, 'our outbound');
  assert.equal(rows.find((n) => n.from_fingerprint === 'fp-C')!.body, 'C reuses the id');
  assert.equal(rows.find((n) => n.from_fingerprint === 'fp-B')!.body, 'B redelivers (updated)', 'only the same sender\'s own row was replaced');
});

test('K7 self-note: a delivery whose sender fingerprint EQUALS the fingerprint on our stored OUTBOUND row (we wrote to ourselves) still must not replace that row: direction is checked, not just the sender', async () => {
  const B = await mint(); // B plays "us" here: the outbound row carries B's own fingerprint as sender
  const st = idbLikeStore();
  const outbound = { ...OUT('self_id', B.fp), from_fingerprint: B.fp };
  st.rows.set('self_id', structuredClone(outbound));
  assert.equal(await accept(await signedFrom(B, 'self_id', 'the same id arriving as an inbound delivery'), st.io), null);
  assert.deepEqual(st.rows.get('self_id'), outbound);
});

test('K6 tripwire: the PWA notes store IS keyed on note_id alone (the reason K1/K2 exist). If the schema ever becomes composite, revisit the guard in acceptInboundNote knowingly', () => {
  const src = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
  assert.match(src, /createObjectStore\('notes', \{ keyPath: 'note_id' \}\)/);
  assert.match(src, /export async function putNote[\s\S]*?txPut\('notes', \{\s*note_id: note\.note_id/);
});
