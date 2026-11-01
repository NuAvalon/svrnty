// src/lib/headless/headless-first-write-wins.test.ts
// FIRST WRITE WINS on the headless inbox (Archie #2653): a contact may redeliver a note, never rewrite it. HeadlessStore.putNote is the one
// chokepoint; the poller reports the stored note, leaves the thread alone and counts the refusal.
// Run: npx tsx --test src/lib/headless/headless-first-write-wins.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';
import { resetRewriteRefusedCount, rewriteRefusedCount } from '@/lib/messaging/rewrite-refused';
import type { NoteRecord } from '@/lib/messaging/types';

const RELAY = 'http://relay.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass, kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig });
const contact = (id: Id): HeadlessContact => ({ id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, trust_level: 'known' });
const rec = (over: Partial<NoteRecord> = {}): NoteRecord => ({ note_id: 'n1', thread_id: 't1', direction: 'inbound', from_fingerprint: 'aa'.repeat(32), to_fingerprints: [], sent_at: '2026-10-30T12:00:00.000Z',
  body: 'original', participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over } as NoteRecord);

test('H1 NEG: an INBOUND note reusing a stored id with a different body/thread/time is refused: putNote returns false and the row is untouched', () => {
  const s = new HeadlessStore();
  assert.equal(s.putNote(rec()), true);
  assert.equal(s.putNote(rec({ body: 'EDITED' })), false);
  assert.equal(s.putNote(rec({ thread_id: 'other' })), false);
  assert.equal(s.putNote(rec({ sent_at: '2026-10-31T00:00:00.000Z' })), false);
  assert.equal(s.listNotes().length, 1);
  assert.deepEqual([s.listNotes()[0].body, s.listNotes()[0].thread_id, s.listNotes()[0].sent_at], ['original', 't1', '2026-10-30T12:00:00.000Z']);
});
test('H2 control: byte-identical redelivery re-persists (true); a different SENDER with the same id is its own row; an OUTBOUND copy is still replaceable by us', () => {
  const s = new HeadlessStore();
  s.putNote(rec());
  assert.equal(s.putNote(rec()), true);
  assert.equal(s.putNote(rec({ from_fingerprint: 'bb'.repeat(32), body: 'someone else' })), true);
  assert.equal(s.listNotes().length, 2);
  s.putNote(rec({ note_id: 'o1', direction: 'outbound', body: 'mine v1' }));
  assert.equal(s.putNote(rec({ note_id: 'o1', direction: 'outbound', body: 'mine v2' })), true);
  assert.equal(s.listNotes().find((n) => n.note_id === 'o1')!.body, 'mine v2');
});

test('P1 the real poller: A sends two DIFFERENT notes under one note_id => B keeps the first, acks both, counts one refusal, and the thread is not touched by the second', async () => {
  resetRewriteRefusedCount();
  const [A, B] = [await mint(), await mint()];
  const box: Array<{ envelope_id: string; blob: string }> = [];
  let acked = 0;
  let seq = 0; // a relay never reuses an envelope id; `box.length + 1` did once the box drained, and #712's C1 dedupe then (correctly) acked it unopened
  const fetchImpl = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith('/envelope')) { box.push({ envelope_id: `e${++seq}`, blob: JSON.parse(String(init?.body)).blob }); return new Response('{}', { status: 200 }); }
    if (u.includes('/queue')) return new Response(JSON.stringify([...box]), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.includes('/ack')) { const { envelope_ids } = JSON.parse(String(init?.body)); acked += envelope_ids.length; box.splice(0, box.length, ...box.filter((e) => !envelope_ids.includes(e.envelope_id))); return new Response('{"deleted":1}', { status: 200 }); }
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
  const send = (body: string, sentAt: string) => sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body, store: new HeadlessStore(), relayBase: RELAY, fetchImpl, noteId: 'same-id', sentAt });
  await send('what A really said', '2026-10-30T12:00:00.000Z');
  const bStore = new HeadlessStore();
  bStore.upsertContact(contact(A));
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  const before = JSON.stringify(bStore.listThreads());
  await send('A rewrites history', '2026-10-31T09:00:00.000Z');
  const s2 = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(bStore.listNotes().length, 1);
  assert.equal(bStore.listNotes()[0].body, 'what A really said');
  assert.equal(s2.polled, 1);
  assert.equal(acked, 2, 'the refused envelope is still consumed (acked), never left to loop');
  assert.equal(JSON.stringify(bStore.listThreads()), before, 'the refused note did not move the thread');
  assert.equal(rewriteRefusedCount(), 1);
  assert.equal(box.length, 0);
  void deriveMailboxId;
});
