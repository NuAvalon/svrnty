// src/lib/messaging/receipt-emit.test.ts
// S62 slice 3: the recipient emits the hybrid MAC receipt AFTER the durable store, to the sender only, never downgraded, never leaking the key.
// Real keys, real hybrid sealing. Run: npx tsx --test src/lib/messaging/receipt-emit.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveOwnerHybridSecrets } from '@/lib/crypto/living-book-receive';
import { openMailboxEnvelope } from '@/lib/crypto/mailbox-envelope';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { newReceiptKey, receiptKeyToHex, verifyReceiptTag, receiptKeyFromHex } from '@/lib/crypto/receipt-mac';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { signNoteWire } from './note-auth';
import { NOTE_WIRE_TYPE } from './domains';
import { emitDeliveredReceipt } from './receipt-emit';
import { buildReceiptWireV1, parseReceiptWireV1, RECEIPT_V1_WIRE_TYPE } from './receipt-wire-v1';
import { sealReceiptTo, sealReceiptV1To } from './seal';
import type { NoteWireV0 } from './types';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const openAs = async (id: Id, blob: string) => {
  const hybrid = await deriveOwnerHybridSecrets(id.priv, id.kpass, id.kem, id.kemSec);
  const { asMailboxEnvelopePackage } = await import('@/lib/sync/hybrid-dual-read');
  const pkg = asMailboxEnvelopePackage(blob);
  assert.ok(pkg && hybrid, 'a hybrid package, openable by the sender');
  return new TextDecoder().decode((await openMailboxEnvelope(pkg!, hybrid!.secrets, hybrid!.myFp))!);
};
async function signedNote(from: Id, over: Partial<NoteWireV0> = {}, withPq = true): Promise<{ wire: NoteWireV0; rkHex: string }> {
  const rkHex = receiptKeyToHex(newReceiptKey());
  const unsigned: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'note_' + crypto.randomUUID(), thread_id: 'thr_1', from_fingerprint: from.fp, sent_at: new Date().toISOString(), body: 'hello', participant_kind: 'agent', receipt_key: rkHex, ...over };
  return { wire: await signNoteWire(unsigned, from.pub, from.priv, from.kpass, withPq ? from.kem : undefined, withPq ? from.sig : undefined), rkHex };
}
function relay() {
  const posts: Array<{ url: string; mailbox_id: string; blob: string }> = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const b = JSON.parse(String(init?.body ?? '{}'));
    posts.push({ url: String(url), mailbox_id: b.mailbox_id, blob: b.blob });
    return new Response('{"ok":true}', { status: 200 });
  }) as unknown as typeof fetch;
  return { posts, fetchImpl };
}

test('W1 the v1 wire is EXACTLY {type, note_id, code, tag}; the tag verifies under rk; the parser is strict (no v0 receipt, note, extra key, bad tag or code parses)', () => {
  const rk = newReceiptKey();
  const w = buildReceiptWireV1(receiptKeyToHex(rk), 'note_1', 'delivered')!;
  assert.deepEqual(Object.keys(w).sort(), ['code', 'note_id', 'tag', 'type']);
  assert.equal(w.type, RECEIPT_V1_WIRE_TYPE);
  assert.equal(verifyReceiptTag(rk, 'note_1', 'delivered', w.tag), true);
  assert.deepEqual(parseReceiptWireV1(JSON.stringify(w)), w);
  for (const bad of [
    { ...w, from_fingerprint: 'ab'.repeat(32) }, { ...w, signature: {} }, { ...w, public_key: 'x' }, { ...w, type: 'svrnty-receipt-v0' }, { ...w, code: 'seen' },
    { ...w, tag: w.tag.toUpperCase() }, { ...w, tag: w.tag.slice(2) }, { ...w, tag: 'zz'.repeat(32) }, { ...w, note_id: '' }, { ...w, note_id: 'x'.repeat(201) }, { ...w, note_id: 7 },
    { type: w.type, note_id: 'n', code: 'delivered' }, [], null, 'str',
  ]) assert.equal(parseReceiptWireV1(JSON.stringify(bad)), null, JSON.stringify(bad).slice(0, 60));
  assert.equal(parseReceiptWireV1('not json'), null);
  assert.equal(buildReceiptWireV1(undefined, 'n', 'delivered'), null);
  assert.equal(buildReceiptWireV1('ab'.repeat(31), 'n', 'delivered'), null, 'a short key builds nothing');
});

test('S1 sealReceiptV1To is hybrid-only: it needs the sender KEM key, opens only for the sender, and sealReceiptTo (the classical body) THROWS', async () => {
  const [A, B] = [await mint(), await mint()];
  const w = buildReceiptWireV1(receiptKeyToHex(newReceiptKey()), 'n1', 'delivered')!;
  await assert.rejects(() => sealReceiptV1To(w, A.pub, undefined), /no classical downgrade/);
  await assert.rejects(() => sealReceiptV1To({ ...w, type: 'svrnty-note-v0' } as never, A.pub, A.kem), /refusing non-receipt/);
  const blob = await sealReceiptV1To(w, A.pub, A.kem);
  assert.deepEqual(parseReceiptWireV1(await openAs(A, blob)), w);
  const hybridB = await deriveOwnerHybridSecrets(B.priv, B.kpass, B.kem, B.kemSec);
  const { asMailboxEnvelopePackage } = await import('@/lib/sync/hybrid-dual-read');
  const opened = await openMailboxEnvelope(asMailboxEnvelopePackage(blob)!, hybridB!.secrets, hybridB!.myFp).catch(() => null);
  assert.equal(opened, null, 'a third party cannot open it');
  await assert.rejects(() => (sealReceiptTo as unknown as (...a: unknown[]) => Promise<unknown>)({}, A.pub), /removed/);
});

test('E1 done_when: after a stored note the recipient deposits ONE hybrid receipt in the SENDER\'s mailbox; only the sender can open it; the tag verifies under the sender\'s rk; nothing identifying or secret rides it', async () => {
  const [A, B] = [await mint(), await mint()]; // A sent the note, B stores it and answers
  const { wire, rkHex } = await signedNote(A);
  const { posts, fetchImpl } = relay();
  const out = await emitDeliveredReceipt(wire, { fetchImpl, relayBase: 'http://relay.test/api/relay' });
  assert.equal(out, 'sent');
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, 'http://relay.test/api/relay/envelope');
  assert.equal(posts[0].mailbox_id, deriveMailboxId(A.fp), 'addressed to the SENDER, derived from the signature-bound fingerprint');
  assert.notEqual(posts[0].mailbox_id, deriveMailboxId(B.fp));
  const inner = await openAs(A, posts[0].blob);
  const r = parseReceiptWireV1(inner)!;
  assert.equal(r.note_id, wire.note_id); assert.equal(r.code, 'delivered');
  assert.equal(verifyReceiptTag(receiptKeyFromHex(rkHex)!, wire.note_id, 'delivered', r.tag), true);
  assert.equal(verifyReceiptTag(receiptKeyFromHex(rkHex)!, wire.note_id, 'read', r.tag), false, 'the tag does not transfer to another code');
  for (const leak of [rkHex, A.fp, B.fp, 'signature', 'public_key']) {
    assert.equal(inner.includes(leak), false, `the receipt plaintext must not contain ${leak.slice(0, 12)}`);
    assert.equal(posts[0].blob.includes(rkHex), false);
  }
});

test('E2 refusals: no receipt_key / malformed key / not a note / classical sender (no ML-KEM key) / no public key => NOTHING is deposited (and a classical sender is never downgraded)', async () => {
  const A = await mint();
  const cases: Array<[string, NoteWireV0]> = [];
  cases.push(['no key', (await signedNote(A, { receipt_key: undefined })).wire]);
  cases.push(['short key', (await signedNote(A, { receipt_key: 'ab'.repeat(31) })).wire]);
  cases.push(['non-hex key', (await signedNote(A, { receipt_key: 'zz'.repeat(32) })).wire]);
  cases.push(['classical sender', (await signedNote(A, {}, false)).wire]);
  const ok = (await signedNote(A)).wire;
  cases.push(['wrong type', { ...ok, type: 'svrnty-resync-v0' } as never]);
  cases.push(['no public key', { ...ok, public_key: undefined }]);
  for (const [name, wire] of cases) {
    const { posts, fetchImpl } = relay();
    assert.equal(await emitDeliveredReceipt(wire, { fetchImpl }), 'skipped', name);
    assert.equal(posts.length, 0, name);
  }
});

test('E3 best-effort: a relay error / refusal / rejection / hang returns failed and NEVER throws', async () => {
  const A = await mint();
  const { wire } = await signedNote(A);
  assert.equal(await emitDeliveredReceipt(wire, { fetchImpl: (async () => new Response('x', { status: 500 })) as never }), 'failed');
  assert.equal(await emitDeliveredReceipt(wire, { fetchImpl: (async () => { throw new Error('offline'); }) as never }), 'failed');
  assert.equal(await emitDeliveredReceipt(wire, { fetchImpl: (() => new Promise(() => {})) as never, postTimeoutMs: 50 }), 'failed', 'a relay that never answers cannot hang the poll');
});
