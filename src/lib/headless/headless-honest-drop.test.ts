// src/lib/headless/headless-honest-drop.test.ts
// #720 say-why on the HEADLESS note seam: a dropped note carries its reason, like the FE seam (live-book-poll.ts). Before this, the
// headless accept returned a bare null for both "unsigned/forged" and "stranger/blocked", and consume-mailbox records a bare null as
// 'verify-failed'. A person's genuine first notes to an agent (sender not yet in the agent's book) then looked like broken crypto
// (Peter→Athena, 2026-10-31).
// Run: npx tsx --test src/lib/headless/headless-honest-drop.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { signNoteWire } from '@/lib/messaging/note-auth';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass, kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig });
const contact = (id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact => ({ id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, trust_level: 'known', ...over });

async function signedWire(from: Id, body = 'hello'): Promise<NoteWireV0> {
  const base = { type: 'svrnty-note-v0', note_id: 'n_' + Math.random().toString(36).slice(2), thread_id: 't1', from_fingerprint: from.fp, body,
    sent_at: '2026-10-31T19:00:00.000Z', participant_kind: 'human' } as unknown as NoteWireV0;
  return signNoteWire(base, from.pub, from.priv, from.kpass, from.kem, from.sig);
}

test('D1: a correctly SIGNED note from a sender NOT in the book → { dropped: "not-in-book", fp } (not a bare null)', async () => {
  const [A, B] = [await mint(), await mint()];
  const deps = await buildHeadlessConsumeDeps(owner(B), new HeadlessStore());
  const out = await deps.note!.accept(await signedWire(A));
  assert.deepEqual(out, { dropped: 'not-in-book', fp: A.fp });
});

test('D2: a BLOCKED contact → "not-in-book" too (no separate "blocked" reason leaves the device, same as the FE)', async () => {
  const [A, B] = [await mint(), await mint()];
  const s = new HeadlessStore();
  s.upsertContact(contact(A, { blocked: true } as Partial<HeadlessContact>));
  const deps = await buildHeadlessConsumeDeps(owner(B), s);
  assert.deepEqual(await deps.note!.accept(await signedWire(A)), { dropped: 'not-in-book', fp: A.fp });
});

test('D3 NEG: an UNSIGNED note, and a note whose signature does not match its body → { dropped: "unverified" } with NO fingerprint', async () => {
  const [A, B] = [await mint(), await mint()];
  const s = new HeadlessStore();
  s.upsertContact(contact(A)); // even an admitted fp: authentication comes first
  const deps = await buildHeadlessConsumeDeps(owner(B), s);
  const signed = await signedWire(A, 'original');
  const unsigned = { ...signed } as Record<string, unknown>;
  delete unsigned.signature;
  for (const w of [unsigned, { ...signed, body: 'tampered' }]) {
    const out = await deps.note!.accept(w as unknown as NoteWireV0);
    assert.deepEqual(out, { dropped: 'unverified' });
    assert.equal('fp' in (out as object), false, 'an unauthenticated from_fingerprint never travels (F3)');
  }
});

test('D4 control: the same signed note from an ADMITTED contact is stored (accepted, not dropped)', async () => {
  const [A, B] = [await mint(), await mint()];
  const s = new HeadlessStore();
  s.upsertContact(contact(A));
  const deps = await buildHeadlessConsumeDeps(owner(B), s);
  const out = await deps.note!.accept(await signedWire(A));
  assert.ok(out && !('dropped' in out), 'admitted + signed → accepted');
  assert.equal(s.listNotes().length, 1);
});

test('P1 the real poller: a stranger\'s genuine note is counted lost["not-in-book"], NOT lost["verify-failed"]', async () => {
  const [A, B] = [await mint(), await mint()];
  const box: Array<{ envelope_id: string; blob: string }> = [];
  const fetchImpl = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith('/envelope')) { box.push({ envelope_id: `e${box.length + 1}`, blob: JSON.parse(String(init?.body)).blob }); return new Response('{}', { status: 200 }); }
    if (u.includes('/queue')) return new Response(JSON.stringify([...box]), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.includes('/ack')) { const { envelope_ids } = JSON.parse(String(init?.body)); box.splice(0, box.length, ...box.filter((e) => !envelope_ids.includes(e.envelope_id))); return new Response('{"deleted":1}', { status: 200 }); }
    return new Response('', { status: 404 });
  }) as unknown as typeof fetch;
  await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'hi, I am new', store: new HeadlessStore(), relayBase: RELAY, fetchImpl });
  const summary = await pollHeadlessOnce(owner(B), new HeadlessStore(), { relayBase: RELAY, fetchImpl });
  assert.equal(summary.polled, 1);
  assert.equal(summary.lost['not-in-book'], 1);
  assert.equal(summary.lost['verify-failed'] ?? 0, 0, 'a stranger is not a forgery');
});
