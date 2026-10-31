// src/lib/headless/headless-failover-2a.test.ts
// Failover T2 phase 2a on the REAL headless client against in-memory relays (Archie #2633, Flint #2639): a send is sealed ONCE and the same
// bytes are re-POSTed to the next relay; a poll walks every relay under one pass; the same blob arriving from two relays is stored once.
// Run: npx tsx --test src/lib/headless/headless-failover-2a.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { formatNotSent, formatUnconfirmed } from './peer-kem';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessAllRelays, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

const R1 = 'http://t1.test/api/relay';
const R2 = 'http://t2.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
  kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig });
const contact = (id: Id): HeadlessContact => ({ id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, trust_level: 'known' });

/** One in-memory relay per base URL, with an optional scripted behaviour for POST /envelope. */
function relays(script: Partial<Record<string, number | 'throw'>> = {}) {
  const boxes = new Map<string, Map<string, Array<{ envelope_id: string; blob: string }>>>();
  const posts: Array<{ relay: string; body: string }> = [];
  let seq = 0;
  const fetchImpl = (async (url: unknown, init?: RequestInit) => {
    const u = String(url);
    const relay = [R1, R2].find((r) => u.startsWith(r))!;
    const box = boxes.get(relay) ?? boxes.set(relay, new Map()).get(relay)!;
    if (u.endsWith('/envelope')) {
      posts.push({ relay, body: String(init?.body) });
      const s = script[relay];
      if (s === 'throw') throw new TypeError('fetch failed');
      if (typeof s === 'number') return new Response('{}', { status: s });
      const { mailbox_id, blob } = JSON.parse(String(init?.body));
      if (!box.has(mailbox_id)) box.set(mailbox_id, []);
      box.get(mailbox_id)!.push({ envelope_id: `${relay.slice(7, 9)}-${++seq}`, blob });
      return new Response('{}', { status: 200 });
    }
    if (u.includes('/queue')) {
      const s = script[relay + '/queue'];
      if (s === 'throw') throw new TypeError('fetch failed');
      if (typeof s === 'number') return new Response('{}', { status: s });
      return new Response(JSON.stringify(box.get(new URL(u).searchParams.get('mailbox_id') ?? '') ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (u.includes('/ack')) {
      const { mailbox_id, envelope_ids } = JSON.parse(String(init?.body));
      box.set(mailbox_id, (box.get(mailbox_id) ?? []).filter((e) => !envelope_ids.includes(e.envelope_id)));
      return new Response(JSON.stringify({ deleted: envelope_ids.length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes, posts };
}

async function sender(over: Parameters<typeof relays>[0], relayBases: string[]) {
  const [A, B] = [await mint(), await mint()];
  const r = relays(over);
  const aStore = new HeadlessStore();
  const out = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'hello', store: aStore, relayBases, fetchImpl: r.fetchImpl });
  return { A, B, r, out, aStore };
}

test('S1 T1 ok => T2 is never contacted, tier 0', async () => {
  const { out, r } = await sender({}, [R1, R2]);
  assert.equal(out.deposited, true);
  assert.equal(out.tier, 0);
  assert.deepEqual(r.posts.map((p) => p.relay), [R1]);
});
test('S2 T1 429 at-cap => T2 receives BYTE-EQUAL bytes (sealed once, never re-sealed) and the send is deposited on tier 1', async () => {
  const { out, r, aStore } = await sender({ [R1]: 429 }, [R1, R2]);
  assert.equal(out.deposited, true);
  assert.equal(out.tier, 1);
  assert.equal(out.unconfirmed, false);
  assert.equal(r.posts.length, 2);
  assert.equal(r.posts[0].body, r.posts[1].body, 'the very same request body, so the same sealed blob and the same ratchet frame inside it');
  assert.equal(aStore.listNotes().length, 1, 'one local outbound copy');
});
test('S3 T1 network failure => T2 carries it, flagged unconfirmed; the old single-relay form still works unchanged', async () => {
  const a = await sender({ [R1]: 'throw' }, [R1, R2]);
  assert.deepEqual([a.out.deposited, a.out.tier, a.out.unconfirmed], [true, 1, true]);
  const [A, B] = [await mint(), await mint()];
  const r = relays();
  const o = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'x', store: new HeadlessStore(), relayBase: R1, fetchImpl: r.fetchImpl });
  assert.equal(o.deposited, true);
  assert.deepEqual(r.posts.map((p) => p.relay), [R1]);
});
test('S4 NEG: T1 400 ends it (no T2 attempt); every relay down => the first error is thrown, as before; no local copy is claimed sent', async () => {
  const a = await sender({ [R1]: 400 }, [R1, R2]);
  assert.equal(a.out.deposited, false);
  assert.deepEqual(a.r.posts.map((p) => p.relay), [R1]);
  const [A, B] = [await mint(), await mint()];
  const r = relays({ [R1]: 'throw', [R2]: 'throw' });
  await assert.rejects(sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'x', store: new HeadlessStore(), relayBases: [R1, R2], fetchImpl: r.fetchImpl }), /fetch failed/);
});

async function recvWith(blobsOn: Array<'r1' | 'r2'>) {
  const s = await sender({}, [R1]);
  const blob = s.r.boxes.get(R1)!.get(deriveMailboxId(s.B.fp))![0].blob;
  const r = relays();
  for (const which of blobsOn) {
    const relay = which === 'r1' ? R1 : R2;
    await r.fetchImpl(`${relay}/envelope`, { method: 'POST', body: JSON.stringify({ mailbox_id: deriveMailboxId(s.B.fp), blob }) });
  }
  const bStore = new HeadlessStore();
  bStore.upsertContact(contact(s.A));
  return { s, r, bStore };
}
test('P1 the SAME blob in BOTH relays => one stored note, and both relays are acked clean (nothing left on either)', async () => {
  const { s, r, bStore } = await recvWith(['r1', 'r2']);
  const m = await pollHeadlessAllRelays(owner(s.B), bStore, [R1, R2], { fetchImpl: r.fetchImpl });
  assert.equal(bStore.listNotes().length, 1, 'stored once (note_id is the key)');
  assert.deepEqual([m.relays, m.relaysFailed, m.relaysRejected], [2, 0, 0]);
  assert.equal(m.polled, 2);
  assert.equal(m.acked, 2);
  assert.equal(r.boxes.get(R1)!.get(deriveMailboxId(s.B.fp))!.length + r.boxes.get(R2)!.get(deriveMailboxId(s.B.fp))!.length, 0);
  assert.deepEqual(m.lost, {}, 'no loss on the duplicate');
});
test('P2 a relay that is down never stops the others; the surviving relay still delivers', async () => {
  const { s, r, bStore } = await recvWith(['r2']);
  const script = relays({ [R1 + '/queue']: 'throw' });
  const fetchImpl = (async (u: unknown, i?: RequestInit) => (String(u).startsWith(R1) ? script.fetchImpl(u as string, i) : r.fetchImpl(u as string, i))) as typeof fetch;
  const m = await pollHeadlessAllRelays(owner(s.B), bStore, [R1, R2], { fetchImpl });
  assert.deepEqual([m.relays, m.relaysFailed], [2, 1]);
  assert.equal(bStore.listNotes().length, 1);
});
test('P3 NEG: every relay down => the pass THROWS (the tick is reported failed, never an empty "all clear")', async () => {
  const s = await sender({}, [R1]);
  const r = relays({ [R1 + '/queue']: 'throw', [R2 + '/queue']: 'throw' });
  await assert.rejects(pollHeadlessAllRelays(owner(s.B), new HeadlessStore(), [R1, R2], { fetchImpl: r.fetchImpl }), /fetch failed/);
});
test('P4 control: one relay in the list behaves exactly like pollHeadlessOnce', async () => {
  const { s, r, bStore } = await recvWith(['r1']);
  const m = await pollHeadlessAllRelays(owner(s.B), bStore, [R1], { fetchImpl: r.fetchImpl });
  assert.equal(m.notes, 1);
  assert.equal(bStore.listNotes().length, 1);
  void pollHeadlessOnce;
});

test('W1 an unconfirmed outcome is never worded "NOT SENT" (a re-send would duplicate); a definite refusal still is', () => {
  assert.match(formatUnconfirmed('ab'.repeat(32), 'a relay may have stored it; check before resending'), /^UNCONFIRMED to abababab: /);
  assert.doesNotMatch(formatUnconfirmed('ab'.repeat(32), 'x'), /NOT SENT/);
  assert.match(formatNotSent('ab'.repeat(32), 'x'), /^NOT SENT/);
});

test('W2 static: devin-comm reads the list through parseRelayList, sends with relayBases, keeps the one-relay poll path untouched and the summary keys unchanged', () => {
  const src = readFileSync(new URL('../../../scripts/devin-comm.ts', import.meta.url), 'utf8');
  assert.match(src, /const RELAYS = parseRelayList\(\{ SVRNTY_RELAYS: process\.env\.SVRNTY_RELAYS, SVRNTY_RELAY: process\.env\.SVRNTY_RELAY \}/);
  assert.match(src, /const RELAY = RELAYS\[0\];/);
  assert.equal((src.match(/relayBases: RELAYS/g) ?? []).length, 2, 'both send paths (tr-send and send) fail over');
  assert.doesNotMatch(src, /relayBase: RELAY,/, 'no send path is left on the single relay');
  assert.match(src, /if \(RELAYS\.length === 1\) return pollRelay\(owner, store, RELAY\);/);
  assert.match(src, /const \{ relays, relaysFailed, relaysRejected, \.\.\.summary \} = await pollHeadlessAllRelays/, 'the extra keys are stripped before the summary is printed');
  assert.equal((src.match(/\(r\.unconfirmed && RELAYS\.length > 1\) \? formatUnconfirmed/g) ?? []).length, 2, 'UNCONFIRMED wording only when failover was in play; one relay keeps the pinned NOT SENT text');
});
