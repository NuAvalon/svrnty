// src/lib/headless/headless-thread-activity.test.ts
// Chat-list order on the headless poller (Archie #2541: the headless pollers re-process the most). The REAL pollHeadlessOnce against an
// in-memory mock relay: a thread's last_activity_at is monotone and clamped, exactly like the browser seam.
// Run: npx tsx --test src/lib/headless/headless-thread-activity.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';
import { ACTIVITY_FUTURE_SLACK_MS } from '@/lib/messaging/thread-activity';

const RELAY = 'http://relay.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
  kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig });
const asContact = (id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact => ({ id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub,
  pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, ...over });

/** Mailbox whose ack NEVER lands (Peter's 431 loop): every poll re-delivers the same envelopes. */
function stuckAckRelay() {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  let seq = 0;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `e${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/queue')) return new Response(JSON.stringify(boxes.get(new URL(u).searchParams.get('mailbox_id') ?? '') ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    return new Response('', { status: 431 });
  }) as unknown as typeof fetch;
  return { fetchImpl };
}

async function setup(seedActivity: string) {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = stuckAckRelay();
  const aStore = new HeadlessStore();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trust_level: 'known' }));
  await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'hi', store: aStore, relayBase: RELAY, fetchImpl });
  const thread_id = aStore.listNotes()[0].thread_id;
  bStore.putThread({ thread_id, kind: 'direct', participants: [{ fingerprint: A.fp, kind: 'human', display_name: 'A' }],
    created_at: '2026-10-01T00:00:00.000Z', last_activity_at: seedActivity, retention: { expires_at: null } });
  return { B, bStore, fetchImpl, thread_id };
}

test('H1 NEG: a note older than the thread\'s activity does not move it back, even re-delivered (ack never lands)', async () => {
  const seed = new Date(Date.now() + 2 * 60_000).toISOString(); // newer than the incoming note, inside the slack
  const { B, bStore, fetchImpl, thread_id } = await setup(seed);
  for (let i = 0; i < 3; i++) {
    const s = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
    assert.equal(s.notes, 1, `pass ${i}: the note is (re)processed`);
    assert.equal(bStore.listThreads().find((t) => t.thread_id === thread_id)!.last_activity_at, seed, `pass ${i}: activity unchanged`);
  }
});

test('H2 NEG: a legacy thread already pinned in 2099 heals to now+slack at the next note instead of sticking', async () => {
  const { B, bStore, fetchImpl, thread_id } = await setup('2099-01-01T00:00:00.000Z');
  const before = Date.now();
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  const got = Date.parse(bStore.listThreads().find((t) => t.thread_id === thread_id)!.last_activity_at);
  assert.ok(got <= Date.now() + ACTIVITY_FUTURE_SLACK_MS + 1000, 'no longer in 2099');
  assert.ok(got >= before + ACTIVITY_FUTURE_SLACK_MS - 5000, 'clamped at the ceiling, not dropped to the old note');
});
