// src/lib/headless/open-legs-headless.test.ts
// #720 (Archie #2032, Flint #2031): the REAL headless receive path reports which leg opened a note. Real keys, real sealing, real consume.
// Run: npx tsx --test src/lib/headless/open-legs-headless.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { signNoteWire } from '@/lib/messaging/note-auth';
import { sealNoteClassicalFixture } from '@/lib/messaging/seal-classical-fixture';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const owner = (id: Id, withSecret: boolean): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass, kemPublicKey: id.kem, ...(withSecret ? { kemSecretKey: id.kemSec } : {}), sigPublicKey: id.sig });
const asContact = (id: Id): HeadlessContact => ({ id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem });

function mockRelay() {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  let seq = 0;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `e${++seq}`, blob });
      return new Response('{"ok":true}', { status: 200 });
    }
    if (u.includes('/queue')) return new Response(JSON.stringify(boxes.get(new URL(u).searchParams.get('mailbox_id') ?? '') ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    if (u.includes('/ack')) {
      const { mailbox_id, envelope_ids } = JSON.parse(String(init?.body ?? '{}'));
      boxes.set(mailbox_id, (boxes.get(mailbox_id) ?? []).filter((e) => !envelope_ids.includes(e.envelope_id)));
      return new Response('{"deleted":1}', { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes };
}

/** A signed note sealed the OLD way (OpenPGP only), as a sender that never moved to hybrid would still deposit it. */
async function depositClassical(from: Id, to: Id, boxes: Map<string, Array<{ envelope_id: string; blob: string }>>, noteId: string) {
  const unsigned: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: noteId, thread_id: 't-' + noteId, from_fingerprint: from.fp, sent_at: new Date().toISOString(), body: 'classical hello', participant_kind: 'agent' };
  const wire = await signNoteWire(unsigned, from.pub, from.priv, from.kpass, from.kem, from.sig);
  const blob = await sealNoteClassicalFixture(wire, to.pub);
  const mid = deriveMailboxId(to.fp);
  boxes.set(mid, [...(boxes.get(mid) ?? []), { envelope_id: 'c-' + noteId, blob }]);
}

test('O1 a HYBRID note opens on the hybrid leg: opened_hybrid=1, opened_classical=0; the next (empty) poll reports 0/0', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A));
  await sendNoteFromHeadless({ owner: owner(A, true), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'hybrid hello', store: new HeadlessStore(), relayBase: RELAY, fetchImpl });
  const s = await pollHeadlessOnce(owner(B, true), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(s.notes, 1);
  assert.equal(s.opened_hybrid, 1); assert.equal(s.opened_classical, 0);
  const again = await pollHeadlessOnce(owner(B, true), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(again.opened_hybrid, 0); assert.equal(again.opened_classical, 0);
});

test('O2 a CLASSICAL note (old sender) opens on the classical leg of a hybrid-capable owner: opened_classical=1, opened_hybrid=0', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A));
  await depositClassical(A, B, boxes, 'n-classical-1');
  const s = await pollHeadlessOnce(owner(B, true), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(s.notes, 1, 'the classical note still opens (compat) ...');
  assert.equal(s.opened_classical, 1, '... and is COUNTED as classical, so the removal decision has evidence');
  assert.equal(s.opened_hybrid, 0);
});

test('O3 an owner with NO ML-KEM secret (classical-only openers) still counts its opens as classical', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A));
  await depositClassical(A, B, boxes, 'n-classical-2');
  const s = await pollHeadlessOnce(owner(B, false), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(s.notes, 1);
  assert.equal(s.opened_classical, 1); assert.equal(s.opened_hybrid, 0);
});

test('O4 an unopenable junk blob counts as neither leg', async () => {
  const B = await mint();
  const { fetchImpl, boxes } = mockRelay();
  boxes.set(deriveMailboxId(B.fp), [{ envelope_id: 'junk1', blob: 'not-a-blob' }]);
  const s = await pollHeadlessOnce(owner(B, true), new HeadlessStore(), { relayBase: RELAY, fetchImpl });
  assert.equal(s.opened_hybrid, 0); assert.equal(s.opened_classical, 0);
});

test('O5 poll-json PRINTS the counters under the exact names the ward allowlist (devin_quarantine, Flint 529322d5) accepts: a key not printed here is invisible to the ward', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../../../scripts/devin-comm.ts', import.meta.url), 'utf8');
  const line = src.slice(src.indexOf('console.log(JSON.stringify({ journaled'), src.indexOf("    return;\n  }\n\n  if (cmd === 'loop')"));
  for (const key of ['held: consumed.held', 'deadLettered: consumed.deadLettered', 'unrecorded: consumed.unrecorded', 'released: consumed.released', 'lost: consumed.lost', 'opened_hybrid: consumed.opened_hybrid', 'opened_classical: consumed.opened_classical']) {
    assert.ok(line.includes(key), `poll-json must print ${key}`);
  }
});
