// Run: npx tsx --test src/lib/headless/headless-send-recipient-gate.test.ts
// An agent's note goes only to someone its book admits. The check runs first, so a refused note leaves no outbound row and posts nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';
type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, sig: id.pq_sig_public_key };
}
const owner = (id: Id): HeadlessOwner => ({ fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass, kemPublicKey: id.kem, sigPublicKey: id.sig });

async function attempt(contacts: (b: Id) => Array<Partial<HeadlessContact>>) {
  const [A, B] = [await mint(), await mint()];
  const store = new HeadlessStore();
  for (const c of contacts(B)) store.upsertContact(c as HeadlessContact);
  let posts = 0;
  const fetchImpl = (async () => { posts++; return new Response('{"ok":true}', { status: 200 }); }) as unknown as typeof fetch;
  const send = () => sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'x', store, relayBase: RELAY, fetchImpl });
  return { send, store, posts: () => posts };
}

test('control: a contact in the book who is not blocked gets the note', async () => {
  const t = await attempt((b) => [{ id: 'c1', fingerprint: b.fp, public_key: b.pub }]);
  const r = await t.send();
  assert.equal(r.deposited, true);
  assert.equal(t.posts(), 1);
  assert.equal(t.store.listNotes().length, 1);
});

const REFUSED: Array<[string, (b: Id) => Array<Partial<HeadlessContact>>]> = [
  ['not in the book', () => []],
  ['blocked at the top level', (b) => [{ id: 'c1', fingerprint: b.fp, public_key: b.pub, blocked: true }]],
  ['blocked only in metadata', (b) => [{ id: 'c1', fingerprint: b.fp, public_key: b.pub, metadata: { blocked: true } }]],
  ['blocked and trusted', (b) => [{ id: 'c1', fingerprint: b.fp, public_key: b.pub, blocked: true, trusted: true }]],
  ['blocked under another spelling of the same fingerprint', (b) => [{ id: 'c1', fingerprint: b.fp.toUpperCase(), public_key: b.pub, blocked: true }]],
];
for (const [name, book] of REFUSED) {
  test(`refused, ${name}: it throws before anything happens, so no POST and no outbound row`, async () => {
    const t = await attempt(book);
    await assert.rejects(t.send, /blocked or not in the address book/);
    assert.equal(t.posts(), 0);
    assert.equal(t.store.listNotes().length, 0);
    assert.equal(t.store.listThreads().length, 0);
  });
}
