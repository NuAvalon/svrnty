// Weft port of dev 9dd2cf2's consume-mailbox hunk (Archie #2401 / #3009, Hypatia #3008): a 2xx /queue whose body is NOT a list
// sets summary.rejected = the status. Before it, the poll reported polled 0 with rejected unset: the same summary as a clean,
// empty mailbox, which is what watchmail and ward read ("Caught up." in headless form).
// Run: npx --no-install tsx --test src/lib/sync/consume-mailbox-nonlist-2xx.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps } from '@/lib/sync/consume-mailbox';

let owner: ConsumeDeps['owner'];
before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
    curve: 'ed25519',
    userIDs: [{ name: 'alice', email: 'alice@x.test' }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint().toUpperCase();
  owner = { fingerprint, publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

const poll = (body: string, status = 200) => {
  let acks = 0;
  const fetchImpl: typeof fetch = async (url) => {
    if (String(url).includes('/ack')) { acks++; return new Response('{}', { status: 200 }); }
    return new Response(body, { status, headers: { 'content-type': 'application/json' } });
  };
  const deps: ConsumeDeps = {
    owner,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    fetchImpl,
  };
  return consumeInboundContactUpdates(deps).then((s) => ({ s, acks }));
};

test('a 2xx whose body is not a list is REJECTED (status recorded), never a clean empty poll', async () => {
  for (const [body, status] of [['{}', 200], ['null', 200], ['"queue"', 200], ['42', 200], ['{"envelopes":[]}', 200], ['{}', 203]] as const) {
    const { s, acks } = await poll(body, status);
    assert.equal(s.rejected, status, `body ${body} / ${status} → rejected must be ${status}`);
    assert.equal(s.polled, 0, `body ${body}: nothing was polled`);
    assert.equal(acks, 0, `body ${body}: nothing is acked`);
  }
});

test('a 2xx empty LIST is the clean empty mailbox: polled 0, rejected absent', async () => {
  const { s, acks } = await poll('[]');
  assert.equal(s.rejected, undefined);
  assert.equal(s.polled, 0);
  assert.equal(acks, 0);
});

test('a refused poll (401) still reports its status (unchanged path)', async () => {
  const { s } = await poll('{"error":"unauthorized"}', 401);
  assert.equal(s.rejected, 401);
});
