// src/lib/sync/consume-mailbox-open-legs.test.ts
// #720: consume reports ONLY the opens of THIS poll. Run: npx tsx --test src/lib/sync/consume-mailbox-open-legs.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps } from './consume-mailbox';
import { counted, createOpenLegCounter } from './open-leg-counter';

let OWNER: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-legs';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'legs', email: 'legs@x.test' }],
    passphrase,
    format: 'armored',
  });
  OWNER = { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

const relay = (ids: string[]) => (async (url: string) => {
  if (String(url).includes('/queue')) return new Response(JSON.stringify(ids.map((id) => ({ envelope_id: id, blob: id }))), { status: 200, headers: { 'content-type': 'application/json' } });
  return new Response(JSON.stringify({ deleted: 1 }), { status: 200 });
}) as unknown as typeof fetch;
const deps = (over: Partial<ConsumeDeps>): ConsumeDeps => ({ owner: OWNER, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} }, relayBase: 'http://relay.test/api/relay', fetchImpl: relay([]), ...over });

test('P1 the summary carries exactly this poll\'s opens per leg, and the counter is reset for the next poll', async () => {
  const legs = createOpenLegCounter();
  const open = (leg: 'hybrid' | 'classical') => counted(async () => ({ envelope: { fingerprint: 'ab'.repeat(32) } }) as never, leg, legs);
  const decrypt = async (b: string) => (b.startsWith('h') ? open('hybrid')(b) : b.startsWith('c') ? open('classical')(b) : null);
  const s = await consumeInboundContactUpdates(deps({ openLegs: legs, decrypt, fetchImpl: relay(['h1', 'h2', 'c1', 'junk']) }));
  assert.equal(s.opened_hybrid, 2); assert.equal(s.opened_classical, 1);
  const next = await consumeInboundContactUpdates(deps({ openLegs: legs, decrypt, fetchImpl: relay([]) }));
  assert.equal(next.opened_hybrid, 0); assert.equal(next.opened_classical, 0);
});

test('P2 counts made OUTSIDE a poll (a stale bump) are discarded at poll start: a poll reports only its own opens', async () => {
  const legs = createOpenLegCounter();
  legs.bump('classical'); legs.bump('classical'); legs.bump('hybrid');
  const s = await consumeInboundContactUpdates(deps({ openLegs: legs, fetchImpl: relay([]) }));
  assert.equal(s.opened_hybrid, 0); assert.equal(s.opened_classical, 0);
});

test('P3 with no counter wired the fields are 0, never undefined (stable summary shape for poll-json)', async () => {
  const s = await consumeInboundContactUpdates(deps({}));
  assert.equal(s.opened_hybrid, 0); assert.equal(s.opened_classical, 0);
});
