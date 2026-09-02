// Unit tests for the joiner's return-channel deposit (send-joiner-response.ts). Uses REAL openpgp keys
// (mirrors joiner-response.e2e.test.ts) so the round-trip is genuine: buildJoinerResponseDeposit →
// blob → verifyJoinerResponse recovers the KNOWN joiner. Plus the fail-closed + POST accounting paths.
// Run: npx tsx --test src/lib/sync/send-joiner-response.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { buildJoinerResponseDeposit, sendJoinerResponse } from './send-joiner-response';
import { verifyJoinerResponse } from '../trust/joiner-response';
import { deriveMailboxId } from '../relay/mailbox-auth';

const pass = 'test-passphrase-sjr';
const CODE = 'GROW42';

let alicePriv: string, alicePub: string, aliceFp: string; // GIVER (mailbox owner / recipient)
let bobPriv: string, bobPub: string, bobFp: string;        // JOINER (sender)

before(async () => {
  ({ privateKey: alicePriv, publicKey: alicePub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.test' }], passphrase: pass, format: 'armored',
  }));
  aliceFp = (await readKey({ armoredKey: alicePub })).getFingerprint();
  ({ privateKey: bobPriv, publicKey: bobPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Bob', email: 'bob@example.test' }], passphrase: pass, format: 'armored',
  }));
  bobFp = (await readKey({ armoredKey: bobPub })).getFingerprint();
});

function bobSender() {
  return { fingerprint: bobFp, epoch: 0, publicKeyArmored: bobPub, displayName: 'Bob', privateKeyArmored: bobPriv, passphrase: pass };
}
function aliceTarget(overrides: Partial<{ fingerprint: string; publicKeyArmored: string; inviteNonce: string }> = {}) {
  return { fingerprint: aliceFp, publicKeyArmored: alicePub, inviteNonce: CODE, ...overrides };
}

// ── The deposit is addressed + encrypted so the giver's verifyJoinerResponse recovers the joiner ──
test('buildJoinerResponseDeposit: addresses the giver mailbox and round-trips through verifyJoinerResponse', async () => {
  const deposit = await buildJoinerResponseDeposit(bobSender(), aliceTarget());
  assert.ok(deposit, 'a valid sender+target must produce a deposit');
  assert.equal(deposit!.mailbox_id, deriveMailboxId(aliceFp), 'addressed to the giver’s derived mailbox id');

  // The blob decrypts to Alice and verifies to Bob-as-KNOWN (the code is a solicited nonce Alice issued).
  const joiner = await verifyJoinerResponse(
    deposit!.blob,
    { fingerprint: aliceFp, privateKeyArmored: alicePriv, passphrase: pass },
    (n) => n === CODE,
  );
  assert.ok(joiner, 'the deposited blob must verify to a PendingJoiner at the giver');
  assert.equal(joiner!.fingerprint, bobFp);
  assert.equal(joiner!.epoch, 0, 'epoch 0 — the giver’s future contact.update replay floor');
  assert.equal(joiner!.inviteNonce, CODE);
  assert.equal(joiner!.displayName, 'Bob');
});

// ── The response is bound to THIS giver — a different giver’s verify rejects it (no cross-giver replay) ──
test('buildJoinerResponseDeposit: the blob is giver-bound (a wrong-fp verify rejects it)', async () => {
  const deposit = await buildJoinerResponseDeposit(bobSender(), aliceTarget());
  // A different owner (fresh key) polling with the SAME code oracle must NOT accept Alice’s response —
  // it can’t even decrypt it (encrypted to Alice), and giver_fingerprint is signed to Alice.
  const { privateKey: evePriv, publicKey: evePub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Eve', email: 'eve@example.test' }], passphrase: pass, format: 'armored',
  });
  const eveFp = (await readKey({ armoredKey: evePub })).getFingerprint();
  const notForEve = await verifyJoinerResponse(
    deposit!.blob,
    { fingerprint: eveFp, privateKeyArmored: evePriv, passphrase: pass },
    () => true,
  );
  assert.equal(notForEve, null, 'a joiner-response encrypted+bound to Alice must not verify for Eve');
});

// ── Fail-closed: no usable target key / missing binding fields → null (never a downgraded send) ──
test('buildJoinerResponseDeposit: returns null on a target with no key / no fingerprint / no nonce', async () => {
  assert.equal(await buildJoinerResponseDeposit(bobSender(), aliceTarget({ publicKeyArmored: '' })), null, 'no giver key → null');
  assert.equal(await buildJoinerResponseDeposit(bobSender(), aliceTarget({ fingerprint: '' })), null, 'no giver fp → null');
  assert.equal(await buildJoinerResponseDeposit(bobSender(), aliceTarget({ inviteNonce: '' })), null, 'no invite nonce → null');
  // A garbage recipient key must be caught (encrypt throws internally) → null, not a throw.
  assert.equal(await buildJoinerResponseDeposit(bobSender(), aliceTarget({ publicKeyArmored: 'not-a-key' })), null, 'bad giver key → null (no throw)');
});

// ── sendJoinerResponse: honest POST accounting, fail-soft on relay/network errors ──
test('sendJoinerResponse: POSTs {mailbox_id, blob} to /api/relay/envelope and reports ok', async () => {
  let seen: { url: string; body: any } | null = null;
  const okFetch = (async (url: string, init: any) => { seen = { url, body: JSON.parse(init.body) }; return { ok: true, status: 200 }; }) as unknown as typeof fetch;
  const res = await sendJoinerResponse(bobSender(), aliceTarget(), { fetchImpl: okFetch });
  assert.equal(res.ok, true);
  assert.ok(seen, 'fetch was called');
  assert.match((seen as any).url, /\/api\/relay\/envelope$/);
  assert.equal((seen as any).body.mailbox_id, deriveMailboxId(aliceFp));
  assert.ok(typeof (seen as any).body.blob === 'string' && (seen as any).body.blob.length > 0, 'carries the opaque blob');
});

test('sendJoinerResponse: a relay non-2xx is reported (not thrown), status carried', async () => {
  const failFetch = (async () => ({ ok: false, status: 503 })) as unknown as typeof fetch;
  const res = await sendJoinerResponse(bobSender(), aliceTarget(), { fetchImpl: failFetch });
  assert.deepEqual(res, { ok: false, status: 503 });
});

test('sendJoinerResponse: a network error is caught and reported (fail-soft)', async () => {
  const throwFetch = (async () => { throw new Error('offline'); }) as unknown as typeof fetch;
  const res = await sendJoinerResponse(bobSender(), aliceTarget(), { fetchImpl: throwFetch });
  assert.deepEqual(res, { ok: false, status: 'network-error' });
});

test('sendJoinerResponse: an unbuildable deposit never POSTs (encrypt-failed)', async () => {
  let called = false;
  const spyFetch = (async () => { called = true; return { ok: true, status: 200 }; }) as unknown as typeof fetch;
  const res = await sendJoinerResponse(bobSender(), aliceTarget({ publicKeyArmored: '' }), { fetchImpl: spyFetch });
  assert.deepEqual(res, { ok: false, status: 'encrypt-failed' });
  assert.equal(called, false, 'no POST when there is no deposit to send');
});
