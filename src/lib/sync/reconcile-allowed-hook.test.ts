// reconcile-allowed-hook — FE integration hook for #572 part 2 (gate -> seed -> reconcile, fail-soft).
// Run: npx tsx --test src/lib/sync/reconcile-allowed-hook.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, decryptKey, readPrivateKey } from 'openpgp';
import { reconcileAllowedOnConsentChange } from './reconcile-allowed-hook';

const passphrase = 'reconcile-hook-test-pass';
const ownerFp = 'ab'.repeat(32);
const senderFp = 'cd'.repeat(32);

let privateKey: string;

before(async () => {
  const generated = await generateKey({
    type: 'ecc',
    // openpgp runtime accepts 'ed25519' (what every svrnty test uses); the bundled .d.ts only names
    // 'ed25519Legacy' — known types-vs-runtime drift. Cast the literal so tsc stays at baseline.
    curve: 'ed25519' as 'ed25519Legacy',
    userIDs: [{ name: 'Hook', email: 'hook@example.test' }],
    passphrase,
    format: 'armored',
  });
  privateKey = generated.privateKey;
  // sanity: the generated key is a valid svrnty identity key (decrypt + extract must work)
  const locked = await readPrivateKey({ armoredKey: privateKey });
  assert.ok(locked.isDecrypted() || (await decryptKey({ privateKey: locked, passphrase })));
});

/** A loadKey stub that returns the real generated identity (unlocked path). */
const loadKeyOk = async () => ({ privateKey, passphrase });

/** Capture every fetch the hook issues so we can assert method + URL. */
function recordingFetch() {
  const calls: Array<{ url: string; method: string }> = [];
  const fetchImpl = (async (url: unknown, init?: { method?: string }) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET' });
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

const FULL_INVARIANT = { trusted: true, openVisibility: true, blocked: false };

test('GATE dark (isPSIDiscoveryLive=false): skips entirely — no loadKey, no fetch', async () => {
  const { calls, fetchImpl } = recordingFetch();
  let loadKeyCalled = false;
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp,
    consent: FULL_INVARIANT,
    gate: () => false,
    loadKeyImpl: (async () => { loadKeyCalled = true; return { privateKey, passphrase }; }) as never,
    fetchImpl,
  });
  assert.deepEqual(res, { skipped: 'dark' });
  assert.equal(loadKeyCalled, false, 'must not touch the identity when gated dark');
  assert.equal(calls.length, 0, 'must issue no /allowed traffic when gated dark');
});

test('no peer fingerprint: skips (not a svrnty-network peer) — no fetch', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp: '',
    consent: FULL_INVARIANT,
    gate: () => true,
    loadKeyImpl: loadKeyOk,
    fetchImpl,
  });
  assert.deepEqual(res, { skipped: 'no-peer' });
  assert.equal(calls.length, 0);
});

test('identity LOCKED (loadKey → null): skips fail-soft — no fetch, no throw', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp,
    consent: FULL_INVARIANT,
    gate: () => true,
    loadKeyImpl: (async () => null) as never,
    fetchImpl,
  });
  assert.deepEqual(res, { skipped: 'locked' });
  assert.equal(calls.length, 0);
});

test('full invariant (trusted ∩ open_vis ∩ !blocked) + unlocked → ADD (POST /allowed/{owner})', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp,
    consent: FULL_INVARIANT,
    gate: () => true,
    loadKeyImpl: loadKeyOk,
    fetchImpl,
  });
  assert.deepEqual(res, { action: 'add', ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.ok(calls[0].url.endsWith(`/api/satellite/allowed/${ownerFp}`), calls[0].url);
});

test('each invariant EXIT → DELETE (/allowed/{owner}/{sender}) — the #111 satellite revoke', async () => {
  const exits = [
    { name: 'untrust', consent: { trusted: false, openVisibility: true, blocked: false } },
    { name: 'go-private', consent: { trusted: true, openVisibility: false, blocked: false } },
    { name: 'block', consent: { trusted: false, openVisibility: false, blocked: true } },
  ];
  for (const { name, consent } of exits) {
    const { calls, fetchImpl } = recordingFetch();
    const res = await reconcileAllowedOnConsentChange({
      ownerFp, senderFp, consent, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl,
    });
    assert.deepEqual(res, { action: 'delete', ok: true }, `exit=${name}`);
    assert.equal(calls.length, 1, `exit=${name}`);
    assert.equal(calls[0].method, 'DELETE', `exit=${name}`);
    assert.ok(
      calls[0].url.endsWith(`/api/satellite/allowed/${ownerFp}/${senderFp}`),
      `exit=${name}: ${calls[0].url}`,
    );
  }
});

test('contact-REMOVE (6th exit): all-false "peer gone" consent → unconditional DELETE', async () => {
  const { calls, fetchImpl } = recordingFetch();
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp,
    // removeContact passes {false,false,false} — the peer no longer exists, so nothing is revealed and
    // the row must not exist. allowedRowShouldExist=false → DELETE regardless of prior trust/open-vis.
    consent: { trusted: false, openVisibility: false, blocked: false },
    gate: () => true,
    loadKeyImpl: loadKeyOk,
    fetchImpl,
  });
  assert.deepEqual(res, { action: 'delete', ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'DELETE');
  assert.ok(calls[0].url.endsWith(`/api/satellite/allowed/${ownerFp}/${senderFp}`), calls[0].url);
});

test('FAIL-SOFT: a decrypt/extract failure returns skipped:error, never throws', async () => {
  const res = await reconcileAllowedOnConsentChange({
    ownerFp,
    senderFp,
    consent: FULL_INVARIANT,
    gate: () => true,
    // garbage armored key → readPrivateKey/decrypt throws inside the hook
    loadKeyImpl: (async () => ({ privateKey: 'not-a-real-armored-key', passphrase })) as never,
  });
  assert.deepEqual(res, { skipped: 'error' });
});

test('FAIL-SOFT: satellite non-2xx → reconcile returns ok:false (handler still fine)', async () => {
  const fetchImpl = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch;
  const res = await reconcileAllowedOnConsentChange({
    ownerFp, senderFp, consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl,
  });
  assert.deepEqual(res, { action: 'add', ok: false });
});
