// reconcile-allowed-hook — FE integration hook for #572 part 2 (gate -> seed -> reconcile, fail-soft).
// Run: npx tsx --test src/lib/sync/reconcile-allowed-hook.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, decryptKey, readPrivateKey } from 'openpgp';
import { reconcileAllowedOnConsentChange, reconcileAllowedOnRemove } from './reconcile-allowed-hook';

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

const FULL_INVARIANT = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };

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

// piece-1 (Flint seal #158892): KNOWN-reveal exits = go-private, block, per_contact_private (new). UNTRUST
// is NO LONGER a known-exit (trusted dropped to the trust layer, piece-2) → removed here; it's covered as
// an ADD in allowed-sync.test.ts. (The all-false contact-REMOVE 6th-exit is the test below.)
test('each invariant EXIT → DELETE (/allowed/{owner}/{sender}) — the #111 satellite revoke', async () => {
  const exits = [
    { name: 'go-private', consent: { trusted: true, openVisibility: false, blocked: false, perContactPrivate: false } },
    { name: 'block', consent: { trusted: false, openVisibility: false, blocked: true, perContactPrivate: false } },
    { name: 'per_contact_private', consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true } },
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
    consent: { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false },
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

// ---- #941: Remove of a contact that never had a satellite row sends the satellite nothing ----
// The row exists iff allowedRowShouldExist(consent) = open_visibility && !blocked && !per_contact_private ('trusted' is NOT a term). `consentBefore` is the consent read from the stored record BEFORE the removal.

const rm = (consentBefore: Parameters<typeof reconcileAllowedOnRemove>[0]['consentBefore'], extra: Partial<Parameters<typeof reconcileAllowedOnRemove>[0]> = {}) => {
  const rec = recordingFetch();
  let loads = 0;
  const loadKeyCounting = async () => { loads++; return { privateKey, passphrase }; };
  const run = () => reconcileAllowedOnRemove({ ownerFp, senderFp, consentBefore, gate: () => true, loadKeyImpl: loadKeyCounting, fetchImpl: rec.fetchImpl, ...extra });
  return { ...rec, run, loads: () => loads };
};

test('RM1 a contact that never had a row (the fresh-import default: nothing open, not blocked) -> Remove sends NOTHING: 0 requests, the key is not even loaded', async () => {
  const t = rm({ trusted: false, openVisibility: false, blocked: false, perContactPrivate: false });
  assert.deepEqual(await t.run(), { skipped: 'never-allowed' });
  assert.equal(t.calls.length, 0, 'no request names this person to the satellite');
  assert.equal(t.loads(), 0, 'and nothing was unlocked for it');
});

test('RM2 a contact that HAD a row (open_visibility on, not blocked, not private) -> Remove sends EXACTLY ONE DELETE for that pair', async () => {
  const t = rm(FULL_INVARIANT);
  assert.deepEqual(await t.run(), { action: 'delete', ok: true });
  assert.equal(t.calls.length, 1);
  assert.equal(t.calls[0].method, 'DELETE');
  assert.ok(t.calls[0].url.endsWith(`/api/satellite/allowed/${ownerFp}/${senderFp}`), t.calls[0].url);
});

test('RM3 the threshold, from both sides: every state with NO row sends nothing, and the nearest state WITH a row sends one DELETE', async () => {
  const noRow = [
    ['trusted but open_visibility off (a private trusted contact)', { trusted: true, openVisibility: false, blocked: false, perContactPrivate: false }],
    ['open_visibility on but BLOCKED (block already deleted the row)', { trusted: true, openVisibility: true, blocked: true, perContactPrivate: false }],
    ['open_visibility on but per-contact PRIVATE', { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true }],
    ['open_visibility on, blocked AND private', { trusted: false, openVisibility: true, blocked: true, perContactPrivate: true }],
  ] as const;
  for (const [name, c] of noRow) {
    const t = rm(c);
    assert.deepEqual(await t.run(), { skipped: 'never-allowed' }, name);
    assert.equal(t.calls.length, 0, `${name}: 0 requests`);
  }
  // one step across the line in each direction still has a row: open_visibility on, NOT trusted (trusted is not a term of the invariant), not blocked, not private
  const t = rm({ trusted: false, openVisibility: true, blocked: false, perContactPrivate: false });
  assert.deepEqual(await t.run(), { action: 'delete', ok: true });
  assert.equal(t.calls.length, 1, 'a contact that is open but not trusted HAD a row: one DELETE');
});

test('RM4 an unknown consent (the record could not be read: null / undefined) is not a reason to name a person to a server: nothing is sent', async () => {
  for (const unknown of [null, undefined]) {
    const t = rm(unknown);
    assert.deepEqual(await t.run(), { skipped: 'never-allowed' });
    assert.equal(t.calls.length, 0);
  }
});

test('RM5 what the hook already did is kept: a dark gate sends nothing, a locked identity skips fail-soft, a non-2xx is ok:false and never throws', async () => {
  const dark = rm(FULL_INVARIANT, { gate: () => false });
  assert.deepEqual(await dark.run(), { skipped: 'dark' });
  assert.equal(dark.calls.length, 0);
  const locked = rm(FULL_INVARIANT, { loadKeyImpl: async () => null as never });
  assert.deepEqual(await locked.run(), { skipped: 'locked' });
  assert.equal(locked.calls.length, 0);
  const bad = reconcileAllowedOnRemove({ ownerFp, senderFp, consentBefore: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: (async () => new Response('{}', { status: 500 })) as unknown as typeof fetch });
  assert.deepEqual(await bad, { action: 'delete', ok: false });
  const noPeer = rm(FULL_INVARIANT, { senderFp: '' });
  assert.deepEqual(await noPeer.run(), { skipped: 'no-peer' });
});
