// reconcile-allowed-hook — FE integration hook for #572 part 2 (gate -> seed -> reconcile, fail-soft).
// Run: npx tsx --test src/lib/sync/reconcile-allowed-hook.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, decryptKey, readPrivateKey } from 'openpgp';
import { reconcileAllowedOnConsentChange, reconcileAllowedOnRemove, runAllowedRevokeTick } from './reconcile-allowed-hook';
import { resetRevokeState, type AllowedRevokeDeps } from './allowed-revoke';
import type { PeerConsent } from './allowed-sync';

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

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

/** A fake relay that KEEPS A LIST: GET lists it, POST adds the sender, a 2xx DELETE removes it. Every request is recorded. */
function relayFetch(opts: { list?: string[]; getStatus?: number; deleteStatus?: number; postStatus?: number } = {}) {
  const relay = new Set(opts.list ?? []);
  const calls: Array<{ url: string; method: string }> = [];
  const fetchImpl = (async (url: unknown, init?: { method?: string; body?: string }) => {
    const method = init?.method ?? 'GET';
    calls.push({ url: String(url), method });
    if (method === 'GET') return (opts.getStatus ?? 200) === 200 ? json(200, { owner_fingerprint: ownerFp, allowed: [...relay], count: relay.size }) : json(opts.getStatus!, {});
    if (method === 'POST') { const st = opts.postStatus ?? 200; if (st === 200) relay.add(JSON.parse(init!.body!).sender_fingerprint); return json(st, {}); }
    const st = opts.deleteStatus ?? 200; if (st === 200) relay.delete(String(url).split('/').pop()!);
    return json(st, {});
  }) as unknown as typeof fetch;
  return { relay, calls, fetchImpl, count: (m: string) => calls.filter((c) => c.method === m).length };
}

const FULL_INVARIANT = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };
const BLOCKED = { ...FULL_INVARIANT, blocked: true };
const OTHER = 'ef'.repeat(32);

/** The owner's book as the drain reads it (a contact that is not in it is gone), with no pause between DELETEs. */
const book = (consents: Record<string, PeerConsent> = {}, extra: Partial<AllowedRevokeDeps> = {}): AllowedRevokeDeps => ({ consents: async () => new Map(Object.entries(consents)), sleep: async () => {}, delay: async () => {}, log: () => {}, ...extra });
const common = () => { resetRevokeState(); };

test('GATE dark (isPSIDiscoveryLive=false): skips entirely — no loadKey, no fetch', async () => {
  common(); const { calls, fetchImpl } = relayFetch(); let loadKeyCalled = false;
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book(), consent: FULL_INVARIANT, gate: () => false, loadKeyImpl: (async () => { loadKeyCalled = true; return { privateKey, passphrase }; }) as never, fetchImpl });
  assert.deepEqual(res, { skipped: 'dark' });
  assert.equal(loadKeyCalled, false, 'must not touch the identity when gated dark');
  assert.equal(calls.length, 0, 'must issue no /allowed traffic when gated dark');
});

test('no peer fingerprint: skips (not a svrnty-network peer) — no fetch', async () => {
  common(); const { calls, fetchImpl } = relayFetch();
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp: '', allowedRevoke: book(), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl });
  assert.deepEqual(res, { skipped: 'no-peer' });
  assert.equal(calls.length, 0);
});

test('identity LOCKED (loadKey → null): skips fail-soft — no fetch, no throw', async () => {
  common(); const { calls, fetchImpl } = relayFetch();
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book(), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: (async () => null) as never, fetchImpl });
  assert.deepEqual(res, { skipped: 'locked' });
  assert.equal(calls.length, 0);
});

test('full invariant (trusted ∩ open_vis ∩ !blocked) + unlocked → ADD (POST /allowed/{owner}), then ONE GET to pay down anything else that is owed', async () => {
  common(); const { calls, fetchImpl, count } = relayFetch();
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: FULL_INVARIANT }), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl });
  assert.deepEqual(res, { action: 'add', ok: true });
  assert.equal(calls[0].method, 'POST');
  assert.ok(calls[0].url.endsWith(`/api/satellite/allowed/${ownerFp}`), calls[0].url);
  assert.equal(count('POST'), 1); assert.equal(count('GET'), 1); assert.equal(count('DELETE'), 0);
});

// piece-1 (Flint seal #158892): KNOWN-reveal exits = go-private, block, per_contact_private (new). UNTRUST is NO LONGER a known-exit (trusted dropped to the trust layer, piece-2).
const EXITS = [
  { name: 'go-private', consent: { trusted: true, openVisibility: false, blocked: false, perContactPrivate: false } },
  { name: 'block', consent: { trusted: false, openVisibility: false, blocked: true, perContactPrivate: false } },
  { name: 'per_contact_private', consent: { trusted: true, openVisibility: true, blocked: false, perContactPrivate: true } },
];

test('each invariant EXIT → exactly one DELETE (/allowed/{owner}/{sender}) for a peer the relay LISTS — the #111 satellite revoke', async () => {
  for (const { name, consent } of EXITS) {
    common(); const { calls, fetchImpl, relay, count } = relayFetch({ list: [senderFp] });
    const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: consent }), consent, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl });
    assert.deepEqual(res, { action: 'delete', ok: true }, `exit=${name}`);
    assert.equal(count('GET'), 1, `exit=${name}: one GET`); assert.equal(count('DELETE'), 1, `exit=${name}`);
    assert.ok(calls.find((c) => c.method === 'DELETE')!.url.endsWith(`/api/satellite/allowed/${ownerFp}/${senderFp}`));
    assert.equal(relay.size, 0);
  }
});

test('an exit for a peer the relay does NOT list sends NOTHING: a person who never had a row is never named (one GET, 0 DELETEs)', async () => {
  for (const { name, consent } of EXITS) {
    common(); const { fetchImpl, count } = relayFetch({ list: [OTHER].filter(() => false) });
    const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: consent }), consent, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl });
    assert.deepEqual(res, { skipped: 'never-allowed' }, name);
    assert.equal(count('GET'), 1); assert.equal(count('DELETE'), 0); assert.equal(count('POST'), 0);
  }
});

test('FAIL-SOFT: a decrypt/extract failure returns skipped:error, never throws', async () => {
  common();
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book(), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: (async () => ({ privateKey: 'not-a-real-armored-key', passphrase })) as never });
  assert.deepEqual(res, { skipped: 'error' });
});

test('FAIL-SOFT: satellite non-2xx → the ADD returns ok:false, a refused DELETE returns ok:false and stays owed (the handler is still fine)', async () => {
  common();
  const add = relayFetch({ postStatus: 500 });
  assert.deepEqual(await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: FULL_INVARIANT }), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: add.fetchImpl }), { action: 'add', ok: false });
  common();
  const del = relayFetch({ list: [senderFp], deleteStatus: 500 });
  assert.deepEqual(await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: BLOCKED }), consent: BLOCKED, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: del.fetchImpl }), { action: 'delete', ok: false });
  assert.deepEqual([...del.relay], [senderFp], 'the relay still lists it, so it is still owed');
});

// ---- #941 + #959: Remove of a contact that never had a satellite row sends the satellite nothing ----
// The relay's own list says whether a row exists, so a Remove sends a DELETE only for a contact the relay lists.
const rm = (opts: Parameters<typeof relayFetch>[0] = {}, extra: Partial<Parameters<typeof reconcileAllowedOnRemove>[0]> = {}) => {
  common();
  const relay = relayFetch(opts);
  const run = () => reconcileAllowedOnRemove({ ownerFp, senderFp, allowedRevoke: book(), gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl, ...extra });
  return { ...relay, run };
};

test('RM1 a contact the relay does NOT list (never added) -> Remove sends NO DELETE: one GET of the owner\'s own list names no contact, and nothing else', async () => {
  const t = rm({ list: [] });
  assert.deepEqual(await t.run(), { skipped: 'never-allowed' });
  assert.equal(t.count('DELETE'), 0); assert.equal(t.count('POST'), 0);
  assert.equal(t.count('GET'), 1);
  assert.ok(!t.calls.some((c) => c.url.includes(senderFp)), 'no request names this person');
});

test('RM2 a contact the relay LISTS -> Remove sends EXACTLY ONE DELETE for that pair, and the relay then lists nothing', async () => {
  const t = rm({ list: [senderFp] });
  assert.deepEqual(await t.run(), { action: 'delete', ok: true });
  assert.equal(t.count('DELETE'), 1);
  assert.ok(t.calls.find((c) => c.method === 'DELETE')!.url.endsWith(`/api/satellite/allowed/${ownerFp}/${senderFp}`));
  assert.equal(t.relay.size, 0);
});

test('RM3 other peers the relay lists do not make THIS one revocable, but they ARE paid down by the same call (a row left by an earlier failed DELETE goes now)', async () => {
  const t = rm({ list: [OTHER] });                                   // the relay lists only OTHER, which the book no longer has
  assert.deepEqual(await t.run(), { skipped: 'never-allowed' }, 'this peer is not listed');
  assert.deepEqual(t.calls.filter((c) => c.method === 'DELETE').map((c) => c.url.split('/').pop()), [OTHER], 'but the stale row for OTHER was revoked');
});

test('RM4 NEG: a GET that FAILS (403, 500) is UNKNOWN: 0 DELETEs, skipped:error, and the next call (the relay answering again) sends it; a 410 stops the session with no further GETs', async () => {
  for (const st of [403, 500]) {
    const t = rm({ list: [senderFp], getStatus: st });
    assert.deepEqual(await t.run(), { skipped: 'error' }, `GET ${st}`);
    assert.equal(t.count('DELETE'), 0, `GET ${st}: nothing revoked`);
    assert.deepEqual([...t.relay], [senderFp], 'and nothing was declared done');
  }
  const gone = rm({ list: [senderFp], getStatus: 410 });
  assert.deepEqual(await gone.run(), { skipped: 'error' });
  await gone.run(); await gone.run();
  assert.equal(gone.count('GET'), 1, 'after a 410 no further GETs this session');
  assert.equal(gone.count('DELETE'), 0);
});

test('RM5 what the hook already did is kept: a dark gate sends nothing, a locked identity skips fail-soft, no peer skips', async () => {
  const dark = rm({ list: [senderFp] }, { gate: () => false });
  assert.deepEqual(await dark.run(), { skipped: 'dark' });
  assert.equal(dark.calls.length, 0);
  const locked = rm({ list: [senderFp] }, { loadKeyImpl: async () => null as never });
  assert.deepEqual(await locked.run(), { skipped: 'locked' });
  assert.equal(locked.calls.length, 0);
  const noPeer = rm({ list: [senderFp] }, { senderFp: '' });
  assert.deepEqual(await noPeer.run(), { skipped: 'no-peer' });
});

// ---- #959: what a call pays down, and what it owes next ----
test('ARH1 a DELETE the relay REFUSES stays owed: the next call inside the retry window sends nothing more and says so (ok:false); the relay still lists it', async () => {
  common();
  const relay = relayFetch({ list: [senderFp], deleteStatus: 500 });
  const run = () => reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [senderFp]: BLOCKED }), consent: BLOCKED, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl });
  assert.deepEqual(await run(), { action: 'delete', ok: false });
  assert.deepEqual(await run(), { action: 'delete', ok: false });
  assert.equal(relay.count('DELETE'), 1, 'the second call was inside the window');
  assert.deepEqual([...relay.relay], [senderFp]);
});

test('ARH2 EVERY call pays down what is owed to OTHER peers: an ADD for one peer also revokes another the relay lists and the book no longer allows, and does NOT revoke the peer it just added', async () => {
  common();
  const relay = relayFetch({ list: [OTHER] });
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book({ [OTHER]: BLOCKED }), consent: FULL_INVARIANT, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl });
  assert.deepEqual(res, { action: 'add', ok: true });
  assert.deepEqual(relay.calls.filter((c) => c.method === 'DELETE').map((c) => c.url.split('/').pop()), [OTHER]);
  assert.ok(relay.relay.has(senderFp), 'the peer this call added is still listed: its own consent is authoritative over a book that does not have it yet');
});

// ---- #959: the know-layer tick's share ----
const tick = (opts: Parameters<typeof relayFetch>[0], deps: AllowedRevokeDeps, extra: Partial<Parameters<typeof runAllowedRevokeTick>[1]> = {}) => {
  common();
  const relay = relayFetch(opts);
  return { relay, run: () => runAllowedRevokeTick(ownerFp, { allowedRevoke: deps, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl, ...extra }) };
};

test('ARH3 the tick revokes every row the relay lists and the book no longer allows (a blocked contact with a local record, a contact the book does not have at all) and leaves an allowed one', async () => {
  const t = tick({ list: [senderFp, OTHER, 'aa'.repeat(32)] }, book({ [senderFp]: BLOCKED, ['aa'.repeat(32)]: FULL_INVARIANT }));
  await t.run();
  assert.deepEqual(t.relay.calls.filter((c) => c.method === 'DELETE').map((c) => c.url.split('/').pop()).sort(), [OTHER, senderFp].sort());
  assert.deepEqual([...t.relay.relay], ['aa'.repeat(32)], 'only the allowed contact is left');
});

test('ARH4 a tick with NOTHING owed makes one GET and no DELETE; a dark gate does nothing at all; a locked identity sends nothing; a GET failure changes nothing; and it never throws', async () => {
  const quiet = tick({ list: [senderFp] }, book({ [senderFp]: FULL_INVARIANT }));
  await quiet.run();
  assert.equal(quiet.relay.count('GET'), 1); assert.equal(quiet.relay.count('DELETE'), 0);
  const dark = tick({ list: [OTHER] }, book(), { gate: () => false });
  await dark.run(); assert.equal(dark.relay.calls.length, 0);
  const locked = tick({ list: [OTHER] }, book(), { loadKeyImpl: async () => null as never });
  await locked.run(); assert.equal(locked.relay.calls.length, 0);
  const failing = tick({ list: [OTHER], getStatus: 500 }, book());
  await failing.run(); assert.equal(failing.relay.count('DELETE'), 0); assert.deepEqual([...failing.relay.relay], [OTHER]);
  const unreadable = tick({ list: [OTHER] }, { consents: async () => { throw new Error('unreadable'); }, sleep: async () => {}, delay: async () => {}, log: () => {} });
  await unreadable.run(); assert.equal(unreadable.relay.count('DELETE'), 0, 'a book that cannot be read sends nothing blind');
});

test('ARH7 BURST (Flint): 10 hook calls in one tick make ONE GET, and each call still gets ITS OWN peer\'s outcome', async () => {
  common();
  const peers = Array.from({ length: 10 }, (_, i) => `${i}`.padStart(2, '0').repeat(32));
  const relay = relayFetch({ list: peers });
  const deps = book({}, { delay: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 5))) });
  const out = await Promise.all(peers.map((fp) => reconcileAllowedOnConsentChange({ ownerFp, senderFp: fp, allowedRevoke: deps, consent: BLOCKED, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl })));
  assert.equal(relay.count('GET'), 1, 'ONE GET for ten hook calls');
  assert.equal(relay.count('DELETE'), 10, 'every owed row revoked once');
  for (const o of out) assert.deepEqual(o, { action: 'delete', ok: true });
});

test('ARH8 the peer\'s outcome is found whatever the case of its fingerprint: an upper-case fingerprint in the book, listed in lower case, is revoked and reported as deleted', async () => {
  common();
  const relay = relayFetch({ list: [senderFp] });
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp: senderFp.toUpperCase(), allowedRevoke: book(), consent: BLOCKED, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl });
  assert.deepEqual(res, { action: 'delete', ok: true });
  assert.equal(relay.count('DELETE'), 1);
});

test('ARH9 a peer that falls beyond the drain\'s cap is reported as owed (ok:false), not as "never allowed": it is still listed and goes out on the next drain', async () => {
  common();
  const others = Array.from({ length: 25 }, (_, i) => i.toString(16).padStart(64, '0'));
  const relay = relayFetch({ list: [...others, senderFp] });            // the peer is listed LAST, so it falls past the cap of 25
  const res = await reconcileAllowedOnConsentChange({ ownerFp, senderFp, allowedRevoke: book(), consent: BLOCKED, gate: () => true, loadKeyImpl: loadKeyOk, fetchImpl: relay.fetchImpl });
  assert.deepEqual(res, { action: 'delete', ok: false });
  assert.equal(relay.count('DELETE'), 25);
  assert.ok(relay.relay.has(senderFp), 'still listed, so still owed');
});
