// Run: npx tsx --test src/lib/headless/join-grow-link.test.ts
// `devin-comm join` hardening: Flint join_expect_fp_spec_v1 J1-J6 + "admit only after deposit:ok" (task:698 #1236). Every rule has a test that FAILS
// when the rule is removed (see the mutation list in the commit message). The last two tests use the REAL primitives (a real minted identity, the real
// fingerprint-derivation check, the real deposit builder): they reproduce the production failure (`encrypt-failed`) and show the fix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GROW_FRAGMENT_CHARS, parseJoinFlags, runJoin, type JoinDeps, type JoinResult } from './join-grow-link';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { fingerprintMatchesKey } from '../identity/fingerprint';
import { buildJoinerResponseDeposit } from '../sync/send-joiner-response';

const FP = 'bf4b93d94408cb9a87ec91c7e30e772173e61621248c737f537b78f368e1e2a3';
const FRAG = 'a'.repeat(GROW_FRAGMENT_CHARS);
const URL_OK = `https://dev.svrnty.is/c/b3gW9g#${FRAG}`;
const CARD = { identity: { fingerprint: FP, public_key: '-----PUBKEY-----', pq_kem_public_key: 'KEMKEY', pq_sig_public_key: 'SIGKEY', display_name: 'totally-legit-name' } };

interface Calls { order: string[]; resolves: Array<[string, string]>; derives: unknown[][]; deposits: Array<Record<string, unknown>>; admits: Array<Record<string, unknown>>; backups: number }
function fakeDeps(over: Partial<JoinDeps> = {}, card: unknown = CARD): { deps: JoinDeps; calls: Calls } {
  const calls: Calls = { order: [], resolves: [], derives: [], deposits: [], admits: [], backups: 0 };
  const deps: JoinDeps = {
    backup: () => { calls.order.push('backup'); calls.backups++; },
    resolve: async (c, f) => { calls.order.push('resolve'); calls.resolves.push([c, f]); return typeof card === 'string' ? card : JSON.stringify(card); },
    derives: async (...a) => { calls.order.push('derives'); calls.derives.push(a); return true; },
    deposit: async (t) => { calls.order.push('deposit'); calls.deposits.push(t); return { ok: true, status: 200 }; },
    admit: (c) => { calls.order.push('admit'); calls.admits.push(c); },
    ...over,
  };
  return { deps, calls };
}
const nothingHappened = (c: Calls) => assert.deepEqual([c.backups, c.resolves.length, c.deposits.length, c.admits.length], [0, 0, 0, 0], `side effects: ${c.order.join(',')}`);
const good = { url: URL_OK, expectFp: FP, name: 'topos' };
const refusal = (r: JoinResult) => (r.ok ? 'OK' : r.refusal);

test('happy path: order is backup, resolve, derives, deposit, ADMIT; the name is --name (never the card\'s display_name); the deposit carries the giver\'s KEM key', async () => {
  const { deps, calls } = fakeDeps();
  const r = await runJoin(good, deps);
  assert.deepEqual(r, { ok: true, admitted: FP, fp8: 'bf4b93d9', name: 'topos', joinerResponse: { ok: true, status: 200 } });
  assert.deepEqual(calls.order, ['backup', 'resolve', 'derives', 'deposit', 'admit']);
  assert.deepEqual(calls.resolves, [['b3gW9g', FRAG]]);
  assert.deepEqual(calls.deposits[0], { fingerprint: FP, publicKeyArmored: '-----PUBKEY-----', giverPqKemPublicKey: 'KEMKEY', inviteNonce: 'b3gW9g' });
  assert.equal(calls.admits[0].name, 'topos', 'J3: the petname comes from us');
  assert.notEqual(calls.admits[0].name, CARD.identity.display_name);
  assert.equal(calls.admits[0].trust_level, 'known');
  assert.equal(calls.admits.length, 1);
});

test('J1: --expect-fp is REQUIRED; without a usable one join refuses with ZERO side effects (no backup, no GET, no deposit, no admit)', async () => {
  for (const [expectFp, want] of [[undefined, 'missing-expect-fp'], ['', 'missing-expect-fp'], [FP.slice(0, 63), 'bad-expect-fp'], [FP + 'a', 'bad-expect-fp'],
    ['z'.repeat(64), 'bad-expect-fp'], [FP.slice(0, 40), 'bad-expect-fp'], [FP.slice(0, 16), 'bad-expect-fp']] as const) {
    const { deps, calls } = fakeDeps();
    assert.equal(refusal(await runJoin({ ...good, expectFp }, deps)), want, String(expectFp));
    nothingHappened(calls);
  }
});

test('J1: an UPPERCASE --expect-fp is accepted and compared lowercased on both sides (Flint #1236)', async () => {
  const { deps } = fakeDeps(undefined, { identity: { ...CARD.identity, fingerprint: FP.toUpperCase() } });
  const r = await runJoin({ ...good, expectFp: FP.toUpperCase() }, deps);
  assert.equal(refusal(r), 'OK');
  assert.ok(r.ok && r.admitted === FP, 'stored lowercase');
});

test('J3: --name is REQUIRED and must be [a-z0-9-]{1,24}; refusals have zero side effects', async () => {
  for (const [name, want] of [[undefined, 'missing-name'], ['', 'missing-name'], ['Topos', 'bad-name'], ['a_b', 'bad-name'], ['a b', 'bad-name'],
    ['x'.repeat(25), 'bad-name'], ['../etc', 'bad-name'], ['é', 'bad-name']] as const) {
    const { deps, calls } = fakeDeps();
    assert.equal(refusal(await runJoin({ ...good, name }, deps)), want, String(name));
    nothingHappened(calls);
  }
  assert.equal(refusal(await runJoin({ ...good, name: 'x'.repeat(24) }, fakeDeps().deps)), 'OK', '24 chars is the maximum allowed');
});

test('J4: a malformed URL or a short/long/odd fragment (the LINE-WRAP case) refuses BEFORE any GET and before the backup', async () => {
  const cases: Array<[string, string]> = [
    ['not a url', 'bad-url'], ['https://dev.svrnty.is/x/b3gW9g#' + FRAG, 'bad-url'], ['https://dev.svrnty.is/c/#' + FRAG, 'bad-url'], ['https://dev.svrnty.is/c/a b#' + FRAG, 'bad-url'],
    ['https://dev.svrnty.is/c/b3gW9g', 'bad-fragment'], ['https://dev.svrnty.is/c/b3gW9g#', 'bad-fragment'],
    ['https://dev.svrnty.is/c/b3gW9g#' + 'a'.repeat(34), 'bad-fragment'], // exactly Peter's wrapped link: first line only
    ['https://dev.svrnty.is/c/b3gW9g#' + 'a'.repeat(42), 'bad-fragment'], ['https://dev.svrnty.is/c/b3gW9g#' + 'a'.repeat(44), 'bad-fragment'],
    ['https://dev.svrnty.is/c/b3gW9g#' + 'a'.repeat(42) + '+', 'bad-fragment'], ['https://dev.svrnty.is/c/b3gW9g#' + 'a'.repeat(42) + '=', 'bad-fragment'],
  ];
  for (const [url, want] of cases) {
    const { deps, calls } = fakeDeps();
    assert.equal(refusal(await runJoin({ ...good, url }, deps)), want, url);
    nothingHappened(calls);
  }
  assert.equal(refusal(await runJoin({ ...good, url: undefined }, fakeDeps().deps)), 'bad-url');
});

test('J5: the backup happens once, BEFORE the GET; if the backup fails nothing else happens', async () => {
  const { deps, calls } = fakeDeps();
  await runJoin(good, deps);
  assert.equal(calls.backups, 1);
  assert.ok(calls.order.indexOf('backup') < calls.order.indexOf('resolve'));
  const bad = fakeDeps({ backup: () => { throw new Error('disk full'); } });
  assert.equal(refusal(await runJoin(good, bad.deps)), 'backup-failed');
  assert.deepEqual([bad.calls.resolves.length, bad.calls.deposits.length, bad.calls.admits.length], [0, 0, 0]);
});

test('J2: a link that resolves to a DIFFERENT fingerprint (one hex digit off) is refused: nothing deposited, nothing admitted', async () => {
  const off = FP.slice(0, 63) + (FP.endsWith('0') ? '1' : '0');
  const { deps, calls } = fakeDeps(undefined, { identity: { ...CARD.identity, fingerprint: off } });
  assert.equal(refusal(await runJoin(good, deps)), 'fp-mismatch');
  assert.deepEqual([calls.deposits.length, calls.admits.length], [0, 0]);
});

test('J2: a card whose fingerprint does NOT derive from the keys it presents is refused: nothing deposited, nothing admitted', async () => {
  const { deps, calls } = fakeDeps({ derives: async () => false });
  assert.equal(refusal(await runJoin(good, deps)), 'fp-not-derived');
  assert.deepEqual([calls.deposits.length, calls.admits.length], [0, 0]);
});

test('the derive check is given exactly the card\'s fp, armored key and BOTH PQ keys', async () => {
  const { deps, calls } = fakeDeps();
  await runJoin(good, deps);
  assert.deepEqual(calls.derives[0], [FP, '-----PUBKEY-----', { kem_public_key: 'KEMKEY', sig_public_key: 'SIGKEY' }]);
});

test('a card with no KEM key can never reach the deposit (no-kem-key), even if the derive check were fooled', async () => {
  const { deps, calls } = fakeDeps(undefined, { identity: { fingerprint: FP, public_key: 'K', pq_sig_public_key: 'S' } });
  assert.equal(refusal(await runJoin(good, deps)), 'no-kem-key');
  assert.deepEqual([calls.deposits.length, calls.admits.length], [0, 0]);
});

test('malformed or unreadable cards are refused: bad JSON, missing fingerprint, missing public key, a throwing resolve', async () => {
  for (const card of ['{not json', JSON.stringify({ identity: { public_key: 'K' } }), JSON.stringify({ identity: { fingerprint: FP } }), JSON.stringify([])]) {
    const { deps, calls } = fakeDeps(undefined, card);
    assert.equal(refusal(await runJoin(good, deps)), 'bad-card', card);
    assert.deepEqual([calls.deposits.length, calls.admits.length], [0, 0]);
  }
  const t = fakeDeps({ resolve: async () => { throw new Error('404 expired'); } });
  assert.equal(refusal(await runJoin(good, t.deps)), 'resolve-failed');
  assert.deepEqual([t.calls.deposits.length, t.calls.admits.length], [0, 0]);
});

test('the top-level card form (durable_id, no identity wrapper) is accepted, as stock join accepted it', async () => {
  const { deps } = fakeDeps(undefined, { durable_id: FP, public_key: 'K', pq_kem_public_key: 'KEM', pq_sig_public_key: 'SIG' });
  const r = await runJoin(good, deps);
  assert.equal(refusal(r), 'OK');
});

test('NO HALF-STATE: a failed or throwing deposit refuses with deposit-failed and the giver is NOT admitted', async () => {
  for (const dep of [async () => ({ ok: false, status: 'encrypt-failed' }), async () => ({ ok: false, status: 500 }), async () => { throw new Error('network'); },
    async () => undefined as never, async () => ({ ok: 'yes' } as never)]) {
    const { deps, calls } = fakeDeps({ deposit: dep });
    const r = await runJoin(good, deps);
    assert.equal(refusal(r), 'deposit-failed');
    assert.equal(calls.admits.length, 0, 'the old join admitted BEFORE the deposit and left a trusted contact whose response never went out');
  }
});

test('LIVENESS (Flint #1304): if admit THROWS after a successful deposit the result is admit-failed-after-deposit (not deposit-failed), the deposit is NOT retried, and the unadmitted contact is handed back', async () => {
  const { deps, calls } = fakeDeps({ admit: (c) => { calls.order.push('admit'); calls.admits.push(c); throw new Error('store lock wait 120s'); } });
  const r = await runJoin(good, deps);
  assert.equal(refusal(r), 'admit-failed-after-deposit');
  assert.equal(calls.deposits.length, 1, 'the response is already sent; a second deposit would count against the link cap');
  assert.deepEqual(calls.order.filter((x) => x === 'deposit' || x === 'admit'), ['deposit', 'admit']);
  if (r.ok) throw new Error('unreachable');
  assert.match(r.detail ?? '', /store lock wait/);
  assert.deepEqual(r.pending, calls.admits[0], 'pending is exactly the contact that failed to be admitted: --name as the name, the card keys, trust known');
  assert.equal(r.pending?.name, 'topos');
  assert.equal(r.pending?.fingerprint, FP);
});

test('LIVENESS control: only deposit-failed and admit-failed-after-deposit carry different meanings (a failed deposit has NO pending contact)', async () => {
  const { deps } = fakeDeps({ deposit: async () => ({ ok: false, status: 500 }) });
  const r = await runJoin(good, deps);
  assert.equal(refusal(r), 'deposit-failed');
  if (r.ok) throw new Error('unreachable');
  assert.equal(r.pending, undefined);
});

test('parseJoinFlags: flags in any position, the URL is the first non-flag token, a flag with no value is undefined', () => {
  assert.deepEqual(parseJoinFlags([URL_OK, '--expect-fp', FP, '--name', 'topos']), { url: URL_OK, expectFp: FP, name: 'topos' });
  assert.deepEqual(parseJoinFlags(['--name', 'topos', '--expect-fp', FP, URL_OK]), { url: URL_OK, expectFp: FP, name: 'topos' });
  assert.deepEqual(parseJoinFlags([URL_OK, '--expect-fp']), { url: URL_OK, expectFp: undefined, name: undefined });
  assert.deepEqual(parseJoinFlags([URL_OK, '--expect-fp', '--name', 'x']), { url: URL_OK, expectFp: undefined, name: 'x' });
  assert.deepEqual(parseJoinFlags([]), { url: undefined, expectFp: undefined, name: undefined });
});

// ─────────────────────── REAL primitives: reproduce the production failure, then the fix ───────────────────────

async function realParties() {
  const giver = await mintHeadlessAgent();
  const joiner = await mintHeadlessAgent();
  const gid = giver.introduction.card.identity as unknown as Record<string, string>;
  const jid = joiner.introduction.card.identity as unknown as Record<string, string>;
  const sender = {
    fingerprint: joiner.introduction.durableId, epoch: 0, publicKeyArmored: jid.public_key, displayName: 'joiner',
    privateKeyArmored: joiner.secret_material.classicalPrivateKey, passphrase: joiner.secret_material.classicalKpass,
    kemPublicKeyB64: jid.pq_kem_public_key, sigPublicKeyB64: jid.pq_sig_public_key,
  };
  return { giverFp: giver.introduction.durableId, gid, sender };
}

test('REAL: the fixed join delivers a deposit to a real PQ card, and the real derive check accepts it', async () => {
  const { giverFp, gid, sender } = await realParties();
  const admits: unknown[] = [];
  const deps: JoinDeps = {
    backup: () => {},
    resolve: async () => JSON.stringify({ identity: { ...gid, fingerprint: giverFp } }),
    derives: (fp, pk, pq) => fingerprintMatchesKey(fp, pk, pq),
    deposit: async (target) => { const d = await buildJoinerResponseDeposit(sender, target); return { ok: d !== null, status: d ? 200 : 'encrypt-failed' }; },
    admit: (c) => { admits.push(c); },
  };
  const r = await runJoin({ url: URL_OK, expectFp: giverFp, name: 'giver' }, deps);
  assert.equal(refusal(r), 'OK');
  assert.equal(admits.length, 1);
});

test('REAL, the PRODUCTION BUG: a join whose target OMITS the giver\'s KEM key (what dev 374d31e did) gets encrypt-failed, and the new flow admits NOBODY', async () => {
  const { giverFp, gid, sender } = await realParties();
  const admits: unknown[] = [];
  const deps: JoinDeps = {
    backup: () => {},
    resolve: async () => JSON.stringify({ identity: { ...gid, fingerprint: giverFp } }),
    derives: (fp, pk, pq) => fingerprintMatchesKey(fp, pk, pq),
    // the OLD call shape: no giverPqKemPublicKey in the target
    deposit: async (target) => { const old = { ...target } as Partial<typeof target>; delete old.giverPqKemPublicKey; const d = await buildJoinerResponseDeposit(sender, old as never); return { ok: d !== null, status: d ? 200 : 'encrypt-failed' }; },
    admit: (c) => { admits.push(c); },
  };
  const r = await runJoin({ url: URL_OK, expectFp: giverFp, name: 'giver' }, deps);
  assert.equal(refusal(r), 'deposit-failed');
  assert.ok(!r.ok && r.detail === 'encrypt-failed');
  assert.equal(admits.length, 0);
});

test('REAL: a swapped card (valid keys, but not the fingerprint Peter read) is refused before anything is sent', async () => {
  const a = await realParties();
  const b = await realParties();
  let deposited = 0; const admits: unknown[] = [];
  const deps: JoinDeps = {
    backup: () => {},
    resolve: async () => JSON.stringify({ identity: { ...b.gid, fingerprint: b.giverFp } }), // the link resolves to B
    derives: (fp, pk, pq) => fingerprintMatchesKey(fp, pk, pq),
    deposit: async () => { deposited++; return { ok: true, status: 200 }; },
    admit: (c) => { admits.push(c); },
  };
  const r = await runJoin({ url: URL_OK, expectFp: a.giverFp, name: 'giver' }, deps); // Peter read A's fingerprint
  assert.equal(refusal(r), 'fp-mismatch');
  assert.deepEqual([deposited, admits.length], [0, 0]);
});
