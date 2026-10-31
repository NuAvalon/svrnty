// src/lib/sync/relay-tiers.test.ts
// Failover T2 phase 2a (Archie #2633): the relay list, the failover walk, and the merged poll summary. Pure.
// Run: npx tsx --test src/lib/sync/relay-tiers.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_RELAYS, depositWithFailover, failoverWorthy, isPrivateHost, mergeRelaySummaries, parseRelayList } from './relay-tiers';
import type { ConsumeSummary } from './consume-mailbox';

const D = 'https://dev.svrnty.is/api/relay';

test('L1 one relay: SVRNTY_RELAY keeps working, the default applies, a trailing slash is trimmed', () => {
  assert.deepEqual(parseRelayList({}, D), [D]);
  assert.deepEqual(parseRelayList({ SVRNTY_RELAY: 'http://10.0.0.5:3000/api/relay/' }, D), ['http://10.0.0.5:3000/api/relay']);
});
test('L2 SVRNTY_RELAYS wins over SVRNTY_RELAY, keeps order, drops duplicates and blanks', () => {
  assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: ' https://a.test/r , http://b.local/r,, https://a.test/r/ ', SVRNTY_RELAY: 'https://x.test/r' }, D), ['https://a.test/r', 'http://b.local/r']);
  assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: '   ', SVRNTY_RELAY: 'https://x.test/r' }, D), ['https://x.test/r'], 'a blank list falls back to the single form');
});
test('L3 NEG: a misconfigured list is LOUD, never silently single-relay', () => {
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: 'https://a.test/r,not a url' }, D), /not a URL/);
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: 'ftp://a.test/r' }, D), /only http\(s\)/);
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: ',,' }, D), /no relay configured/);
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `https://r${i}.test/x`).join(',') }, D), /at most/);
});
test('F0 only a relay problem fails over: 5xx, 429, 408; a refusal of the BLOB does not', () => {
  for (const s of [500, 502, 503, 504, 429, 408]) assert.equal(failoverWorthy(s), true, String(s));
  for (const s of [200, 400, 401, 403, 404, 413, 422]) assert.equal(failoverWorthy(s), false, String(s));
});
const res = (status: number) => ({ ok: status >= 200 && status < 300, status });
function run(statuses: Array<number | Error>) {
  const hits: string[] = [];
  const relays = statuses.map((_, i) => `r${i}`);
  return depositWithFailover(relays, async (r) => {
    hits.push(r);
    const s = statuses[relays.indexOf(r)];
    if (s instanceof Error) throw s;
    return res(s);
  }).then((o) => ({ o, hits }));
}
test('F1 T1 ok => T2 is never contacted', async () => {
  const { o, hits } = await run([200, 200]);
  assert.deepEqual(o, { deposited: true, tier: 0, tried: 1, unconfirmed: false });
  assert.deepEqual(hits, ['r0']);
});
test('F2 T1 429 at-cap => T2 carries it; T1 5xx => T2 carries it and the outcome is flagged UNCONFIRMED (T1 may hold it too)', async () => {
  assert.deepEqual((await run([429, 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: false });
  assert.deepEqual((await run([503, 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: true });
  assert.deepEqual((await run([new Error('ECONNRESET'), 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: true });
});
test('F3 NEG: a 400/413/401 ends the walk at once (the next relay would refuse the same blob)', async () => {
  for (const s of [400, 413, 401, 403]) {
    const { o, hits } = await run([s, 200]);
    assert.deepEqual(o, { deposited: false, tier: null, tried: 1, unconfirmed: false }, String(s));
    assert.deepEqual(hits, ['r0']);
  }
});
test('F4 every relay refused (429 + 429): deposited=false and NOT unconfirmed (definite: nothing stored anywhere)', async () => {
  assert.deepEqual((await run([429, 429])).o, { deposited: false, tier: null, tried: 2, unconfirmed: false });
});
test('F5 NEG: T1 5xx then T2 429 => not deposited but UNCONFIRMED, so the caller must not claim "not sent"', async () => {
  assert.deepEqual((await run([502, 429])).o, { deposited: false, tier: null, tried: 2, unconfirmed: true });
});
test('F6 every relay THREW => the first error is rethrown (same contract as a single-relay send)', async () => {
  const first = new Error('first');
  await assert.rejects(run([first, new Error('second')]), (e) => e === first);
});
test('F7 a throw on T1 and a refusal on T2 is a result, not a throw', async () => {
  assert.deepEqual((await run([new Error('x'), 413])).o, { deposited: false, tier: null, tried: 2, unconfirmed: true });
});

const sum = (over: Partial<ConsumeSummary> = {}): ConsumeSummary => ({
  polled: 2, applied: 1, ignited: 0, notes: 1, delivered: 0, dropped: 1, held: 0, deadLettered: 1, unrecorded: 0,
  lost: { 'not-in-book': 1 }, opened_hybrid: 2, opened_classical: 0, released: 0, acked: 2, ...over,
});
test('M1 summaries add up: counters and the lost map are summed key by key', () => {
  const m = mergeRelaySummaries([{ summary: sum() }, { summary: sum({ polled: 3, lost: { 'not-in-book': 2, expired: 1 } }) }]);
  assert.equal(m.polled, 5);
  assert.equal(m.acked, 4);
  assert.deepEqual(m.lost, { 'not-in-book': 3, expired: 1 });
  assert.deepEqual([m.relays, m.relaysFailed, m.relaysRejected], [2, 0, 0]);
  assert.equal(m.rejected, undefined, 'a clean pass carries no rejected');
});
test('M2 NEG: a refused or failed relay is never hidden by a healthy one', () => {
  const m = mergeRelaySummaries([{ summary: sum() }, { summary: sum({ rejected: 401 }) }, { failed: true }]);
  assert.equal(m.rejected, 401);
  assert.deepEqual([m.relays, m.relaysFailed, m.relaysRejected], [3, 1, 1]);
  assert.equal(m.polled, 4, 'the healthy relays still count');
});

test('H1 NEG (Flint #2650 a): plain http is refused for a public host, so the owner-auth header and the poll never cross the internet in the clear', () => {
  for (const u of ['http://example.com/api/relay', 'http://8.8.8.8/api/relay', 'http://172.32.0.1/api/relay', 'http://172.15.255.255/api/relay', 'http://192.169.0.1/api/relay',
    'http://1.2.3.4.nip.io/api/relay', 'http://0.0.0.0/api/relay', 'http://dev.svrnty.is/api/relay', 'http://[2001:db8::1]/api/relay', 'http://127.0.0.1.evil.com/api/relay']) {
    assert.throws(() => parseRelayList({ SVRNTY_RELAYS: u }, D), /plain http is only for a private host/, u);
    assert.throws(() => parseRelayList({ SVRNTY_RELAY: u }, D), /plain http is only for a private host/, 'single form too: ' + u);
  }
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: 'https://a.test/r,http://example.com/r' }, D), /plain http/, 'one public http entry in a list');
});
test('H2 plain http IS fine on a private network, and https is fine anywhere', () => {
  for (const u of ['http://127.0.0.1:3000/r', 'http://127.9.9.9/r', 'http://localhost:3000/r', 'http://10.1.2.3/r', 'http://172.16.0.1/r', 'http://172.31.255.254/r', 'http://172.20.1.2/r',
    'http://192.168.1.5/r', 'http://169.254.7.7/r', 'http://[::1]:3000/r', 'http://[fe80::1]/r', 'http://[fd00::5]/r', 'http://box.local/r', 'http://relay-camelot:3000/r', 'http://2130706433/r']) {
    assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: u }, D), [u], u);
  }
  assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: 'https://example.com/r' }, D), ['https://example.com/r']);
});
test('H3 isPrivateHost edges', () => {
  assert.equal(isPrivateHost(''), false);
  assert.equal(isPrivateHost('a.b'), false);
  assert.equal(isPrivateHost('LOCALHOST'), true);
  assert.equal(isPrivateHost('::'), false, 'the unspecified address is not a private peer');
});
