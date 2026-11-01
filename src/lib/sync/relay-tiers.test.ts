// src/lib/sync/relay-tiers.test.ts
// Failover T2 phase 2a (Archie #2633): the relay list, the failover walk, and the merged poll summary. Pure.
// Run: npx tsx --test src/lib/sync/relay-tiers.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_RELAYS, depositWithFailover, failoverWorthy, isPrivateHost, mergeRelaySummaries, parseRelayList, relayBudgetShare, relayLabel, unconfirmedReason } from './relay-tiers';
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
  assert.deepEqual(o, { deposited: true, tier: 0, tried: 1, unconfirmed: false, status: 200 });
  assert.deepEqual(hits, ['r0']);
});
test('F2 T1 429 at-cap => T2 carries it; T1 5xx => T2 carries it and the outcome is flagged UNCONFIRMED (T1 may hold it too)', async () => {
  assert.deepEqual((await run([429, 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: false, status: 200 });
  assert.deepEqual((await run([503, 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: true, status: 200, unconfirmedBy: [{ relay: '#1', status: 503 }] });
  assert.deepEqual((await run([new Error('ECONNRESET'), 200])).o, { deposited: true, tier: 1, tried: 2, unconfirmed: true, status: 200, unconfirmedBy: [{ relay: '#1' }] });
});
test('F3 NEG: a 400/413/401 ends the walk at once (the next relay would refuse the same blob)', async () => {
  for (const s of [400, 413, 401, 403]) {
    const { o, hits } = await run([s, 200]);
    assert.deepEqual(o, { deposited: false, tier: null, tried: 1, unconfirmed: false, status: s }, String(s));
    assert.deepEqual(hits, ['r0']);
  }
});
test('F4 every relay refused (429 + 429): deposited=false and NOT unconfirmed (definite: nothing stored anywhere)', async () => {
  assert.deepEqual((await run([429, 429])).o, { deposited: false, tier: null, tried: 2, unconfirmed: false, status: 429 });
});
test('F5 NEG: T1 5xx then T2 429 => not deposited but UNCONFIRMED, so the caller must not claim "not sent"', async () => {
  assert.deepEqual((await run([502, 429])).o, { deposited: false, tier: null, tried: 2, unconfirmed: true, status: 429, unconfirmedBy: [{ relay: '#1', status: 502 }] });
});
test('F6 every relay THREW => the first error is rethrown (same contract as a single-relay send)', async () => {
  const first = new Error('first');
  await assert.rejects(run([first, new Error('second')]), (e) => e === first);
});
test('F7 a throw on T1 and a refusal on T2 is a result, not a throw', async () => {
  assert.deepEqual((await run([new Error('x'), 413])).o, { deposited: false, tier: null, tried: 2, unconfirmed: true, status: 413, unconfirmedBy: [{ relay: '#1' }] });
});
test('F8 NEG: a 408 is failover-worthy AND unconfirmed, like a 5xx (the relay may have read the request before it timed out): never a definite refusal', async () => {
  assert.deepEqual((await run([408, 408])).o, { deposited: false, tier: null, tried: 2, unconfirmed: true, status: 408, unconfirmedBy: [{ relay: '#1', status: 408 }, { relay: '#2', status: 408 }] });
  assert.equal((await run([408, 200])).o.unconfirmed, true, 'a 408 then a success elsewhere may store the note twice, by design: flagged');
  assert.equal((await run([429, 429])).o.unconfirmed, false, 'a 429 stays a definite refusal');
});
test('F9 the outcome carries the status of the LAST relay that answered; none when no request was made', async () => {
  assert.equal((await run([503, 429])).o.status, 429);
  assert.equal((await run([new Error('x'), 503])).o.status, 503);
  assert.equal((await run([503, new Error('x')])).o.status, 503, 'a later throw does not erase the status of the last relay that answered');
  assert.equal('status' in (await run([new Error('x'), 413])).o, true);
  assert.equal('status' in (await depositWithFailover([], async () => res(200))), false, 'an empty list posts nothing, so no status');
});
test('U1 relayLabel names a relay by HOST (and port) only: never a path, query, fragment or credentials; "#N" when it is not an absolute URL', () => {
  assert.equal(relayLabel('https://dev.svrnty.is/api/relay', 0), 'dev.svrnty.is');
  assert.equal(relayLabel('http://127.0.0.1:3000/api/relay', 1), '127.0.0.1:3000');
  const nasty = relayLabel('https://user:s3cret@a.example:8443/api/relay/envelope?token=abc#frag', 0);
  assert.equal(nasty, 'a.example:8443');
  for (const bad of ['s3cret', 'user', 'token', 'abc', 'frag', '/api', '?', '@']) assert.ok(!nasty.includes(bad), `label leaks ${bad}`);
  assert.equal(relayLabel('/api/relay', 0), '#1');
  assert.equal(relayLabel('r2', 1), '#2');
  assert.ok(relayLabel(`https://${'a'.repeat(200)}.example/x`, 0).length <= 64, 'bounded');
});
test('U2 unconfirmedReason: WHICH relays and what each said; one relay reads "it", several read "any of them"; no attempts keeps the plain sentence', () => {
  assert.equal(unconfirmedReason([{ relay: 'a.example', status: 503 }]), 'relay a.example answered HTTP 503; it may have stored it');
  assert.equal(unconfirmedReason([{ relay: 'a.example' }]), 'relay a.example did not answer; it may have stored it');
  assert.equal(unconfirmedReason([{ relay: 'a.example', status: 502 }, { relay: 'b.example:8443' }]),
    'relay a.example answered HTTP 502, relay b.example:8443 did not answer; any of them may have stored it');
  assert.equal(unconfirmedReason(undefined), 'a relay may have stored it');
  assert.equal(unconfirmedReason([]), 'a relay may have stored it');
});
test('U3 depositWithFailover labels the unconfirmed relays by host, even when the base URL carries a path, a query or credentials', async () => {
  const bases = ['https://u:pw@a.example/api/relay?k=v', 'https://b.example:8443/api/relay', 'https://c.example/api/relay'];
  const o = await depositWithFailover(bases, async (b) => { if (b.includes('a.example')) return res(503); if (b.includes('b.example')) throw new Error('x'); return res(200); });
  assert.deepEqual(o.unconfirmedBy, [{ relay: 'a.example', status: 503 }, { relay: 'b.example:8443' }]);
  assert.equal(o.tier, 2);
  assert.doesNotMatch(JSON.stringify(o), /pw|k=v|api\/relay/, 'nothing but hosts leaves the walk');
  assert.equal('unconfirmedBy' in (await depositWithFailover(bases, async () => res(200))), false, 'a clean first-relay deposit names nobody');
});
test('B1 relayBudgetShare: ONE budget for the pass, an equal share of what is left per relay, a 1 s floor', () => {
  assert.equal(relayBudgetShare(40_000, 0, 4), 10_000);
  assert.equal(relayBudgetShare(40_000, 10_000, 3), 10_000, 'left / relays left, not the original share');
  assert.equal(relayBudgetShare(40_000, 30_000, 1), 10_000, 'the last relay gets all that is left');
  assert.equal(relayBudgetShare(40_000, 39_900, 2), 1_000, 'nearly nothing left still gets the 1 s floor');
  assert.equal(relayBudgetShare(40_000, 90_000, 2), 1_000, 'an overrun never yields a negative or zero budget');
  assert.equal(relayBudgetShare(40_000, 0, 0), 40_000, 'zero relays left is treated as one, never a divide by zero');
  // walking the relays with each taking its whole share never exceeds the total
  let elapsed = 0;
  for (let left = 4; left >= 1; left--) elapsed += relayBudgetShare(40_000, elapsed, left);
  assert.ok(elapsed <= 40_000, `shares add up to ${elapsed}`);
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
test('M3 EVERY numeric counter is summed, by name-blind rule: deferred, deduped, adopt_future_ignored and the receipts_* counts survive a multi-relay pass; rejected is a status, not a count', () => {
  const a = { ...sum({ deferred: 2, deduped: 1, adopt_future_ignored: 3 }), receipts_sent: 4, receipts_failed: 1, receipts_skipped: 0, receipts_capped: 2, some_future_counter: 5 } as ConsumeSummary;
  const b = { ...sum({ deferred: 3, adopt_future_ignored: 1 }), receipts_sent: 1, receipts_failed: 2, receipts_skipped: 7, receipts_capped: 0, some_future_counter: 1 } as ConsumeSummary;
  const m = mergeRelaySummaries([{ summary: a }, { summary: b }]) as unknown as Record<string, unknown>;
  assert.equal(m.deferred, 5);
  assert.equal(m.deduped, 1, 'present on one relay only: still carried');
  assert.equal(m.adopt_future_ignored, 4);
  assert.deepEqual([m.receipts_sent, m.receipts_failed, m.receipts_skipped, m.receipts_capped], [5, 3, 7, 2]);
  assert.equal(m.some_future_counter, 6, 'a counter nobody has named yet is summed too');
  const rej = mergeRelaySummaries([{ summary: sum({ rejected: 401 }) }, { summary: sum({ rejected: 503 }) }]);
  assert.equal(rej.rejected, 401, 'the FIRST refusal status is kept, never added (401 + 503 is not a status)');
  assert.equal(mergeRelaySummaries([{ summary: sum() }]).deferred, undefined, 'a counter no relay reported stays absent, not 0');
});
test('M2 NEG: a refused or failed relay is never hidden by a healthy one', () => {
  const m = mergeRelaySummaries([{ summary: sum() }, { summary: sum({ rejected: 401 }) }, { failed: true }]);
  assert.equal(m.rejected, 401);
  assert.deepEqual([m.relays, m.relaysFailed, m.relaysRejected], [3, 1, 1]);
  assert.equal(m.polled, 4, 'the healthy relays still count');
});

test('H1 NEG (Flint #2650 a): plain http is refused for a public host, so the owner-auth header and the poll never cross the internet in the clear', () => {
  for (const u of ['http://example.com/api/relay', 'http://8.8.8.8/api/relay', 'http://172.32.0.1/api/relay', 'http://172.15.255.255/api/relay', 'http://192.169.0.1/api/relay',
    'http://1.2.3.4.nip.io/api/relay', 'http://0.0.0.0/api/relay', 'http://dev.svrnty.is/api/relay', 'http://[2001:db8::1]/api/relay', 'http://127.0.0.1.evil.com/api/relay',
    // Flint #361 F1: a bare single-label name can resolve through DNS search domains to a PUBLIC host, so it is NOT private
    'http://relay/api/relay', 'http://relay-camelot:3000/r', 'http://camelot/api/relay', 'http://dockerhost:8100/x', 'http://a/r']) {
    assert.throws(() => parseRelayList({ SVRNTY_RELAYS: u }, D), /plain http is only for a private host/, u);
    assert.throws(() => parseRelayList({ SVRNTY_RELAY: u }, D), /plain http is only for a private host/, 'single form too: ' + u);
  }
  assert.throws(() => parseRelayList({ SVRNTY_RELAYS: 'https://a.test/r,http://example.com/r' }, D), /plain http/, 'one public http entry in a list');
});
test('H2 plain http IS fine on a private network, and https is fine anywhere', () => {
  for (const u of ['http://127.0.0.1:3000/r', 'http://127.9.9.9/r', 'http://localhost:3000/r', 'http://10.1.2.3/r', 'http://172.16.0.1/r', 'http://172.31.255.254/r', 'http://172.20.1.2/r',
    'http://192.168.1.5/r', 'http://169.254.7.7/r', 'http://[::1]:3000/r', 'http://[fe80::1]/r', 'http://[fd00::5]/r', 'http://box.local/r', 'http://2130706433/r']) {
    assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: u }, D), [u], u);
  }
  assert.deepEqual(parseRelayList({ SVRNTY_RELAYS: 'https://example.com/r' }, D), ['https://example.com/r']);
});
test('H3 isPrivateHost edges', () => {
  assert.equal(isPrivateHost(''), false);
  assert.equal(isPrivateHost('a.b'), false);
  for (const bare of ['relay', 'relay-camelot', 'camelot', 'a', 'dockerhost']) assert.equal(isPrivateHost(bare), false, `a bare name (${bare}) is not provably private`);
  assert.equal(isPrivateHost('box.local'), true);
  assert.equal(isPrivateHost('x.localhost'), true);
  assert.equal(isPrivateHost('LOCALHOST'), true);
  assert.equal(isPrivateHost('::'), false, 'the unspecified address is not a private peer');
});
