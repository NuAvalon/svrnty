// allowed-revoke: send the DELETEs the satellite is OWED, derived from the relay's own list (#959). Everything is injected: a fake relay, an in-memory book, a fake clock and sleep.
// Run: node --import tsx --test src/lib/sync/allowed-revoke.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { drainAllowedRevokes, requestDrain, resetRevokeState, REVOKE_BACKOFF_MIN_MS, REVOKE_BACKOFF_MAX_MS, REVOKE_SPACING_MS, DRAIN_BATCH_MS, DRAIN_MIN_GAP_MS, REVOKE_MAX_PER_DRAIN, type AllowedRevokeDeps } from './allowed-revoke';
import type { AllowedListResult, PeerConsent } from './allowed-sync';

const OWNER = 'ee'.repeat(32);
const P = 'a1'.repeat(32), Q = 'b2'.repeat(32), R = 'c3'.repeat(32), Z = 'd4'.repeat(32);
const ALLOWED: PeerConsent = { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false };
const BLOCKED: PeerConsent = { ...ALLOWED, blocked: true };
const NEVER: PeerConsent = { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false };

/** A fake relay that keeps a list, and an in-memory book. A confirmed DELETE takes the peer off the relay's list, as the real one does. */
const rig = (opts: { relay?: string[]; book?: Record<string, PeerConsent>; list?: 'ok' | 'unknown' | 'gone'; bookThrows?: boolean; complete?: boolean | 'throws' } = {}) => {
  const state = { relay: new Set(opts.relay ?? []), book: { ...(opts.book ?? {}) } as Record<string, PeerConsent>, list: opts.list ?? 'ok', t: 1_000_000, bookThrows: !!opts.bookThrows, results: [] as boolean[] };
  const sent: string[] = []; const sleeps: number[] = []; const logs: string[] = []; let lists = 0;
  const io = {
    list: async (): Promise<AllowedListResult> => { lists++; return state.list === 'ok' ? { status: 'ok', fps: [...state.relay].sort() } : { status: state.list }; },
    deleteRow: async (fp: string) => { sent.push(fp); const ok = state.results.length ? state.results.shift()! : true; if (ok) state.relay.delete(fp); return ok; },
  };
  const deps: AllowedRevokeDeps = {
    consents: async () => { if (state.bookThrows) throw new Error('book unreadable'); return new Map(Object.entries(state.book)); },
    now: () => state.t, sleep: async (ms) => { sleeps.push(ms); }, log: (m) => { logs.push(m); },
    ...(opts.complete === undefined ? {} : { bookComplete: async () => { if (opts.complete === 'throws') throw new Error('integrity unreadable'); return opts.complete as boolean; } }),
  };
  return { io, deps, state, sent, sleeps, logs, lists: () => lists, drain: (override?: ReadonlyMap<string, PeerConsent>) => drainAllowedRevokes(OWNER, io, deps, override) };
};

test('AR1 NEG (Flint): the relay lists a BLOCKED contact with a local record -> exactly one DELETE, and the relay then no longer lists it', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  const out = await r.drain();
  assert.deepEqual(r.sent, [P]);
  assert.equal(out.revoked, 1);
  assert.deepEqual([...r.state.relay], []);
});

test('AR2 NEG (Flint): the relay lists a fingerprint that is NOT IN THE BOOK at all (a removed contact, a restored device, a contact this device never had) -> DELETE', async () => {
  resetRevokeState();
  const r = rig({ relay: [Z], book: { [P]: ALLOWED } });
  await r.drain();
  assert.deepEqual(r.sent, [Z], 'a fingerprint with no local record counts as not allowed');
});

test('AR3 a peer whose consent ALLOWS a row is never revoked, and a peer the relay does NOT list is never named: a contact that never had a row sends 0 DELETEs (one GET, nothing more)', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: ALLOWED, [Q]: BLOCKED, [R]: NEVER } });   // Q and R are not on the relay's list
  const out = await r.drain();
  assert.deepEqual(r.sent, []);
  assert.equal(out.attempted, 0);
  assert.equal(r.lists(), 1);
});

test('AR4 NEG (Flint): a GET that FAILS is UNKNOWN: 0 DELETEs, nothing marked done, nothing cleared, and the next drain retries and sends them', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED }, list: 'unknown' });
  const out = await r.drain();
  assert.equal(out.listed, 'unknown');
  assert.deepEqual(r.sent, [], 'never read as an empty list: nothing is revoked AND nothing is declared done');
  assert.deepEqual([...r.state.relay], [P], 'the row is still there to be revoked');
  r.state.list = 'ok';
  const again = await r.drain();
  assert.deepEqual(r.sent, [P], 'the next drain found it and sent the DELETE');
  assert.equal(again.revoked, 1);
});

test('AR5 an unknown GET touches NO state: a backoff window opened by an earlier refused DELETE is still in force afterwards', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  r.state.results = [false];
  await r.drain();                                                   // refused: the window opens
  r.state.list = 'unknown'; await r.drain();                         // an unusable GET in between
  r.state.list = 'ok';
  const inside = await r.drain();
  assert.equal(r.sent.length, 1, 'still inside the window: the unknown GET did not clear it');
  assert.equal(inside.outcomes.get(P), 'waiting');
});

test('AR6 410 is the ONE exception: the relay keeps no list, so NOTHING is owed: 0 DELETEs, no further GETs that session, and it is logged ONCE', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED }, list: 'gone' });
  const first = await r.drain();
  assert.equal(first.listed, 'gone');
  assert.deepEqual(r.sent, []);
  await r.drain(); await r.drain();
  assert.equal(r.lists(), 1, 'no further GETs after the 410');
  assert.equal(r.logs.length, 1, 'logged once');
});

test('AR7 a refused DELETE stays owed: the relay still lists it, the next drain AFTER the backoff retries, and once it succeeds the relay lists nothing and nothing more is sent', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  r.state.results = [false];
  const first = await r.drain();
  assert.equal(first.failed, 1);
  assert.deepEqual([...r.state.relay], [P], 'still at the relay, so still owed');
  r.state.t += REVOKE_BACKOFF_MIN_MS;
  const second = await r.drain();
  assert.equal(second.revoked, 1);
  assert.deepEqual(r.sent, [P, P]);
  await r.drain();
  assert.deepEqual(r.sent, [P, P], 'nothing owed any more');
});

test('AR8 PACED: one GET per drain however many are owed, and the DELETEs are spaced (no pause before the first)', async () => {
  resetRevokeState();
  const r = rig({ relay: [P, Q, R], book: {} });
  await r.drain();
  assert.equal(r.lists(), 1);
  assert.deepEqual([...r.sent].sort(), [P, Q, R].sort());
  assert.deepEqual(r.sleeps, [REVOKE_SPACING_MS, REVOKE_SPACING_MS], 'two pauses between three DELETEs');
});

test('AR9 a book that cannot be read sends NOTHING (it cannot be told who is still allowed) and never throws; a GET that throws is unknown', async () => {
  resetRevokeState();
  const blind = rig({ relay: [P], book: { [P]: BLOCKED }, bookThrows: true });
  const out = await blind.drain();
  assert.deepEqual(blind.sent, []);
  assert.equal(out.listed, 'unknown');
  const throwing = rig({ relay: [P], book: { [P]: BLOCKED } });
  throwing.io.list = async () => { throw new Error('boom'); };
  assert.equal((await throwing.drain()).listed, 'unknown');
  assert.deepEqual(throwing.sent, []);
});

test('AR10 the consent a CALL just made is authoritative for its own peer over whatever the book read says (a stale read must not decide a change this call just made)', async () => {
  resetRevokeState();
  const stale = rig({ relay: [P], book: { [P]: ALLOWED } });          // the book still says allowed...
  await stale.drain(new Map([[P, BLOCKED]]));                         // ...but this call just blocked P
  assert.deepEqual(stale.sent, [P]);
  resetRevokeState();
  const fresh = rig({ relay: [P], book: { [P]: BLOCKED } });          // the book says blocked...
  await fresh.drain(new Map([[P, ALLOWED]]));                         // ...but this call just granted P
  assert.deepEqual(fresh.sent, []);
});

test('AR11 BOUNDED BACKOFF: a refused peer is not retried inside its window, each window is at most double the last and never shrinks, it ends at the cap, and a success clears it', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  r.state.results = Array.from({ length: 40 }, () => false);
  await r.drain();
  assert.equal(r.sent.length, 1);
  r.state.t += REVOKE_BACKOFF_MIN_MS - 1; await r.drain();
  assert.equal(r.sent.length, 1, 'one millisecond inside the first window: not tried');
  r.state.t += 1; await r.drain();
  assert.equal(r.sent.length, 2, 'AT the end of the window: tried');
  const gaps: number[] = []; let lastAt = r.state.t; let n = r.sent.length;
  for (let guard = 0; guard < 4000 && gaps.length < 9; guard++) {
    r.state.t += 60_000; await r.drain();
    if (r.sent.length > n) { gaps.push((r.state.t - lastAt) / 60_000); lastAt = r.state.t; n = r.sent.length; }
  }
  assert.equal(gaps.length, 9, `nine more attempts: ${gaps}`);
  for (let k = 1; k < gaps.length; k++) { assert.ok(gaps[k] >= gaps[k - 1], `never shrinks: ${gaps}`); assert.ok(gaps[k] <= 2 * gaps[k - 1] + 1, `at most double: ${gaps}`); }
  assert.ok(gaps.slice(-2).every((g) => g >= REVOKE_BACKOFF_MAX_MS / 60_000 - 1 && g <= REVOKE_BACKOFF_MAX_MS / 60_000 + 1), `ends at the cap: ${gaps}`);
  r.state.results = [true]; r.state.t += REVOKE_BACKOFF_MAX_MS;
  await r.drain();
  assert.deepEqual([...r.state.relay], [], 'a success removes it');
});

// ── #959: burst control. A burst of calls (an import-merge of N contacts) is ONE GET, not N: the calls share a batch, which runs once after a short window; batches are serialized and spaced. ──
const batching = (r: ReturnType<typeof rig>, real = false) => {
  const waits: number[] = [];
  r.deps.delay = real ? (ms) => { waits.push(ms); return new Promise((res) => setTimeout(res, 5)); } : async (ms) => { waits.push(ms); r.state.t += ms; };
  return waits;
};

test('AR12 BURST CONTROL (Flint): 10 calls in one tick make ONE GET; every caller gets the shared result and its own peer\'s outcome, because each call\'s consent was merged into the batch', async () => {
  resetRevokeState();
  const peers = Array.from({ length: 10 }, (_, i) => String(i).repeat(2).padEnd(64, 'f'));
  const r = rig({ relay: peers, book: Object.fromEntries(peers.map((fp) => [fp, ALLOWED])) });   // the book still says allowed for every peer: ONLY each call's own consent revokes it
  const waits = batching(r, true);
  const results = await Promise.all(peers.map((fp) => requestDrain(OWNER, r.io, r.deps, new Map([[fp, BLOCKED]]))));
  assert.equal(r.lists(), 1, 'ONE GET for ten calls');
  assert.equal(r.sent.length, 10, 'and each owed peer was revoked once');
  assert.ok(results.every((x) => x === results[0]), 'every caller got the same batch result');
  for (const fp of peers) assert.equal(results[0].outcomes.get(fp), 'deleted', fp.slice(0, 4));
  assert.ok(waits[0] >= DRAIN_BATCH_MS, `the batch waited its window first (${waits})`);
});

test('AR13 a LATER batch waits for the minimum gap since the last one started, and never starts while one is running (no two drains at once)', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  const waits = batching(r);
  let active = 0, maxActive = 0;
  const realList = r.io.list;
  r.io.list = async () => { active++; maxActive = Math.max(maxActive, active); await new Promise((res) => setTimeout(res, 15)); const out = await realList(); active--; return out; };
  await requestDrain(OWNER, r.io, r.deps);
  const first = r.state.t;
  const more = [requestDrain(OWNER, r.io, r.deps), requestDrain(OWNER, r.io, r.deps)];   // arrive right after: one batch, not two, and not before the gap
  await Promise.all(more);
  assert.equal(r.lists(), 2, 'two batches: the first, and one for the late arrivals');
  assert.equal(maxActive, 1, 'never two drains at once');
  assert.ok(r.state.t - first >= DRAIN_MIN_GAP_MS - DRAIN_BATCH_MS, `the second batch waited out the gap (waited ${waits.slice(-1)} ms)`);
  assert.ok(waits.slice(-1)[0] >= DRAIN_MIN_GAP_MS - 1, 'the wait it asked for covers the gap');
});

test('AR14 a request that arrives while a drain is RUNNING joins the NEXT batch and is still answered (a hung or failing drain never leaves a caller waiting)', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  batching(r);
  r.io.list = async () => { throw new Error('boom'); };               // the drain itself fails
  const out = await requestDrain(OWNER, r.io, r.deps);
  assert.equal(out.listed, 'unknown', 'answered, with unknown');
  const delayThrows = rig({ relay: [P], book: { [P]: BLOCKED } });
  delayThrows.deps.delay = async () => { throw new Error('timer broke'); };
  const out2 = await requestDrain(OWNER, delayThrows.io, delayThrows.deps);
  assert.equal(out2.listed, 'unknown', 'a broken timer still answers');
});

test('AR15 a request that arrives while a drain is RUNNING waits for it: two drains for one owner never overlap, and the late request is still answered by its own batch', async () => {
  resetRevokeState();
  const r = rig({ relay: [P], book: { [P]: BLOCKED } });
  batching(r);                                                        // instant timers: only the running drain can hold the second batch back
  let active = 0, maxActive = 0; let release!: () => void; const gate = new Promise<void>((res) => { release = res; });
  let entered!: () => void; const inside = new Promise<void>((res) => { entered = res; });
  const realList = r.io.list;
  r.io.list = async () => { active++; maxActive = Math.max(maxActive, active); entered(); if (active === 1) await gate; const out = await realList(); active--; return out; };
  const first = requestDrain(OWNER, r.io, r.deps);
  await inside;                                                       // the first drain is now running and held open
  const second = requestDrain(OWNER, r.io, r.deps);                   // arrives while it runs
  await new Promise((res) => setTimeout(res, 20));
  assert.equal(active, 1, 'the second batch did not start while the first was running');
  release();
  await Promise.all([first, second]);
  assert.equal(maxActive, 1, 'never two drains at once');
  assert.equal(r.lists(), 2, 'and the late request got a batch of its own');
});

const UP = (fp: string) => fp.toUpperCase();

test('AR16 (Flint) the book and the relay are compared CASE-INSENSITIVELY, and the DELETE goes out with the relay\'s OWN string', async () => {
  resetRevokeState();
  const blocked = rig({ relay: [UP(P)], book: { [P]: BLOCKED } });
  await blocked.drain();
  assert.deepEqual(blocked.sent, [UP(P)], 'revoked, with the relay\'s own upper-case string');
  resetRevokeState();
  const allowed = rig({ relay: [UP(P)], book: { [P]: ALLOWED } });
  await allowed.drain();
  assert.deepEqual(allowed.sent, [], 'an allowed contact is not revoked because of a difference in case');
  resetRevokeState();
  resetRevokeState();
  const upperBook = rig({ relay: [P], book: { [UP(P)]: BLOCKED } });
  await upperBook.drain();
  assert.deepEqual(upperBook.sent, [P], 'a book that holds the fingerprint in upper case still matches the relay\'s lower case');
  resetRevokeState();
  const upperAllowed = rig({ relay: [P], book: { [UP(P)]: ALLOWED } });   // blocked and ABSENT are both revoked, so only an ALLOWED upper-case key tells a matched key from a missed one
  await upperAllowed.drain();
  assert.deepEqual(upperAllowed.sent, [], 'an allowed contact whose book key is upper case is matched, not read as absent and revoked');
  resetRevokeState();
  const own = rig({ relay: [P], book: {} });
  await own.drain(new Map([[UP(P), ALLOWED]]));
  assert.deepEqual(own.sent, [], 'the consent a call just made matches the listed fingerprint whatever its case');
});

test('AR17 CORRUPT BOOK (Flint): a book flagged corrupt revokes only contacts it still HOLDS; a listed fingerprint ABSENT from it is not revoked (with an ok flag it is); an unreadable flag counts as corrupt', async () => {
  for (const [label, complete, wantSent] of [['ok flag: an absent peer is revoked', true, [Z]], ['corrupt flag: the absent peer is NOT revoked', false, []], ['an unreadable flag counts as corrupt', 'throws', []]] as const) {
    resetRevokeState();
    const r = rig({ relay: [Z], book: { [P]: ALLOWED }, complete });
    await r.drain();
    assert.deepEqual(r.sent, wantSent, label);
  }
  resetRevokeState();
  const present = rig({ relay: [P, Z], book: { [P]: BLOCKED }, complete: false });
  await present.drain();
  assert.deepEqual(present.sent, [P], 'a peer the damaged book still holds with a not-allowed consent IS revoked; the absent one is not');
});

test('AR18 CAP (Flint): at most REVOKE_MAX_PER_DRAIN revokes per drain, the rest stay listed (owed) and go out on the next one', async () => {
  resetRevokeState();
  const peers = Array.from({ length: REVOKE_MAX_PER_DRAIN + 5 }, (_, i) => i.toString(16).padStart(64, '0'));
  const r = rig({ relay: peers, book: {} });
  const first = await r.drain();
  assert.equal(r.sent.length, REVOKE_MAX_PER_DRAIN);
  assert.equal(first.attempted, REVOKE_MAX_PER_DRAIN);
  assert.equal(r.state.relay.size, 5, 'the rest are still listed, so still owed');
  assert.equal([...first.outcomes.values()].filter((o) => o === 'deferred').length, 5);
  await r.drain();
  assert.equal(r.state.relay.size, 0, 'the next drain sent them');
});

test('ARR1 (source shape) the REAL book asks the contact book\'s integrity flag, so a book flagged corrupt reaches the drain as incomplete (nothing else exercises the real wiring)', () => {
  const src = readFileSync(join(process.cwd(), 'src/lib/sync/allowed-revoke-real.ts'), 'utf8');
  assert.match(src, /bookComplete:\s*async \(ownerFp\)\s*=>\s*\(await getContactBookIntegrity\(ownerFp\)\)\s*===\s*'ok'/);
});
