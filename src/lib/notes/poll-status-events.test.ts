// src/lib/notes/poll-status-events.test.ts
// Copy v1 §B (Hypatia 07c6d5ae) NEGs: 3 consecutive refused polls → the Chat notice; one answered poll clears it; locked never shows it;
// 200 [] never shows it. The poll-path tests drive the REAL pollLiveBookOnce / startLiveBookPolling tick → consume path with a signing
// owner and an injected relay (only the IndexedDB deps builder is injected).
//
// Run: npx tsx --test src/lib/notes/poll-status-events.test.ts

import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import type { ConsumeDeps } from '@/lib/sync/consume-mailbox';
import { IDLE_TICKS_BEFORE_BACKOFF, pollLiveBookOnce, startLiveBookPolling } from '@/lib/sync/live-book-poll';
import { lockSession } from '@/lib/identity/client-store';
import {
  BUSY_MS_BEFORE_NOTICE,
  REFUSED_POLLS_BEFORE_NOTICE,
  __resetPollStatusForTest,
  busyBackoffMs,
  clearPollStatus,
  getPollRefusedReport,
  reportPollStatus,
  subscribePollRefused,
} from './poll-status-events';
import { POLL_REFUSED_COPY, pollRefusedNotice } from '@/components/notes/poll-refused-notice';

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

beforeEach(() => __resetPollStatusForTest());

/** A relay whose /queue answers with the next status in `statuses` (the last one repeats). */
function relaySeq(statuses: number[]): typeof fetch {
  let i = 0;
  return async () => {
    const status = statuses[Math.min(i++, statuses.length - 1)];
    return new Response(status === 200 ? '[]' : JSON.stringify({ error: 'unauthorized' }), { status });
  };
}

function depsWith(fetchImpl: typeof fetch) {
  return async (): Promise<ConsumeDeps> => ({
    owner,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    fetchImpl,
  });
}

const fmt = (ms: number) => `T${ms}`;
const NEVER_SAY = [/caught up/i, /up to date/i, /no new messages/i, /\bsafe\b/i, /\bkept\b/i, /\d+ (new )?messages? waiting/i];

test('store: 2 refused polls show nothing; the 3rd shows the notice', () => {
  for (let i = 1; i < REFUSED_POLLS_BEFORE_NOTICE; i++) {
    reportPollStatus('rejected');
    assert.equal(getPollRefusedReport().refused, false, `after ${i}`);
  }
  reportPollStatus('rejected');
  assert.equal(getPollRefusedReport().refused, true);
  assert.equal(REFUSED_POLLS_BEFORE_NOTICE, 3);
});

test('store: one answered poll clears it and resets the run (2 more refusals do not re-show it)', () => {
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  reportPollStatus('ok', 1000);
  assert.equal(getPollRefusedReport().refused, false);
  reportPollStatus('rejected');
  reportPollStatus('rejected');
  assert.equal(getPollRefusedReport().refused, false);
  reportPollStatus('rejected');
  assert.deepEqual(getPollRefusedReport(), { refused: true, lastOkAt: 1000, kind: 'refused' });
});

test('store: a checked-waiting poll is an ANSWERED poll: it clears the notice and is the "since" time', () => {
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  reportPollStatus('checked-waiting', 77);
  assert.equal(getPollRefusedReport().refused, false);
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  assert.deepEqual(getPollRefusedReport(), { refused: true, lastOkAt: 77, kind: 'refused' });
});

test('store: locked never shows it and ends the run', () => {
  reportPollStatus('rejected');
  reportPollStatus('rejected');
  reportPollStatus('locked');
  reportPollStatus('rejected');
  assert.equal(getPollRefusedReport().refused, false);
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  reportPollStatus('locked');
  assert.equal(getPollRefusedReport().refused, false, 'shown → locked hides it');
});

test('store: clearPollStatus (session lock) forgets the last answered time, so no "since" leaks across identities', () => {
  reportPollStatus('ok', 5);
  clearPollStatus();
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  assert.deepEqual(getPollRefusedReport(), { refused: true, lastOkAt: undefined, kind: 'refused' });
});

test('store: lockSession() runs the clear (the onSessionLock hook is wired)', () => {
  for (let i = 0; i < 3; i++) reportPollStatus('rejected');
  assert.equal(getPollRefusedReport().refused, true);
  lockSession();
  assert.equal(getPollRefusedReport().refused, false);
});

test('store: subscribers are woken on change only, and a throwing subscriber is isolated', () => {
  const seen: boolean[] = [];
  subscribePollRefused(() => {
    throw new Error('boom');
  });
  subscribePollRefused((r) => seen.push(r.refused));
  for (let i = 0; i < 5; i++) reportPollStatus('rejected');
  reportPollStatus('ok');
  reportPollStatus('ok');
  assert.deepEqual(seen, [true, false]);
});

test('copy: both §B "refused" variants verbatim + the hedged hint on a 401; nothing when not refused', () => {
  assert.equal(pollRefusedNotice({ refused: false }, fmt), null);
  assert.deepEqual(pollRefusedNotice({ refused: true, lastOkAt: 42, kind: 'refused-auth' }, fmt), {
    text: "Couldn't check for new messages since T42. The relay refused this device's request.",
    hint: "If your device's date and time are wrong, fixing them may help.",
  });
  assert.deepEqual(pollRefusedNotice({ refused: true, kind: 'refused-auth' }, fmt), {
    text: "Couldn't check for new messages. The relay refused this device's request.",
    hint: POLL_REFUSED_COPY.hint,
  });
});

test('copy: a refusal that is not a 401 says "refused" with NO clock hint', () => {
  assert.deepEqual(pollRefusedNotice({ refused: true, lastOkAt: 42, kind: 'refused' }, fmt), {
    text: "Couldn't check for new messages since T42. The relay refused this device's request.",
  });
  assert.deepEqual(pollRefusedNotice({ refused: true, kind: 'refused' }, fmt), {
    text: "Couldn't check for new messages. The relay refused this device's request.",
  });
});

test('copy v3: both "couldn\'t be read" variants verbatim, with NO clock hint', () => {
  assert.deepEqual(pollRefusedNotice({ refused: true, lastOkAt: 42, kind: 'unreadable' }, fmt), {
    text: "Couldn't check for new messages since T42. The relay's reply couldn't be read.",
  });
  assert.deepEqual(pollRefusedNotice({ refused: true, kind: 'unreadable' }, fmt), {
    text: "Couldn't check for new messages. The relay's reply couldn't be read.",
  });
});

test('copy: never says caught up / up to date / no new messages / kept / safe / a count', () => {
  for (const kind of ['refused', 'unreadable'] as const) {
    for (const r of [{ refused: true as const, lastOkAt: 1, kind }, { refused: true as const, kind }]) {
      const n = pollRefusedNotice(r, fmt)!;
      for (const re of NEVER_SAY) {
        assert.ok(!re.test(n.text) && !re.test(n.hint ?? ''), `${re} in ${n.text} / ${n.hint}`);
      }
    }
  }
});

test('NEG pull-to-refresh path: 3 × queue 401 → the notice; 200 [] then clears it', async () => {
  const fetchImpl = relaySeq([401, 401, 401, 200]);
  for (let i = 0; i < 3; i++) assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(fetchImpl) }), 'rejected');
  assert.equal(getPollRefusedReport().refused, true);
  assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(fetchImpl) }), 'ok');
  assert.equal(getPollRefusedReport().refused, false);
});

/** /queue answers each poll with the next item: a number = that status with an error body; 'bad' = 200 with a non-list body. */
function relayKinds(seq: Array<number | 'bad'>): typeof fetch {
  let i = 0;
  return async () => {
    const k = seq[Math.min(i++, seq.length - 1)];
    if (k === 'bad') return new Response('{"envelopes":"nope"}', { status: 200 });
    return new Response(k === 200 ? '[]' : '{}', { status: k });
  };
}

test('NEG v3: 3 × malformed 200 → "couldn\'t be read", NO clock hint, never "refused"', async () => {
  const f = relayKinds(['bad']);
  for (let i = 0; i < 3; i++) assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(f) }), 'unreadable');
  const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
  assert.equal(n.text, "Couldn't check for new messages. The relay's reply couldn't be read.");
  assert.equal(n.hint, undefined);
  assert.ok(!/refused/i.test(n.text));
});

test('NEG v3: 3 × 401 → "refused" + the clock hint', async () => {
  const f = relayKinds([401]);
  for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
  assert.equal(n.text, "Couldn't check for new messages. The relay refused this device's request.");
  assert.equal(n.hint, POLL_REFUSED_COPY.hint);
});

test('NEG 3 × 403 and 3 × 400 → "refused", NO clock hint: a wrong clock yields a 401, not these', async () => {
  for (const code of [403, 400]) {
    __resetPollStatusForTest();
    const f = relayKinds([code]);
    for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
    const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
    assert.equal(n.text, "Couldn't check for new messages. The relay refused this device's request.", String(code));
    assert.equal(n.hint, undefined, String(code));
  }
});

test('copy: a relay failure says the relay had a problem, verbatim, with NO clock hint', () => {
  assert.deepEqual(pollRefusedNotice({ refused: true, lastOkAt: 42, kind: 'relay-error' }, fmt), {
    text: "Couldn't check for new messages since T42. The relay ran into a problem. Trying again automatically.",
  });
  assert.deepEqual(pollRefusedNotice({ refused: true, kind: 'relay-error' }, fmt), {
    text: "Couldn't check for new messages. The relay ran into a problem. Trying again automatically.",
  });
});

test('copy: the relay-failure lines never claim a refusal or anything NEVER_SAY forbids', () => {
  for (const line of [POLL_REFUSED_COPY.relayErrorSince('T1'), POLL_REFUSED_COPY.relayErrorNever]) {
    assert.doesNotMatch(line, /refused/i);
    for (const re of NEVER_SAY) assert.doesNotMatch(line, re);
  }
});

test('NEG 3 × 500, 502, 504, 599 → the relay had a problem: never "refused", NO clock hint', async () => {
  for (const code of [500, 502, 504, 599]) {
    __resetPollStatusForTest();
    const f = relayKinds([code]);
    for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
    const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
    assert.equal(n.text, "Couldn't check for new messages. The relay ran into a problem. Trying again automatically.", String(code));
    assert.equal(n.hint, undefined, String(code));
  }
});

test('NEG 2 × 500 shows nothing yet: a relay failure needs the same 3 polls in a row', async () => {
  const f = relayKinds([500]);
  for (let i = 0; i < 2; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  assert.equal(getPollRefusedReport().refused, false);
});

test('NEG 499 is still a refusal: only a 5xx is the relay failing', () => {
  for (let i = 0; i < 3; i++) reportPollStatus('rejected', 1000, 499);
  const r = getPollRefusedReport();
  assert.ok(r.refused && r.kind === 'refused');
});

test('NEG no status known: a rejected poll stays "refused", as before', () => {
  for (let i = 0; i < 3; i++) reportPollStatus('rejected', 1000);
  const r = getPollRefusedReport();
  assert.ok(r.refused && r.kind === 'refused');
});

test('NEG the wording follows the LATEST failing poll: 401, 401, 500 → relay problem, no hint', async () => {
  const f = relayKinds([401, 401, 500]);
  for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
  assert.match(n.text, /ran into a problem/);
  assert.equal(n.hint, undefined);
});

test('NEG the wording follows the LATEST failing poll: 500, 500, 401 → refused + hint', async () => {
  const f = relayKinds([500, 500, 401]);
  for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
  assert.match(n.text, /refused/);
  assert.equal(n.hint, POLL_REFUSED_COPY.hint);
});

test('NEG an answered poll clears a relay-failure notice', async () => {
  const f = relayKinds([500, 500, 500, 200]);
  for (let i = 0; i < 4; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  assert.equal(getPollRefusedReport().refused, false);
});

test('NEG the hint follows the LATEST failing poll: 401, 401, 403 → no hint; 403, 403, 401 → hint', async () => {
  for (const [seq, hint] of [[[401, 401, 403], undefined], [[403, 403, 401], POLL_REFUSED_COPY.hint]] as const) {
    __resetPollStatusForTest();
    const f = relayKinds([...seq]);
    for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
    assert.equal(pollRefusedNotice(getPollRefusedReport(), fmt)!.hint, hint, seq.join(','));
  }
});

test('NEG background tick: the hint needs the 401 there too (a 403 tick shows none)', async () => {
  const fetchImpl: typeof fetch = async () => new Response('{}', { status: 403 });
  const h = startLiveBookPolling({}, { intervalMs: 20, buildDeps: depsWith(fetchImpl) });
  try {
    assert.ok(await waitFor(() => getPollRefusedReport().refused), 'notice after refused ticks');
    assert.equal(pollRefusedNotice(getPollRefusedReport(), fmt)!.hint, undefined);
  } finally {
    h.stop();
  }
});

test('NEG v3: mixed 401, 401, malformed → the streak counts both; worded for the LATEST ("couldn\'t be read")', async () => {
  const f = relayKinds([401, 401, 'bad']);
  for (let i = 0; i < 3; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  const n = pollRefusedNotice(getPollRefusedReport(), fmt)!;
  assert.equal(n.text, "Couldn't check for new messages. The relay's reply couldn't be read.");
  assert.equal(n.hint, undefined);
});

test('NEG v3: an ok first, then 3 failures, the latest a 401 → "since <time>" + "refused" + hint', async () => {
  const f = relayKinds([200, 'bad', 'bad', 401]);
  for (let i = 0; i < 4; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(f) });
  const r = getPollRefusedReport();
  assert.ok(r.refused && r.kind === 'refused-auth' && typeof r.lastOkAt === 'number');
  const n = pollRefusedNotice(r, fmt)!;
  assert.match(n.text, /^Couldn't check for new messages since T\d+\. The relay refused this device's request\.$/);
  assert.equal(n.hint, POLL_REFUSED_COPY.hint);
});

test('NEG pull-to-refresh path: locked never shows it', async () => {
  for (let i = 0; i < 5; i++) await pollLiveBookOnce({}, { buildDeps: async () => null });
  assert.equal(getPollRefusedReport().refused, false);
});

test('control: 200 [] polls never show it', async () => {
  for (let i = 0; i < 5; i++) await pollLiveBookOnce({}, { buildDeps: depsWith(relaySeq([200])) });
  assert.equal(getPollRefusedReport().refused, false);
});

async function waitFor(pred: () => boolean, ms = 8000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return pred();
}

test('NEG background tick: repeated queue 401 → the notice; then an answered poll clears it', async () => {
  let status = 401;
  let polls = 0;
  const fetchImpl: typeof fetch = async () => {
    polls++;
    return new Response(status === 200 ? '[]' : '{}', { status });
  };
  const h = startLiveBookPolling({}, { intervalMs: 20, buildDeps: depsWith(fetchImpl) });
  try {
    assert.ok(await waitFor(() => getPollRefusedReport().refused), 'notice after refused ticks');
    assert.ok(polls >= REFUSED_POLLS_BEFORE_NOTICE);
    assert.equal(pollRefusedNotice(getPollRefusedReport(), fmt)!.hint, POLL_REFUSED_COPY.hint, 'a 401 on the background path keeps the clock hint');
    status = 200;
    assert.ok(await waitFor(() => !getPollRefusedReport().refused), 'cleared by an answered tick');
  } finally {
    h.stop();
  }
});

// ---- a relay shedding load (429/503) is 'busy': silent retry, no refusal notice, one plain line only after 30 s straight ----

const T0 = 1_000_000;

test('H1 busy polls show nothing before 30 s, however many there are (they are not refusals)', () => {
  for (let t = 0; t < BUSY_MS_BEFORE_NOTICE; t += 350) {
    reportPollStatus('busy', T0 + t);
    assert.equal(getPollRefusedReport().refused, false, `at ${t} ms`);
  }
  assert.equal(BUSY_MS_BEFORE_NOTICE, 30_000);
});

test('H2 30 s of continuous busy shows exactly "Could not check right now.": no cause, no clock hint', () => {
  reportPollStatus('busy', T0);
  reportPollStatus('busy', T0 + BUSY_MS_BEFORE_NOTICE);
  const r = getPollRefusedReport();
  assert.equal(r.refused, true);
  assert.deepEqual(pollRefusedNotice(r, () => 'noon'), { text: 'Could not check right now.' });
});

test('H3 the first answered poll clears it, and the next busy spell starts a fresh 30 s', () => {
  reportPollStatus('busy', T0);
  reportPollStatus('busy', T0 + BUSY_MS_BEFORE_NOTICE);
  reportPollStatus('ok', T0 + BUSY_MS_BEFORE_NOTICE + 1);
  assert.equal(getPollRefusedReport().refused, false);
  reportPollStatus('busy', T0 + BUSY_MS_BEFORE_NOTICE + 2);
  assert.equal(getPollRefusedReport().refused, false);
});

test('H4 a different answer breaks "30 s straight"', () => {
  reportPollStatus('busy', T0);
  reportPollStatus('rejected', T0 + 15_000);
  reportPollStatus('busy', T0 + 16_000);
  reportPollStatus('busy', T0 + 31_000);
  assert.equal(getPollRefusedReport().refused, false);
});

test('H5 a lock / identity switch forgets the busy spell', () => {
  reportPollStatus('busy', T0);
  clearPollStatus();
  reportPollStatus('busy', T0 + BUSY_MS_BEFORE_NOTICE + 1);
  assert.equal(getPollRefusedReport().refused, false);
});

test('H6 the real poll path reads 503 and 429 as busy, other refusals as rejected, and shows no refusal notice for busy', async () => {
  for (const s of [503, 429]) {
    __resetPollStatusForTest();
    for (let i = 0; i < 6; i++) assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(relaySeq([s])) }), 'busy', String(s));
    assert.equal(getPollRefusedReport().refused, false);
  }
  __resetPollStatusForTest();
  assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(relaySeq([500])) }), 'rejected');
});

test('H7 backoff: 1 s, 2 s, 4 s, then 8 s', () => {
  assert.deepEqual([1, 2, 3, 4, 5, 9].map(busyBackoffMs), [1000, 2000, 4000, 8000, 8000, 8000]);
});

test('H8 the background loop backs off a busy relay, even in a burst, and returns to its cadence on the next answer', async () => {
  let polls = 0, status = 503;
  const fetchImpl: typeof fetch = async () => { polls++; return new Response(status === 200 ? '[]' : '{}', { status }); };
  // random 0 fixes the jitter at its low end: busy polls land at 0, 750 and 2250 ms, where an unthrottled burst polls at 0, 350, 700, 1050 ms.
  const h = startLiveBookPolling({}, { intervalMs: 20, buildDeps: depsWith(fetchImpl), random: () => 0 });
  try {
    h.burst(60_000);
    await new Promise((r) => setTimeout(r, 1200));
    assert.ok(polls <= 2, `a burst backs off while busy (saw ${polls} polls in 1.2 s)`);
    status = 200;
    await new Promise((r) => setTimeout(r, 3000));
    assert.ok(polls >= 5, `back to the burst cadence after an answered poll (saw ${polls})`);
  } finally {
    h.stop();
  }
});

test('H9 shed polls do not count as idle: after a busy spell the loop is at its normal cadence, not backed off', async () => {
  const delays: number[] = [];
  let fire: (() => void) | null = null;
  const timers = { set: (f: () => void, ms: number) => { delays.push(ms); fire = f; return 1; }, clear: () => { fire = null; } };
  let status = 503;
  const fetchImpl: typeof fetch = async () => new Response(status === 200 ? '[]' : '{}', { status });
  // random 0.5 makes the jitter exactly 1, so every delay is its base.
  const h = startLiveBookPolling({}, { intervalMs: 1000, maxIdleIntervalMs: 60_000, buildDeps: depsWith(fetchImpl), random: () => 0.5, timers });
  try {
    const step = async () => {
      assert.ok(await waitFor(() => fire !== null), 'the next poll was scheduled');
      const f = fire!;
      fire = null;
      f();
    };
    for (let i = 0; i < IDLE_TICKS_BEFORE_BACKOFF + 6; i++) await step();
    status = 200;
    await step(); // this poll may still be the busy one that was already in flight
    await step();
    assert.ok(await waitFor(() => fire !== null));
    assert.equal(delays.at(-1), 1000, `normal cadence after the spell (delays ${delays.join(',')})`);
  } finally {
    h.stop();
  }
});

test('NEG background tick: locked never shows it', async () => {
  let ticks = 0;
  const h = startLiveBookPolling({}, { intervalMs: 10, buildDeps: async () => (ticks++, null) });
  try {
    await waitFor(() => ticks >= 6);
    assert.equal(getPollRefusedReport().refused, false);
  } finally {
    h.stop();
  }
});

test('NotesInbox renders the §B notice from the store (next to the held notice)', async () => {
  const { readFileSync } = await import('node:fs');
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'components', 'notes', 'NotesInbox.tsx'), 'utf8');
  assert.ok(src.includes('return subscribePollRefused(setPollRefused);'));
  assert.ok(src.includes('pollRefusedNotice(pollRefused,'));
  assert.match(src, /data-testid="notes-poll-refused-text"[^>]*>\s*\{refusedNotice\.text\}/);
  assert.match(src, /data-testid="notes-poll-refused-hint"[^>]*>\s*\{refusedNotice\.hint\}/);
  assert.ok(src.indexOf('notes-held-notice') < src.indexOf('notes-poll-refused-notice'), 'placed right after the held notice');
});
