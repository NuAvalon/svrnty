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
import { pollLiveBookOnce, startLiveBookPolling } from '@/lib/sync/live-book-poll';
import { lockSession } from '@/lib/identity/client-store';
import {
  REFUSED_POLLS_BEFORE_NOTICE,
  __resetPollStatusForTest,
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
  assert.deepEqual(getPollRefusedReport(), { refused: true, lastOkAt: 1000 });
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
  assert.deepEqual(getPollRefusedReport(), { refused: true, lastOkAt: undefined });
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

test('copy: both §B variants verbatim + the hedged hint; nothing when not refused', () => {
  assert.equal(pollRefusedNotice({ refused: false }, fmt), null);
  assert.deepEqual(pollRefusedNotice({ refused: true, lastOkAt: 42 }, fmt), {
    text: "Couldn't check for new messages since T42. The relay refused this device's request.",
    hint: "If your device's date and time are wrong, fixing them may help.",
  });
  assert.deepEqual(pollRefusedNotice({ refused: true }, fmt), {
    text: "Couldn't check for new messages. The relay refused this device's request.",
    hint: POLL_REFUSED_COPY.hint,
  });
});

test('copy: never says caught up / up to date / no new messages / kept / safe / a count', () => {
  for (const r of [{ refused: true as const, lastOkAt: 1 }, { refused: true as const }]) {
    const n = pollRefusedNotice(r, fmt)!;
    for (const re of NEVER_SAY) {
      assert.ok(!re.test(n.text) && !re.test(n.hint), `${re} in ${n.text} / ${n.hint}`);
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
    status = 200;
    assert.ok(await waitFor(() => !getPollRefusedReport().refused), 'cleared by an answered tick');
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
