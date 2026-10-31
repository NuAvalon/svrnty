// src/components/trust-map-refresh-note.test.ts
// "Caught up." must only follow a poll the relay ANSWERED with a list and left nothing on (Hypatia #2396, Archie #2398/#2401/#2404, copy v2 54ba6eb0). The refusal runs the REAL pollLiveBookOnce →
// consumeInboundContactUpdates path with a signing owner and an injected 401 relay; only the deps builder is injected (it needs IndexedDB).
//
// Run: npx tsx --test src/components/trust-map-refresh-note.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKey, readKey } from 'openpgp';
import type { ConsumeDeps } from '@/lib/sync/consume-mailbox';
import { pollLiveBookOnce, pollStatusOf } from '@/lib/sync/live-book-poll';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { REFRESH_NOTE, refreshNoteAfter, refreshNoteFor } from './trust-map-refresh-note';

const here = dirname(fileURLToPath(import.meta.url));
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

function relay(status: number, body: unknown): typeof fetch {
  return async () => new Response(JSON.stringify(body), { status });
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

const refreshOver = (buildDeps: () => Promise<ConsumeDeps | null>) => refreshNoteAfter(() => pollLiveBookOnce({}, { buildDeps }));

test('NEG queue 401 (owner-auth refused) → never "Caught up."', async () => {
  assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(relay(401, { error: 'unauthorized' })) }), 'rejected');
  const note = await refreshOver(depsWith(relay(401, { error: 'unauthorized' })));
  assert.notEqual(note, REFRESH_NOTE.ok);
  assert.equal(note, REFRESH_NOTE.failed);
});

test('NEG any non-OK queue status (403, 500, 503) → never "Caught up."', async () => {
  for (const status of [403, 500, 503]) {
    assert.equal(await refreshOver(depsWith(relay(status, {}))), REFRESH_NOTE.failed, `status ${status}`);
  }
});

test('NEG locked (no deps: locked / no identity) → never "Caught up.", says unlock', async () => {
  assert.equal(await pollLiveBookOnce({}, { buildDeps: async () => null }), 'locked');
  assert.equal(await refreshOver(async () => null), REFRESH_NOTE.locked);
});

test('NEG locked through the REAL deps builder (no identity record) → locked', async () => {
  assert.equal(await pollLiveBookOnce(null), 'locked');
});

test('NEG 200 whose body is not a list ({} / null / a string / a number) → never "Caught up." (Archie #2401)', async () => {
  for (const body of [{}, null, 'x', 7, { envelopes: [] }]) {
    assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(relay(200, body)) }), 'unreadable', JSON.stringify(body));
    assert.equal(await refreshOver(depsWith(relay(200, body))), REFRESH_NOTE.failed, JSON.stringify(body));
  }
});

test('control: 200 [] (answered, nothing waiting) → "Caught up."', async () => {
  assert.equal(await pollLiveBookOnce({}, { buildDeps: depsWith(relay(200, [])) }), 'ok');
  assert.equal(await refreshOver(depsWith(relay(200, []))), REFRESH_NOTE.ok);
});

test('a thrown refresh (network) → "Could not check right now."', async () => {
  const note = await refreshNoteAfter(async () => {
    throw new TypeError('fetch failed');
  });
  assert.equal(note, REFRESH_NOTE.failed);
});

test('only the literal "ok" maps to "Caught up." (undefined / unknown are not a claim)', () => {
  assert.equal(refreshNoteFor('ok'), REFRESH_NOTE.ok);
  for (const v of ['rejected', undefined, null, '', 'OK', true, {}]) {
    assert.notEqual(refreshNoteFor(v), REFRESH_NOTE.ok, String(v));
  }
});

test('TrustMap renders the note from refreshNoteAfter, never a hard-coded "Caught up."', () => {
  const src = readFileSync(join(here, 'TrustMap.tsx'), 'utf8');
  assert.ok(src.includes('setRefreshNote(await refreshNoteAfter(onRefresh))'));
  assert.ok(!src.includes("'Caught up.'"), 'no literal "Caught up." in TrustMap');
  const page = readFileSync(join(here, '..', '..', 'app', 'page.tsx'), 'utf8');
  assert.match(page, /const status = await pollLiveBookOnce\(identity\);[\s\S]{0,80}return status;/);
});

// ── copy v2: 'checked-waiting' (the relay answered with a list, but envelopes are still on it) ──

const HYBRID_BLOB = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });

/** /queue answers with `envs`; /ack answers `ackStatus`. */
function relayWith(envs: Array<{ envelope_id: string; blob: string }>, ackStatus = 200): typeof fetch {
  return (async (url: string) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(envs), { status: 200 });
    if (String(url).includes('/ack')) return new Response('{}', { status: ackStatus });
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
}

function depsOver(over: Partial<ConsumeDeps>) {
  return async (): Promise<ConsumeDeps> => ({
    owner,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-10-31T06:00:00.000Z',
    ...over,
  });
}

test('NEG 200 + one HELD envelope (no usable kem secret) → the v2 line, never "Caught up."', async () => {
  const b = depsOver({ hybridSecretMissing: true, fetchImpl: relayWith([{ envelope_id: 'e1', blob: HYBRID_BLOB }]) });
  assert.equal(await pollLiveBookOnce({}, { buildDeps: b }), 'checked-waiting');
  const note = await refreshOver(b);
  assert.equal(note, 'Checked. Some messages are still on the relay.');
  assert.notEqual(note, REFRESH_NOTE.ok);
});

test('NEG 200 + UNRECORDED > 0 (its record could not be committed, left on the relay) → the v2 line', async () => {
  const b = depsOver({
    fetchImpl: relayWith([{ envelope_id: 'e1', blob: 'not-a-sealed-blob' }]),
    deadLetter: { record: async () => { throw new Error('idb full'); }, clear: async () => {} },
  });
  assert.equal(await pollLiveBookOnce({}, { buildDeps: b }), 'checked-waiting');
  assert.equal(await refreshOver(b), REFRESH_NOTE.checkedWaiting);
});

test('NEG 200 + an envelope whose ACK failed (still on the relay) → the v2 line, never "Caught up."', async () => {
  const b = depsOver({ fetchImpl: relayWith([{ envelope_id: 'e1', blob: 'not-a-sealed-blob' }], 500) });
  assert.equal(await pollLiveBookOnce({}, { buildDeps: b }), 'checked-waiting');
  const note = await refreshOver(b);
  assert.equal(note, REFRESH_NOTE.checkedWaiting);
  assert.ok(!/couldn't be opened/i.test(note), 'v4: an un-acked envelope may have been opened; never claim it was not');
});

test('static NEG (copy v4): the retired v2 checked-waiting text appears nowhere in src/ or app/', async () => {
  const { execFileSync } = await import('node:child_process');
  const root = join(here, '..', '..');
  let hits = '';
  try {
    hits = execFileSync('git', ['grep', '-n', '-F', "couldn't be opened on this device and are still on the relay", '--', 'src', 'app', ':!*.test.ts'], { cwd: root, encoding: 'utf8' });
  } catch {
    hits = ''; // git grep exits 1 when there are no hits
  }
  assert.equal(hits, '');
});

test('NEG the unlock cycle ended mid-poll (locked during the tick) → locked, never "Caught up."', async () => {
  const cycle = makeUnlockCycle(owner.privateKeyArmored, owner.passphrase);
  const b = depsOver({
    owner: { ...owner, cycle },
    decrypt: async () => {
      cycle.drop();
      return null;
    },
    fetchImpl: relayWith([{ envelope_id: 'e1', blob: 'x' }, { envelope_id: 'e2', blob: 'y' }]),
  });
  assert.equal(await pollLiveBookOnce({}, { buildDeps: b }), 'locked');
});

test('control: 200 + one envelope consumed and acked (nothing left) → "Caught up."', async () => {
  const b = depsOver({ fetchImpl: relayWith([{ envelope_id: 'e1', blob: 'not-a-sealed-blob' }]) });
  assert.equal(await pollLiveBookOnce({}, { buildDeps: b }), 'ok');
  assert.equal(await refreshOver(b), REFRESH_NOTE.ok);
});

test('pollStatusOf table: only a clean, fully-acked, answered list is ok', () => {
  const z = { polled: 0, acked: 0, held: 0, unrecorded: 0 };
  assert.equal(pollStatusOf(z), 'ok');
  assert.equal(pollStatusOf({ ...z, polled: 2, acked: 2 }), 'ok');
  assert.equal(pollStatusOf({ ...z, held: 1 }), 'checked-waiting');
  assert.equal(pollStatusOf({ ...z, unrecorded: 1 }), 'checked-waiting');
  assert.equal(pollStatusOf({ ...z, polled: 2, acked: 1 }), 'checked-waiting');
  assert.equal(pollStatusOf({ ...z, rejected: 401 }), 'rejected');
  assert.equal(pollStatusOf({ ...z, rejected: 401, held: 1 }), 'rejected');
  assert.equal(pollStatusOf({ ...z, rejected: 200 }), 'unreadable');
  assert.equal(pollStatusOf({ ...z, rejected: 299 }), 'unreadable');
  assert.equal(pollStatusOf({ ...z, rejected: 300 }), 'rejected');
  assert.equal(pollStatusOf({ ...z, rejected: 199 }), 'rejected');
  assert.equal(refreshNoteFor('unreadable'), REFRESH_NOTE.failed);
  assert.equal(pollStatusOf(z, true), 'locked');
  assert.equal(refreshNoteFor('checked-waiting'), REFRESH_NOTE.checkedWaiting);
});
