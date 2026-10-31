// src/components/trust-map-refresh-note.test.ts
// "Caught up." must only follow a poll the relay ANSWERED (Hypatia #2396, Archie #2398). The refusal runs the REAL pollLiveBookOnce →
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
import { pollLiveBookOnce } from '@/lib/sync/live-book-poll';
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
