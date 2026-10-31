// src/lib/sync/psi-discovery-start.test.ts
// Prod ships PSI discovery OFF (Archie #2588, Flint #2583). buildPsiSyncOptions POSTs the user's fingerprint + sign pubkey to /bind BEFORE
// the satellite key pin is checked, so the gate must be consulted before it runs. Run: npx tsx --test src/lib/sync/psi-discovery-start.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { startPsiDiscovery } from './psi-discovery-start';
import { isPSIDiscoveryLive, isPQWireLive } from '../claim-gates';

const ID = { identity: { fingerprint: 'ab'.repeat(32) } };
const OPTS = { satelliteUrl: '/api/satellite', myFingerprint: 'ab'.repeat(32), signFn: () => new Uint8Array() } as never;

function withEnv<T>(value: string | undefined, fn: () => T): T {
  const prev = process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE;
  if (value === undefined) delete process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE;
  else process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE = value;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE;
    else process.env.NEXT_PUBLIC_PSI_DISCOVERY_LIVE = prev;
  }
}

test('G1 NEG: gate OFF => the options builder is never called, nothing starts, and ZERO requests are made (the /bind included)', async () => {
  const calls: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (u: unknown) => { calls.push(String(u)); return new Response('{}', { status: 200 }); }) as typeof fetch;
  let built = 0;
  let started = 0;
  try {
    const h = await startPsiDiscovery(ID, { gate: () => false, build: (async () => { built++; return OPTS; }) as never, start: (() => { started++; return { stop() {} }; }) as never });
    assert.equal(h, null);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(built, 0, 'buildPsiSyncOptions (which POSTs /bind) is not reached');
  assert.equal(started, 0);
  assert.deepEqual(calls, [], 'no request to /api/satellite');
});

test('G2 control: gate ON => it builds the options and starts the sync, returning the handle', async () => {
  let built = 0;
  const stop = () => {};
  const h = await startPsiDiscovery(ID, { gate: () => true, build: (async () => { built++; return OPTS; }) as never, start: (() => ({ stop })) as never });
  assert.equal(built, 1);
  assert.equal(h?.stop, stop);
});

test('G3 gate ON but no options (locked / bind refused) => null, nothing started', async () => {
  let started = 0;
  const h = await startPsiDiscovery(ID, { gate: () => true, build: (async () => null) as never, start: (() => { started++; return { stop() {} }; }) as never });
  assert.equal(h, null);
  assert.equal(started, 0);
});

test('G4 the caller went away while the options were being built => nothing starts (same as the old effect)', async () => {
  let started = 0;
  const h = await startPsiDiscovery(ID, { gate: () => true, build: (async () => OPTS) as never, start: (() => { started++; return { stop() {} }; }) as never, cancelled: () => true });
  assert.equal(h, null);
  assert.equal(started, 0);
});

test('G5 NEG (claim gate, Hypatia/Archie #2593): a build WITHOUT the flag has isPSIDiscoveryLive() = false AND isPQWireLive() = false', () => {
  withEnv(undefined, () => {
    assert.equal(isPSIDiscoveryLive(), false);
    assert.equal(isPQWireLive(), false, 'the "PQ-blinded discovery" claim follows the flag, not a constant');
  });
});

test('G6 only the exact string "true" turns it on (a prod build that sets something else stays dark)', () => {
  for (const v of ['', '1', 'TRUE', 'True', 'yes', 'on', ' true', 'true ', 'false']) withEnv(v, () => assert.equal(isPSIDiscoveryLive(), false, JSON.stringify(v)));
  withEnv('true', () => {
    assert.equal(isPSIDiscoveryLive(), true);
    assert.equal(isPQWireLive(), true);
  });
});

test('G7 static: ContactManagement starts PSI only through startPsiDiscovery (never buildPsiSyncOptions directly), and the Dockerfile + compose pass the arg', () => {
  const cm = readFileSync(new URL('../../components/ContactManagement.tsx', import.meta.url), 'utf8');
  assert.match(cm, /startPsiDiscovery\(identity, \{ cancelled: \(\) => stopped \}\)/);
  assert.doesNotMatch(cm, /buildPsiSyncOptions|startKnowLayerSync/);
  const root = new URL('../../../', import.meta.url);
  assert.match(readFileSync(new URL('Dockerfile', root), 'utf8'), /ARG NEXT_PUBLIC_PSI_DISCOVERY_LIVE=\nENV NEXT_PUBLIC_PSI_DISCOVERY_LIVE=\$\{NEXT_PUBLIC_PSI_DISCOVERY_LIVE\}/);
  assert.match(readFileSync(new URL('docker-compose.yml', root), 'utf8'), /NEXT_PUBLIC_PSI_DISCOVERY_LIVE: \$\{NEXT_PUBLIC_PSI_DISCOVERY_LIVE:-\}/);
});
