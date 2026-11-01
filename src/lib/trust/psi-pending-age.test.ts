// src/lib/trust/psi-pending-age.test.ts
// The satellite lists pending sessions with created_at as an ISO-8601 string. The client turned it into a number with Number(), which is NaN for
// an ISO string, so the age check in respondToTrustSync (older than the session TTL: skip) was always false and never skipped anything. These pin
// the parser and the check end to end through the real respondToTrustSync with the satellite's shape.
//
// Run: npx tsx --test src/lib/trust/psi-pending-age.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createdAtSeconds, respondToTrustSync, type OrchestratorDeps, type PSISyncOptions } from './mutual-trust-sync';

// ── The parser ──────────────────────────────────────────────────────────────────────────────────
test('createdAtSeconds reads the satellite ISO string, with an offset or Z', () => {
  assert.equal(createdAtSeconds('2026-11-01T18:00:00+00:00'), Date.UTC(2026, 10, 1, 18, 0, 0) / 1000);
  assert.equal(createdAtSeconds('2026-11-01T18:00:00Z'), Date.UTC(2026, 10, 1, 18, 0, 0) / 1000);
  assert.equal(createdAtSeconds('2026-11-01T18:00:00.250+00:00'), Date.UTC(2026, 10, 1, 18, 0, 0, 250) / 1000);
  assert.equal(createdAtSeconds('2026-11-01T14:00:00-04:00'), Date.UTC(2026, 10, 1, 18, 0, 0) / 1000, 'an offset is honoured');
});

test('createdAtSeconds still reads seconds, as a number or a numeric string', () => {
  assert.equal(createdAtSeconds(1793556000), 1793556000);
  assert.equal(createdAtSeconds('1793556000'), 1793556000);
  assert.equal(createdAtSeconds('1793556000.5'), 1793556000.5);
});

test('createdAtSeconds turns anything it cannot read into 0, which the age check treats as expired', () => {
  for (const v of [undefined, null, '', 'not a date', 'yesterday', NaN, Infinity, {}, [], true]) {
    assert.equal(createdAtSeconds(v), 0, `${String(v)}`);
  }
});

// ── The check, through the real responder ───────────────────────────────────────────────────────
const INIT = 'fp-initiator';
const RESP = 'fp-responder';
type Pending = { session_id: string; initiator_fingerprint: string; created_at: unknown };

async function answered(created_at: unknown): Promise<boolean> {
  let responded = false;
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: { method?: string; body?: string }) => {
    const { pathname } = new URL(url);
    const ok = (obj: unknown) => ({ ok: true, status: 200, json: async () => obj, text: async () => JSON.stringify(obj) });
    if (pathname.includes('/trust/psi/pending/')) return ok({ sessions: [{ session_id: 's1', initiator_fingerprint: INIT, created_at } satisfies Pending] });
    if (/\/session\/s1\/blinded$/.test(pathname)) return ok({ blinded_set: ['QUJD'] });
    if (/\/session\/s1\/respond$/.test(pathname) && init?.method === 'POST') { responded = true; return ok({ ok: true }); }
    return { ok: false, status: 404, json: async () => ({}), text: async () => '' };
  }) as unknown as typeof fetch;
  try {
    const deps: OrchestratorDeps = {
      getTrustedPeers: async () => [{ fingerprint: INIT }],
      getKnownPeers: async () => [{ fingerprint: INIT }],
      getTrustVisiblePeers: async () => [],
      applyMutualResult: async () => {},
    };
    const options: PSISyncOptions = { satelliteUrl: 'http://sat.test', myFingerprint: RESP, signFn: () => new Uint8Array(64) };
    await respondToTrustSync(deps, options, 'know');
    return responded;
  } finally {
    globalThis.fetch = original;
  }
}

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const HOUR = 60 * 60 * 1000;

test('a fresh pending session (ISO created_at) is answered', async () => {
  assert.equal(await answered(iso(60_000)), true);
});

test('a pending session older than the TTL (ISO created_at) is skipped', async () => {
  assert.equal(await answered(iso(2 * HOUR)), false);
});

test('seconds still work: fresh answered, old skipped', async () => {
  assert.equal(await answered(Math.floor(Date.now() / 1000) - 60), true);
  assert.equal(await answered(Math.floor(Date.now() / 1000) - 2 * 3600), false);
});

test('an unreadable or missing created_at is skipped, as a missing one always was', async () => {
  assert.equal(await answered('garbage'), false);
  assert.equal(await answered(undefined), false);
});
