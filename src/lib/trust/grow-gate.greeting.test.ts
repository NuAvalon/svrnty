// Unit tests for the pre-gate greeting's Gate-side handling (Flint security spec reqs 3-4):
// clampGreeting (sanitize + cap, allow \n) and arrivalFromPendingJoiner copying the SIGNED greeting
// onto the GateArrival write-once. Pure logic — no crypto, no store.
// Run: npx tsx --test src/lib/trust/grow-gate.greeting.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clampGreeting, arrivalFromPendingJoiner } from './grow-gate';
import { GREETING_MAX_CHARS, type PendingJoiner } from './joiner-response';

test('clampGreeting strips control + C1 + DEL but ALLOWS \\n', () => {
  assert.equal(clampGreeting('hi\x00\x07there'), 'hithere', 'strips NUL + BEL');
  assert.equal(clampGreeting('line1\nline2'), 'line1\nline2', 'newline is allowed (greeting may wrap)');
  assert.equal(clampGreeting('tab\there'), 'tabhere', 'tab (0x09) stripped — only \\n allowed below 0x20');
  assert.equal(clampGreeting('c1\x85byte'), 'c1byte', 'strips C1 (0x85)');
  assert.equal(clampGreeting('del\x7fbyte'), 'delbyte', 'strips DEL (0x7f)');
});

test('clampGreeting trims and caps at GREETING_MAX_CHARS', () => {
  assert.equal(clampGreeting('  spaced out  '), 'spaced out', 'trimmed');
  assert.equal(clampGreeting('a'.repeat(GREETING_MAX_CHARS + 200)).length, GREETING_MAX_CHARS, 'capped');
  assert.equal(clampGreeting(42 as unknown as string), '', 'non-string → empty');
  assert.equal(clampGreeting(undefined), '', 'undefined → empty');
});

const basePj = (greeting?: string): PendingJoiner => ({
  fingerprint: 'ABCDEF0123', epoch: 0, publicKeyArmored: 'PUBKEY',
  displayName: 'Nina', inviteNonce: 'GROW-CODE', ts: '2026-10-23T10:00:00.000Z',
  ...(greeting !== undefined ? { greeting } : {}),
});

test('arrivalFromPendingJoiner copies the greeting, sanitized (clampGreeting on the write path)', () => {
  const arrival = arrivalFromPendingJoiner(basePj('hi\x00\x07\nthere, I\'m Nina'), 'remote');
  assert.equal(arrival.greeting, 'hi\nthere, I\'m Nina', 'greeting clamped onto the arrival');
  assert.equal(arrival.fingerprint, 'ABCDEF0123');
});

test('arrivalFromPendingJoiner omits greeting when the joiner sent none (and when it clamps to empty)', () => {
  assert.equal('greeting' in arrivalFromPendingJoiner(basePj(), 'remote'), false, 'absent → omitted on arrival');
  assert.equal('greeting' in arrivalFromPendingJoiner(basePj('\x00\x07'), 'remote'), false, 'control-only → clamps empty → omitted');
});

// ── PERSISTENCE chokepoint (regression for the greeting being dropped by the store's field whitelist) ──
// enqueueGateArrival and every load run arrivals through normalizeArrival, which rebuilds the object from
// an explicit field list. The earlier tests stopped at arrivalFromPendingJoiner, so a greeting missing from
// that list was invisible: it was set at receive, then silently dropped before the Gate could show it.
import { normalizeArrival } from '../identity/client-store';

test('greeting SURVIVES the persistence whitelist (receive -> normalizeArrival round trip)', () => {
  const arrival = arrivalFromPendingJoiner(basePj("hi, it's Nina\nfrom the conference"), 'remote');
  const stored = normalizeArrival(JSON.parse(JSON.stringify(arrival))); // what save+load does
  assert.ok(stored, 'arrival must normalize');
  assert.equal(stored!.greeting, "hi, it's Nina\nfrom the conference");
});

test('persistence re-caps an oversized greeting and omits an empty one', () => {
  const base = arrivalFromPendingJoiner(basePj('x'), 'remote');
  const big = normalizeArrival({ ...base, greeting: 'y'.repeat(GREETING_MAX_CHARS + 300) });
  assert.equal(big!.greeting!.length, GREETING_MAX_CHARS);
  assert.equal('greeting' in normalizeArrival({ ...base, greeting: '' })!, false);
  assert.equal('greeting' in normalizeArrival({ ...base, greeting: 42 })!, false, 'non-string dropped');
});
