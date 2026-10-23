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
