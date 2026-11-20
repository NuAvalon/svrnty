// beacon-relay-margin: the one place that says when a row of an epoch is dead at the relay, as this device can know it.
// Run: npx tsx --test src/lib/crypto/beacon-relay-margin.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RELAY_CLOSE_MARGIN_SECONDS, relayDead, relayDeadAtMs } from './beacon-relay-margin';

const WEEK_MS = 604_800_000, GRACE_MS = 600_000, MARGIN_MS = 3_600_000;   // written out by hand, not read from the module under test
const E = 3000;

test('RLM1 the instant a row is dead = the end of its epoch + the grace window + the relay skew margin, by hand', () => {
  assert.equal(relayDeadAtMs(E), (E + 1) * WEEK_MS + GRACE_MS + MARGIN_MS);
  assert.equal(relayDeadAtMs(BigInt(E)), relayDeadAtMs(E));
  assert.equal(relayDeadAtMs(String(E)), relayDeadAtMs(E));
});

test('RLM2 both sides of the threshold: not dead one millisecond before, dead AT the instant and after', () => {
  const d = relayDeadAtMs(E);
  assert.equal(relayDead(E, d - 1), false);
  assert.equal(relayDead(E, d), true);
  assert.equal(relayDead(E, d + 1), true);
});

test('RLM3 an epoch is never dead while it is current or in the future, and an older one is dead only past its own instant', () => {
  const start = E * WEEK_MS;
  for (const t of [start, start + WEEK_MS / 2, start + WEEK_MS - 1]) assert.equal(relayDead(E, t), false, 'the current epoch');
  assert.equal(relayDead(E + 1, start + WEEK_MS / 2), false, 'a future epoch');
  assert.equal(relayDead(E - 1, start + GRACE_MS), false, 'the previous epoch, just past its grace window, is NOT dead yet: the margin is still running');
  assert.equal(relayDead(E - 1, start + GRACE_MS + MARGIN_MS), true, 'the previous epoch at its dead instant');
});

/** The value of RETENTION_MARGIN_S in the relay's source text, or null if that line is not there. */
const relayMarginIn = (text: string): number | null => {
  const m = /^RETENTION_MARGIN_S\s*=\s*(\d+)\b/m.exec(text);
  return m ? Number(m[1]) : null;
};

test('RLM4 PIN: the client margin is the relay\'s own RETENTION_MARGIN_S, read from the relay source (one value, two places, tied by this test)', () => {
  const relay = readFileSync(join(process.cwd(), 'infra/svrnty/beacon_centurion.py'), 'utf8');
  assert.equal(relayMarginIn(relay), RELAY_CLOSE_MARGIN_SECONDS);
});

test('RLM5 the pin can fail: a different value, or a missing line, is reported as a mismatch (control for RLM4)', () => {
  assert.equal(relayMarginIn('RETENTION_MARGIN_S = 7200   # x'), 7200);
  assert.notEqual(relayMarginIn('RETENTION_MARGIN_S = 7200'), RELAY_CLOSE_MARGIN_SECONDS);
  assert.equal(relayMarginIn('# RETENTION_MARGIN_S = 3600 (commented out)'), null);
  assert.equal(relayMarginIn('nothing here'), null);
});
