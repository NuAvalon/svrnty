// The switch order for per-epoch PSI elements: F1 receive, then F2 send, then F3 use. Run: npx tsx --test src/lib/trust/psi-epoch-flags.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assertFlagOrder, checkFlagOrder, FlagOrderError, PSI_EPOCH_FLAGS_OFF, type PsiEpochFlags } from './psi-epoch-flags';

const f = (receive: boolean, send: boolean, use: boolean): PsiEpochFlags => ({ receive, send, use });

test('every switch is OFF by default, and the default cannot be changed in place', () => {
  assert.deepEqual(PSI_EPOCH_FLAGS_OFF, { receive: false, send: false, use: false });
  assert.ok(Object.isFrozen(PSI_EPOCH_FLAGS_OFF));
  assert.deepEqual(checkFlagOrder({}), { ok: true }, 'a caller that says nothing has everything off');
  assert.doesNotThrow(() => assertFlagOrder(PSI_EPOCH_FLAGS_OFF));
});

test('the four orders that are allowed: all off, F1, F1+F2, F1+F2+F3', () => {
  for (const flags of [f(false, false, false), f(true, false, false), f(true, true, false), f(true, true, true)]) {
    assert.deepEqual(checkFlagOrder(flags), { ok: true });
    assert.doesNotThrow(() => assertFlagOrder(flags));
  }
});

test('F2 without F1 is refused (alone, or with F3)', () => {
  for (const flags of [f(false, true, false), f(false, true, true)]) {
    const c = checkFlagOrder(flags);
    assert.equal(c.ok, false);
    assert.equal(c.ok === false && c.violation, 'send-needs-receive');
    assert.throws(() => assertFlagOrder(flags), (e: unknown) => e instanceof FlagOrderError && e.violation === 'send-needs-receive');
  }
});

test('F3 without F2 is refused (alone, or with F1)', () => {
  for (const flags of [f(false, false, true), f(true, false, true)]) {
    const c = checkFlagOrder(flags);
    assert.equal(c.ok, false);
    assert.equal(c.ok === false && c.violation, 'use-needs-send');
    assert.throws(() => assertFlagOrder(flags), (e: unknown) => e instanceof FlagOrderError && e.violation === 'use-needs-send');
  }
});

test('a switch that is not exactly true counts as off (a string, a number, undefined)', () => {
  assert.deepEqual(checkFlagOrder({ receive: 'true' as unknown as boolean, send: true }), { ok: false, violation: 'send-needs-receive', detail: 'F2 (send epoch notes) is on but F1 (receive and store them) is off' });
  assert.deepEqual(checkFlagOrder({ receive: true, send: 1 as unknown as boolean, use: true }), { ok: false, violation: 'use-needs-send', detail: 'F3 (match on epoch elements) is on but F2 (send epoch notes) is off' });
  assert.deepEqual(checkFlagOrder({ receive: undefined, send: undefined, use: undefined }), { ok: true });
});

test('the refusal says which switches, in words', () => {
  assert.match(String((checkFlagOrder(f(false, true, false)) as { detail: string }).detail), /F2.*F1/);
  assert.match(String((checkFlagOrder(f(true, false, true)) as { detail: string }).detail), /F3.*F2/);
});
