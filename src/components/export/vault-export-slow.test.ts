// src/components/export/vault-export-slow.test.ts
// Gate: the "still encrypting" line (copy ledger rows 306, 306e and 308) is the reviewed sentence, appears only when the work is STILL running 5 s in, is removed the moment the export finishes or fails, and
// never carries a percentage, bar, timer or estimate.
//   · COPY: the sentence is pinned by length and sha256 (ASCII only); it has no digit, no percent sign and no "about".
//   · TIMING: a fake-timer run of the real helper (shown only after the delay; a stop before it means it never shows; a stop after it hides it; stopping twice is harmless).
//   · DIALOG: source guards: the clock starts when Export is pressed, stops in the `finally` (success AND failure), and the line renders only through the constant in an always-present
//     polite live region; the dialog has no progress bar element.
// Run: npx tsx --test src/components/export/vault-export-slow.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { VAULT_EXPORT_SLOW, VAULT_EXPORT_SLOW_AFTER_MS } from '@/components/export/vault-export-copy';
import { startSlowNotice, type Timers } from '@/components/export/slow-notice';

const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16);

test('COPY: the sentence is exactly the reviewed text (146 chars, ASCII), and it promises no number', () => {
  assert.equal(VAULT_EXPORT_SLOW.length, 146);
  assert.equal(sha(VAULT_EXPORT_SLOW), 'abad9bfa01ad7148');
  assert.ok([...VAULT_EXPORT_SLOW].every((c) => c.charCodeAt(0) < 128), 'ASCII only');
  assert.doesNotMatch(VAULT_EXPORT_SLOW, /\d|%|\babout\b/i, 'no digit, no percent, no "about N"');
  assert.equal(VAULT_EXPORT_SLOW_AFTER_MS, 5000, 'the line waits 5 s so a fast export never flashes it');
});

/** Fake timers: nothing runs until `advance`. */
function fakeTimers() {
  let now = 0, next = 1;
  const pending = new Map<number, { at: number; fn: () => void }>();
  const timers: Timers = {
    set(fn, ms) { const id = next++; pending.set(id, { at: now + ms, fn }); return id; },
    clear(id) { pending.delete(id as number); },
  };
  return {
    timers,
    pendingCount: () => pending.size,
    advance(ms: number) {
      now += ms;
      for (const [id, t] of [...pending]) if (t.at <= now) { pending.delete(id); t.fn(); }
    },
  };
}

test('TIMING: the line is not shown before the delay and is shown after it', () => {
  const f = fakeTimers(); const log: boolean[] = [];
  startSlowNotice((on) => log.push(on), 5000, f.timers);
  f.advance(4999);
  assert.deepEqual(log, [], 'nothing before 5 s');
  f.advance(1);
  assert.deepEqual(log, [true], 'shown at 5 s');
});

test('TIMING: an export that finishes before the delay never shows the line (stopping cancels the pending show)', () => {
  const f = fakeTimers(); const log: boolean[] = [];
  const stop = startSlowNotice((on) => log.push(on), 5000, f.timers);
  f.advance(2700); // a fast device
  stop();
  f.advance(10_000);
  assert.deepEqual(log, [false], 'only the hide, never a show');
  assert.equal(f.pendingCount(), 0, 'no timer left behind');
});

test('TIMING: stopping after the line is up hides it, and stopping twice is harmless', () => {
  const f = fakeTimers(); const log: boolean[] = [];
  const stop = startSlowNotice((on) => log.push(on), 5000, f.timers);
  f.advance(6000);
  stop();
  stop();
  assert.deepEqual(log, [true, false], 'shown once, hidden once');
});

// ---- the dialog: source guards (comments are not code) ----
const dialog = readFileSync(join(process.cwd(), 'src', 'components', 'export', 'VaultExportDialog.tsx'), 'utf8')
  .split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

test('DIALOG: the clock starts when Export is pressed and stops in the finally, so success AND failure remove the line', () => {
  assert.equal((dialog.match(/startSlowNotice\(setSlow, VAULT_EXPORT_SLOW_AFTER_MS\)/g) ?? []).length, 1, 'one start, with the reviewed delay');
  const start = dialog.indexOf('const handleExport = async');
  const fin = dialog.indexOf('} finally {', start);
  const end = dialog.indexOf('\n  };', fin);
  assert.ok(start > 0 && fin > start && end > fin, 'handleExport and its finally are found');
  assert.match(dialog.slice(fin, end), /stopSlow\(\);/, 'the stop is inside the finally');
  assert.ok(dialog.indexOf('startSlowNotice(', start) > dialog.indexOf('setLoading(true);', start), 'the clock starts after loading begins');
  assert.match(dialog, /setSlow\(false\);\n\s*setError\(null\);\n\s*setBeaconUnreadable/, 'reset() also clears the line');
});

test('DIALOG: the line renders only through the constant, in an always-present polite live region, and the dialog shows no progress bar', () => {
  assert.doesNotMatch(dialog, /Still encrypting/, 'the sentence is not written into the dialog; it comes from the reviewed constant');
  assert.match(dialog, /<p data-testid="vault-export-slow" aria-live="polite"[^>]*>\s*\{slow \? VAULT_EXPORT_SLOW : ''\}/, 'one region, polite, always in the DOM, text only while slow');
  assert.doesNotMatch(dialog, /<progress|role="progressbar"|progressbar/i, 'no progress bar element');
});
