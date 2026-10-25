// NEG-FIRST wiring contract for the Notes inbox reload (D-N8 / task #700). Run: npx --no-install tsx --test src/components/notes/notes-inbox-reload-wiring.test.ts
//
// There is no DOM test environment in this repo, so the behaviour is pinned in two halves:
//   1. src/lib/notes/reload-gate.test.ts proves the GATE (a burst of N arrivals -> one run per window, the last arrival always served, bounded staleness).
//   2. THIS file proves NotesInbox.tsx actually USES it, by reading the real source: every reload trigger goes through gate.request(), nothing in the
//      trigger effect calls loadThreads / loadNotes directly, and the selection effect is guarded so it cannot fire a second ungated decrypt per reload.
// It FAILS on dev 374d31e (where the arrival callback calls loadThreads()/loadNotes() directly, once per arrival) and passes with the change.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const src = readFileSync(join(__dirname, 'NotesInbox.tsx'), 'utf8');

/** The trigger effect: from the gate's creation to its disposal. */
function triggerEffect(): string {
  const a = src.indexOf('createReloadGate(');
  const b = src.indexOf('gate.dispose();');
  assert.ok(a > 0 && b > a, 'NotesInbox.tsx builds a gate and disposes it');
  return src.slice(a, b + 'gate.dispose();'.length);
}

test('NotesInbox imports the reload gate and the thread-load guard', () => {
  assert.match(src, /import \{ createReloadGate \} from '@\/lib\/notes\/reload-gate';/);
  assert.match(src, /import \{ createThreadLoadGuard \} from '@\/lib\/notes\/thread-load-guard';/);
});

test('a note ARRIVAL only asks the gate: the callback is exactly gate.request(), never loadThreads / loadNotes (dev reloaded once PER arrival)', () => {
  const m = /subscribeNoteArrivals\(\(\) =>\s*([^;]*?)\);/.exec(src);
  assert.ok(m, 'there is a subscribeNoteArrivals call');
  assert.equal(m![1].trim(), 'gate.request()');
  // The block form is the dev shape: `subscribeNoteArrivals(() => { void loadThreads(); void loadNotes(...); })`.
  assert.doesNotMatch(src, /subscribeNoteArrivals\(\(\) => \{[^}]*load(Threads|Notes)/);
});

test('the periodic re-read and the tab-visible handler ALSO go through the gate (all three triggers share one run budget)', () => {
  const eff = triggerEffect();
  assert.match(eff, /window\.setInterval\(\(\) => gate\.request\(\), STORE_REREAD_MS\)/);
  assert.match(eff, /visibilityState === 'visible'\) gate\.request\(\)/);
  assert.doesNotMatch(src, /const tick = \(\) =>/, 'the old ungated tick is gone');
});

test('the ONLY reload work in the trigger effect is the gate task: loadThreads() and loadNotes( each appear exactly once, inside it', () => {
  const eff = triggerEffect();
  assert.equal((eff.match(/loadThreads\(\)/g) ?? []).length, 1);
  assert.equal((eff.match(/loadNotes\(/g) ?? []).length, 1);
  assert.match(eff, /createReloadGate\(async \(\) => \{\s*await Promise\.all\(\[loadThreads\(\), loadNotes\(activeThreadId\)\]\);\s*\}, ARRIVAL_RELOAD_WINDOW_MS\)/);
});

test('the window is 250 ms and the effect disposes the gate and unsubscribes on cleanup', () => {
  assert.match(src, /const ARRIVAL_RELOAD_WINDOW_MS = 250;/);
  const eff = triggerEffect();
  assert.match(eff, /unsubscribe\(\);/);
  assert.match(eff, /window\.clearInterval\(id\);/);
});

test('the selection effect is guarded: it loads only when the target thread CHANGED, so a new `threads` array identity per reload cannot fire a second ungated decrypt', () => {
  const m = /setActiveThreadId\(nextId\);([\s\S]*?)\}, \[selectedFp, threads, loadNotes\]\);/.exec(src);
  assert.ok(m, 'the selection effect exists');
  assert.match(m![1], /if \(!threadLoadGuard\.current\.shouldLoad\(nextId\)\) return;/);
  assert.match(m![1], /void loadNotes\(nextId\);/);
  assert.ok(m![1].indexOf('shouldLoad') < m![1].indexOf('void loadNotes'), 'the guard runs BEFORE the load');
  assert.match(src, /const threadLoadGuard = useRef\(createThreadLoadGuard\(\)\);/);
});
