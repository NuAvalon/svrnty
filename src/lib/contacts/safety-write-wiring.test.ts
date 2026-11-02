// Which writes take the per-contact safety lock, and that the poll yields to it. Static guards (the lock itself is tested in
// safety-write.test.ts, the deferral in consume-mailbox.test.ts, the real two-tab behaviour in e2e/contact-cas.spec.ts).
//
// Run: npx tsx --test src/lib/contacts/safety-write-wiring.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');
const noComments = (s: string) => s.replace(/^\s*\/\/.*$/gm, '');

function body(text: string, startMarker: string, endMarker: string): string {
  const a = text.indexOf(startMarker);
  assert.notEqual(a, -1, `${startMarker} not found`);
  const b = text.indexOf(endMarker, a + startMarker.length);
  return noComments(text.slice(a, b === -1 ? undefined : b));
}

test('block / unblock takes the contact lock around its write', () => {
  const ui = src('../../components/ContactManagement.tsx');
  const h = body(ui, 'const handleSetBlocked', 'const confirmTarget');
  assert.match(h, /withSafetyWrite\(contact\.id, \(\) => updateContact\(contact\.id, \(fresh\) => blockPatch\(fresh, blocked\)\)\)/);
});

test('a share-settings change (go-private among them) takes the contact lock around its write', () => {
  const ui = src('../../components/ContactManagement.tsx');
  const h = body(ui, 'const handleShareSettingsChange', '// --- Render ---');
  assert.match(h, /withSafetyWrite\(selectedContact\.id, \(\) => updateContact\(selectedContact\.id, \(fresh\) => shareSettingsPatch\(fresh, seen, next\)\)\)/);
});

test('a trust change takes the contact lock around its write', () => {
  const t = noComments(src('../trust/apply-trust-transition.ts'));
  assert.match(t, /import \{ withSafetyWrite \} from '@\/lib\/contacts\/safety-write'/);
  assert.match(t, /await withSafetyWrite\(peer\.contactId, \(\) => updateContact\(peer\.contactId,/);
});

test('the unlock privacy sweep takes the contact lock per contact it rewrites', () => {
  const s = noComments(src('../identity/client-store.ts'));
  assert.match(s, /await withSafetyWrite\(c\.id, \(\) => updateContact\(c\.id, clearOpenVisibilityIfUntrusted\)\)/);
});

test('the poll\'s contact store yields: it provides a guard built on the same lock, and the consumer returns retryable when it defers', () => {
  const poll = noComments(src('../sync/live-book-poll.ts'));
  assert.match(poll, /guard: \(id, run\) => pollWriteUnlessSafety\(id, run\)/);
  const consume = noComments(src('../sync/consume-mailbox.ts'));
  assert.match(consume, /const g = await deps\.store\.guard\(contact\.current\.id, write\);\s*if \(g\.deferred\) return \{ kind: 'retryable' \};/);
});

test('no protecting write is nested inside another lock holder (a nested request for the same contact would wait forever)', () => {
  const ui = noComments(src('../../components/ContactManagement.tsx'));
  const calls = ui.match(/withSafetyWrite\(/g) ?? [];
  assert.equal(calls.length, 2, 'exactly the two handlers in the component');
  // neither handler calls the other or applyTrustTransition
  const block = body(src('../../components/ContactManagement.tsx'), 'const handleSetBlocked', 'const confirmTarget');
  const share = body(src('../../components/ContactManagement.tsx'), 'const handleShareSettingsChange', '// --- Render ---');
  for (const h of [block, share]) assert.doesNotMatch(h, /applyTrustTransition|handleSetBlocked\(|handleShareSettingsChange\(/);
});
