// The activity ember must be ANNOUNCED, not just painted (Hypatia #915). Two cases found at 99e7e3a:
//   Galaxy: no aria-label on the trigger, so the name was text + the ember's aria-label => "Galaxy Galaxy has new activity".
//   Chat:   the trigger carried a STATIC aria-label that OVERRIDES its content, so the ember's "New messages" was never announced at all.
// Now the dot is decorative (aria-hidden) and each trigger carries an aria-label ONLY while lit: "Galaxy, new activity" / "Chat, new messages";
// plain "Galaxy" / "Chat" (no aria-label) otherwise. (A visually-hidden span inside the tab gave "Chat , new messages": Chromium inserts a space
// before an absolutely-positioned child.) Pinned here at the markup + source level; the lit Chat name is proven in a real browser in
// e2e/notes-roundtrip.spec.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { TabActivityEmber } from './TabActivityEmber';

const html = (on: boolean, label = 'new messages') => renderToStaticMarkup(createElement(TabActivityEmber, { on, label, testId: 'tab-x-activity' }));

test('unlit: renders nothing at all (no dot, no hidden text)', () => {
  assert.equal(html(false), '');
});

test('lit: the dot is decorative (aria-hidden), carries NO aria-label and no hidden text node of its own', () => {
  const out = html(true);
  assert.match(out, /data-testid="tab-x-activity"/);
  assert.match(out, /aria-hidden="true"/);
  assert.doesNotMatch(out, /aria-label/);
  assert.doesNotMatch(out, /sr-only/);
});

test('app/page.tsx: the Galaxy and Chat triggers have NO static aria-label; each has one only while lit, with the exact spoken name', () => {
  const src = readFileSync(join(__dirname, '..', '..', '..', 'app', 'page.tsx'), 'utf8');
  const want: Record<string, RegExp> = {
    'trust-map': /aria-label=\{galaxyActivity \? 'Galaxy, new activity' : undefined\}/,
    notes: /aria-label=\{notesActivity \? `\$\{BETA_COPY\.tabLabel\}, new messages` : undefined\}/,
  };
  for (const [value, re] of Object.entries(want)) {
    const trigger = new RegExp(`<TabsTrigger\\s+value="${value}"([\\s\\S]*?)>`).exec(src);
    assert.ok(trigger, `the ${value} trigger exists`);
    const attrs = trigger![1];
    assert.match(attrs, re, `${value}: conditional aria-label with the exact lit name`);
    // Every aria-label on this trigger is the conditional one: none is a static string / static expression.
    const labels = attrs.match(/aria-label=(\{[^}]*\}|"[^"]*")/g) ?? [];
    assert.equal(labels.length, 1, `${value}: exactly one aria-label`);
    assert.match(labels[0], /Activity \?/, `${value}: the aria-label is conditional on activity`);
  }
  assert.match(src, /label="new activity"/);
  assert.match(src, /label="new messages"/);
  assert.doesNotMatch(src, /label="Galaxy has new activity"|label="New messages"/);
});
