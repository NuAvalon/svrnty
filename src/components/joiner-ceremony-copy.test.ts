// Run: npx tsx --test src/components/joiner-ceremony-copy.test.ts
// The link-landing screen shows a sentence chosen by the SITE, never an error's own text (copy ledger row 231c). The sentences are pinned byte for byte here, apart from the
// module that holds them; the component is checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorTag } from '@/lib/error-tag';
import { JOINER_FAILURE_MESSAGES, joinerFailureMessage, type JoinerFailureSite } from './joiner-ceremony-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const HOSTILE = 'x"\n\u202E<b>Failed to fetch';
const SITES: ReadonlyArray<readonly [JoinerFailureSite, string]> = [
  ['openLink', "This link isn't available. It may have expired, been copied incompletely, or no longer be held by the relay. Ask the person who shared it for a new one."],
  ['addToGate', "Adding them to your Gate didn't finish. Check your Gate before you try again."],
  ['keepPiece', "The piece couldn't be saved. Try again."],
];

test('JC1 the three sentences are the copy owner\'s words, byte for byte (ledger row 231c), and are all there are', () => {
  for (const [site, s] of SITES) assert.equal(JOINER_FAILURE_MESSAGES[site], s, site);
  assert.deepEqual(Object.keys(JOINER_FAILURE_MESSAGES).sort(), SITES.map(([s]) => s).sort());
  assert.ok(Object.isFrozen(JOINER_FAILURE_MESSAGES));
});

test('JC2 any error shows the site\'s fixed sentence and none of the thrower\'s text; it is logged by class name and code only', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    for (const [site, s] of SITES) {
      const m = joinerFailureMessage(new TypeError(HOSTILE), site);
      assert.equal(m, s);
      assert.ok(!m.includes('\u202E') && !m.includes('<b>') && !m.includes('Failed to fetch'));
      assert.equal(joinerFailureMessage(HOSTILE, site), s);
      assert.equal(joinerFailureMessage(undefined, site), s);
    }
    assert.deepEqual(calls[0], ['Joiner openLink failed:', 'TypeError']);
    assert.ok(!JSON.stringify(calls).includes('Failed to fetch'), 'no thrower text in the log');
    const named = Object.assign(new Error(HOSTILE), { name: 'Evil\u202E\n"name', code: 'c\nx' });
    joinerFailureMessage(named, 'keepPiece');
    assert.deepEqual(calls.at(-1), ['Joiner keepPiece failed:', errorTag(named)]);
  } finally { console.error = real; }
});

test('JC3 THE COMPONENT: no error text is read, the three catches use the site map, and the old fallbacks are gone', () => {
  const jc = code('JoinerCeremony.tsx');
  assert.ok(!/\.message\b/.test(jc), 'no .message left in the link-landing screen');
  assert.equal(jc.split("setError(joinerFailureMessage(err, 'openLink'))").length - 1, 1);
  assert.equal(jc.split("setError(joinerFailureMessage(err, 'addToGate'))").length - 1, 1);
  assert.equal(jc.split("setShardMsg(joinerFailureMessage(err, 'keepPiece'))").length - 1, 1);
  assert.equal((jc.match(/joinerFailureMessage\(/g) ?? []).length, 3);
  assert.ok(!/Could not add them to your Gate\./.test(jc) && !/Could not accept the piece\./.test(jc), 'the old fallbacks are gone');
  assert.ok(!jc.includes("This link isn't available."), 'the link-unavailable sentence lives only in the constants file');
});
