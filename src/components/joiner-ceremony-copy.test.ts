// Run: npx tsx --test src/components/joiner-ceremony-copy.test.ts
// The link-landing screen shows a sentence chosen by the SITE, never an error's own text (copy ledger row 231c). The sentences are pinned byte for byte here, apart from the
// module that holds them; the component is checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorTag } from '@/lib/error-tag';
import { ContactUpdateRefused } from '@/lib/identity/contact-identity';
import { CONTACT_REFUSAL_MESSAGES } from '@/lib/contacts/contact-refusal';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
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

// The refusals the contact store makes on purpose, as the add-to-Gate site can receive them. Recognised by code and reason, so look-alikes are built as plain objects too.
const REFUSALS: ReadonlyArray<readonly [string, unknown, string]> = [
  ['update refused: binding (a real ContactUpdateRefused)', new ContactUpdateRefused('binding', 'HOSTILE ' + HOSTILE), CONTACT_REFUSAL_MESSAGES.updateBinding],
  ['update refused: verify-before-trust (real class)', new ContactUpdateRefused('verify-before-trust', HOSTILE), CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust],
  ['update refused: identity-immutable (real class)', new ContactUpdateRefused('identity-immutable', HOSTILE), CONTACT_REFUSAL_MESSAGES.identityImmutable],
  ['contact refused: binding, by code', Object.assign(new Error(HOSTILE), { code: 'contact-refused', reason: 'binding' }), CONTACT_REFUSAL_MESSAGES.updateBinding],
  ['trust refused: blocked, by code', Object.assign(new Error(HOSTILE), { code: 'trust-refused', reason: 'blocked' }), CONTACT_REFUSAL_MESSAGES.blocked],
];

test('JC4 a contact refusal at the add-to-Gate site shows ITS OWN sentence, never the site\'s "didn\'t finish, try again"; nothing of the thrower\'s text', () => {
  const real = console.error; console.error = () => { /* a refusal is not logged as an unknown failure */ };
  try {
    for (const [name, err, sentence] of REFUSALS) {
      const m = joinerFailureMessage(err, 'addToGate');
      assert.equal(m, sentence, name);
      assert.notEqual(m, JOINER_FAILURE_MESSAGES.addToGate, name);
      assert.ok(!m.includes('HOSTILE') && !m.includes('Failed to fetch') && !m.includes('\u202E'), name);
    }
  } finally { console.error = real; }
});

test('JC5 only a refusal CODE counts: a plain Error with refusal-like text, or an unknown reason, gets the site sentence; the other two sites never map a refusal', () => {
  const real = console.error; console.error = () => {};
  try {
    for (const err of [new Error('fingerprint does not match key'), new Error(CONTACT_REFUSAL_MESSAGES.updateBinding), Object.assign(new Error('x'), { code: 'contact-update-refused', reason: 'novel' }), Object.assign(new Error('x'), { code: 'other', reason: 'binding' })]) {
      assert.equal(joinerFailureMessage(err, 'addToGate'), JOINER_FAILURE_MESSAGES.addToGate);
    }
    // openLink and keepPiece never reach the contact store: a refusal-coded error there is NOT mapped (if one ever can reach them, this fails and the site must map it).
    for (const site of ['openLink', 'keepPiece'] as const) {
      assert.equal(joinerFailureMessage(new ContactUpdateRefused('binding', 'x'), site), JOINER_FAILURE_MESSAGES[site]);
    }
  } finally { console.error = real; }
});

test('JC6 a refusal is not logged as an unknown failure (it is an expected stop), and an unknown error still is, by tag only', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    joinerFailureMessage(new ContactUpdateRefused('binding', 'x'), 'addToGate');
    assert.equal(calls.length, 0);
    joinerFailureMessage(new TypeError(HOSTILE), 'addToGate');
    assert.deepEqual(calls, [['Joiner addToGate failed:', 'TypeError']]);
  } finally { console.error = real; }
});

test('JC7 THE LEAF STAYS LIGHT: the joiner copy module imports only the three leaf modules (error-tag, contact-refusal, db-upgrade-blocked), so the public page loads no store code', () => {
  const src = code('joiner-ceremony-copy.ts');
  // every way a module can be pulled in: `import x from 'm'`, a bare `import 'm'` (side effect), `import('m')`, `require('m')`
  const specs = [...src.matchAll(/(?:^|[\s;])import\s+(?:[^'"()]*?\s+from\s+)?['"]([^'"]+)['"]/g), ...src.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]/g)].map((m) => m[1]).sort();
  assert.deepEqual(specs, ['@/lib/contacts/contact-refusal', '@/lib/db-upgrade-blocked', '@/lib/error-tag']);
});

test('JC8 a blocked database upgrade shows THE one sentence at EVERY site (any of them can touch the store), is not logged as an unknown failure, and is recognised by code only', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    for (const [site] of SITES) {
      assert.equal(joinerFailureMessage(new DbUpgradeBlocked(), site), DB_UPGRADE_BLOCKED_MESSAGE, site);
      assert.equal(joinerFailureMessage({ code: 'db-upgrade-blocked' }, site), DB_UPGRADE_BLOCKED_MESSAGE, `${site} by code`);
      assert.notEqual(DB_UPGRADE_BLOCKED_MESSAGE, JOINER_FAILURE_MESSAGES[site]);
      assert.equal(joinerFailureMessage(new Error('svrnty database is upgrading — close other svrnty tabs and reload'), site), JOINER_FAILURE_MESSAGES[site], `${site}: the old plain text is not a code`);
    }
    assert.equal(calls.filter((c) => String(c[0]).includes('Joiner')).length, SITES.length, 'only the three plain-text errors were logged, by tag');
  } finally { console.error = real; }
});
