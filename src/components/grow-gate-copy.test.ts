// Run: npx tsx --test src/components/grow-gate-copy.test.ts
// The Gate panel shows a sentence chosen by the SITE, never an error's own text (copy ledger row 232b). The sentences are pinned byte for byte here, apart from the module that holds
// them; the component is checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorTag } from '@/lib/error-tag';
import { ContactRefused } from '@/lib/identity/client-store';
import { CONTACT_REFUSAL_MESSAGES } from '@/lib/contacts/contact-refusal';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { GROW_GATE_FAILURE_MESSAGES, growGateFailureMessage, type GrowGateFailureSite } from './grow-gate-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const HOSTILE = 'x"\n‮<b>Failed to fetch';
const SITES: ReadonlyArray<readonly [GrowGateFailureSite, string]> = [
  ['admit', "Letting them in didn't finish. Check your Gate before you try again."],
  ['dismiss', "Dismissing didn't finish. Check your Gate before you try again."],
];
const quiet = <T,>(fn: () => T): { out: T; logged: unknown[][] } => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: fn(), logged }; } finally { console.error = real; }
};

test('GG1 the two sentences are the copy owner\'s words, byte for byte (ledger row 232b), plain ASCII, and are all there are', () => {
  for (const [site, s] of SITES) { assert.equal(GROW_GATE_FAILURE_MESSAGES[site], s, site); assert.ok(/^[\x20-\x7e]+$/.test(s), `${site} is pure ASCII`); }
  assert.deepEqual(Object.keys(GROW_GATE_FAILURE_MESSAGES).sort(), SITES.map(([s]) => s).sort());
  assert.ok(Object.isFrozen(GROW_GATE_FAILURE_MESSAGES));
});

test('GG2 any other error shows the site\'s fixed sentence and none of the thrower\'s text; it is logged ONCE, by class name and code only (the exact arguments)', () => {
  for (const [site, s] of SITES) {
    const { out, logged } = quiet(() => growGateFailureMessage(new TypeError(HOSTILE), site));
    assert.equal(out, s);
    assert.ok(!out.includes('‮') && !out.includes('<b>') && !out.includes('Failed to fetch'));
    assert.deepEqual(logged, [[`Grow gate ${site} failed:`, 'TypeError']]);
  }
  const named = Object.assign(new Error(HOSTILE), { name: 'Evil‮\n"name', code: 'c\nx' });
  const r = quiet(() => growGateFailureMessage(named, 'dismiss'));
  assert.deepEqual(r.logged, [['Grow gate dismiss failed:', errorTag(named)]]);
  for (const v of [HOSTILE, undefined, null, { message: 'x' }]) for (const [site, s] of SITES) assert.equal(quiet(() => growGateFailureMessage(v, site)).out, s);
});

test('GG3 THE COMPONENT: no error text is read, the two catches use the site map, and the old fallbacks are gone', () => {
  const gp = code('GrowGatePanel.tsx');
  assert.ok(!/\.message\b/.test(gp), 'no .message left in the Gate panel');
  assert.equal(gp.split("import { growGateFailureMessage } from './grow-gate-copy';").length - 1, 1);
  assert.equal(gp.split("setError(growGateFailureMessage(e, 'admit'));").length - 1, 1);
  assert.equal(gp.split("setError(growGateFailureMessage(e, 'dismiss'));").length - 1, 1);
  assert.equal((gp.match(/growGateFailureMessage\(/g) ?? []).length, 2);
  assert.ok(!gp.includes('Could not admit them.') && !gp.includes('Could not dismiss.'), 'the old fallbacks are gone');
  assert.ok(!gp.includes("didn't finish"), 'the sentences live only in the copy module');
});

test('GG4 a contact refusal at the ADMIT site shows ITS OWN sentence, never "didn\'t finish, try again"; nothing of the thrower\'s text; it is not logged as an unknown failure', () => {
  const REFUSALS: ReadonlyArray<readonly [string, unknown, string]> = [
    ['binding, the real ContactRefused class (a Gate arrival whose fingerprint does not match its key)', new ContactRefused('binding', 'HOSTILE ' + HOSTILE), CONTACT_REFUSAL_MESSAGES.updateBinding],
    ['verify-before-trust, the real class', new ContactRefused('verify-before-trust', HOSTILE), CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust],
    ['binding, by code', Object.assign(new Error(HOSTILE), { code: 'contact-refused', reason: 'binding' }), CONTACT_REFUSAL_MESSAGES.updateBinding],
    ['blocked, by code', Object.assign(new Error(HOSTILE), { code: 'trust-refused', reason: 'blocked' }), CONTACT_REFUSAL_MESSAGES.blocked],
  ];
  for (const [name, err, sentence] of REFUSALS) {
    const { out, logged } = quiet(() => growGateFailureMessage(err, 'admit'));
    assert.equal(out, sentence, name);
    assert.notEqual(out, GROW_GATE_FAILURE_MESSAGES.admit, name);
    assert.ok(!out.includes('HOSTILE') && !out.includes('Failed to fetch') && !out.includes('‮'), name);
    assert.deepEqual(logged, [], `${name}: a refusal is an expected stop, not logged`);
  }
});

test('GG5 only a refusal CODE counts: refusal-like text or an unknown reason gets the site sentence; the DISMISS site never maps a refusal', () => {
  for (const err of [new Error('fingerprint does not match key'), new Error(CONTACT_REFUSAL_MESSAGES.updateBinding), Object.assign(new Error('x'), { code: 'contact-refused', reason: 'novel' }), Object.assign(new Error('x'), { reason: 'binding' })]) {
    assert.equal(quiet(() => growGateFailureMessage(err, 'admit')).out, GROW_GATE_FAILURE_MESSAGES.admit);
  }
  // dismiss removes an arrival from the Gate and writes no contact: a refusal-coded error there is NOT mapped (if one ever can reach it, this fails and the site must map it)
  assert.equal(quiet(() => growGateFailureMessage(new ContactRefused('binding', 'x'), 'dismiss')).out, GROW_GATE_FAILURE_MESSAGES.dismiss);
});

test('GG6 a blocked database upgrade shows THE one sentence at BOTH sites, is not logged as an unknown failure, and is recognised by code only', () => {
  for (const [site] of SITES) {
    const a = quiet(() => growGateFailureMessage(new DbUpgradeBlocked(), site));
    assert.equal(a.out, DB_UPGRADE_BLOCKED_MESSAGE, site);
    assert.deepEqual(a.logged, []);
    assert.equal(quiet(() => growGateFailureMessage({ code: 'db-upgrade-blocked' }, site)).out, DB_UPGRADE_BLOCKED_MESSAGE, `${site} by code`);
    assert.equal(quiet(() => growGateFailureMessage(new Error(DB_UPGRADE_BLOCKED_MESSAGE), site)).out, GROW_GATE_FAILURE_MESSAGES[site], `${site}: the sentence as plain text is not a code`);
  }
});

test('GG7 the copy module imports only the three leaf modules (error-tag, contact-refusal, db-upgrade-blocked), so the Gate panel pulls in no store code through it', () => {
  const src = code('grow-gate-copy.ts');
  const specs = [...src.matchAll(/(?:^|[\s;])import\s+(?:[^'"()]*?\s+from\s+)?['"]([^'"]+)['"]/g), ...src.matchAll(/\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]/g)].map((m) => m[1]).sort();
  assert.deepEqual(specs, ['@/lib/contacts/contact-refusal', '@/lib/db-upgrade-blocked', '@/lib/error-tag']);
});
