// Run: npx tsx --test src/lib/db-upgrade-blocked.test.ts
// "Another tab is holding the database" (copy ledger row 245): the coded error, its one sentence, and the guard that EVERY helper which turns a failure into a sentence
// asks for it first. A helper that forgets would show its generic "didn't finish, try again" for a failure where a reload alone loops, so the helper list is
// scanned from the source, not typed here, and a new helper fails this file until it is added to the table.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked, dbUpgradeBlockedMessage, isDbUpgradeBlocked } from './db-upgrade-blocked';
import { CONTACT_FAILURE_MESSAGES, contactFailureMessage, type ContactFailureSite } from '../components/contact-management-copy';
import { FRONTEND_FAILURE_MESSAGES, frontendFailureMessage, type FrontendFailureSite } from '../components/soverentity-frontend-copy';
import { JOINER_FAILURE_MESSAGES, joinerFailureMessage, type JoinerFailureSite } from '../components/joiner-ceremony-copy';
import { GROW_GATE_FAILURE_MESSAGES, growGateFailureMessage, type GrowGateFailureSite } from '../components/grow-gate-copy';
import { exportFailureMessage, keyExportFailureMessage, plainPasteFailureMessage } from './contacts/contact-io-errors';
import { vaultExportFailureMessage } from '../components/export/vault-export-copy';
import { sealedFailureMessage } from './contacts/sealed-book-import';
import { classifyRestoreFailure } from './identity/restore-errors';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(HERE, '..');
const SENTENCE = 'Another svrnty tab is holding up an update. Close your other svrnty tabs, then reload this page.';
const OLD_TEXT = 'svrnty database is upgrading — close other svrnty tabs and reload';
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const sources = (): Array<{ rel: string; text: string }> => {
  const out: Array<{ rel: string; text: string }> = [];
  const walk = (dir: string): void => {
    for (const n of readdirSync(dir)) {
      const p = join(dir, n);
      if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p); }
      else if (/\.(ts|tsx)$/.test(n) && !/\.(test|spec|selftest)\.tsx?$/.test(n)) out.push({ rel: p.slice(SRC.length + 1), text: stripComments(readFileSync(p, 'utf8')) });
    }
  };
  walk(SRC);
  return out;
};

test('DU1 the sentence is the copy owner\'s words byte for byte (row 245b); the error is coded and carries it; recognised by CODE only', () => {
  assert.equal(DB_UPGRADE_BLOCKED_MESSAGE, SENTENCE);
  const e = new DbUpgradeBlocked();
  assert.equal(e.code, 'db-upgrade-blocked');
  assert.equal(e.name, 'DbUpgradeBlocked');
  assert.equal(e.message, SENTENCE, 'a catch not yet converted that still reads err.message shows the same words');
  assert.ok(e instanceof Error);
  for (const yes of [e, { code: 'db-upgrade-blocked' }, Object.assign(new Error('x'), { code: 'db-upgrade-blocked' })]) {
    assert.equal(isDbUpgradeBlocked(yes), true);
    assert.equal(dbUpgradeBlockedMessage(yes), SENTENCE);
  }
  for (const no of [new Error(OLD_TEXT), new Error(SENTENCE), { code: 'other' }, { code: 'DB-UPGRADE-BLOCKED' }, 'db-upgrade-blocked', null, undefined, 0, {}]) {
    assert.equal(isDbUpgradeBlocked(no), false, String(no));
    assert.equal(dbUpgradeBlockedMessage(no), null);
  }
});

test('DU2 the leaf has no imports in any form, so a public page can use it without loading store code', () => {
  const text = stripComments(readFileSync(join(HERE, 'db-upgrade-blocked.ts'), 'utf8'));
  assert.ok(!/(?:^|[\s;])import\s+(?:[^'"()]*?\s+from\s+)?['"]/m.test(text), 'no import statement');
  assert.ok(!/\b(?:import|require)\s*\(/.test(text), 'no dynamic import or require');
});

// Every helper that turns a failure into a sentence, with a way to read its sentence. Names are checked against the source in DU4.
const HELPERS: ReadonlyArray<readonly [string, (e: unknown) => string]> = [
  ...(Object.keys(CONTACT_FAILURE_MESSAGES) as ContactFailureSite[]).map((site) => [`contactFailureMessage(${site})`, (e: unknown) => contactFailureMessage(e, site)] as const),
  ...(Object.keys(FRONTEND_FAILURE_MESSAGES) as FrontendFailureSite[]).map((site) => [`frontendFailureMessage(${site})`, (e: unknown) => frontendFailureMessage(e, site)] as const),
  ...(Object.keys(JOINER_FAILURE_MESSAGES) as JoinerFailureSite[]).map((site) => [`joinerFailureMessage(${site})`, (e: unknown) => joinerFailureMessage(e, site)] as const),
  ...(Object.keys(GROW_GATE_FAILURE_MESSAGES) as GrowGateFailureSite[]).map((site) => [`growGateFailureMessage(${site})`, (e: unknown) => growGateFailureMessage(e, site)] as const),
  ['exportFailureMessage', exportFailureMessage],
  ['keyExportFailureMessage', keyExportFailureMessage],
  ['plainPasteFailureMessage', plainPasteFailureMessage],
  ['sealedFailureMessage', sealedFailureMessage],
  ['vaultExportFailureMessage', vaultExportFailureMessage],
  ['classifyRestoreFailure', (e) => classifyRestoreFailure(e).message],
  ['classifyRestoreFailure(v4Vault)', (e) => classifyRestoreFailure(e, { v4Vault: true }).message],
];
const HELPER_NAMES = ['classifyRestoreFailure', 'contactFailureMessage', 'exportFailureMessage', 'frontendFailureMessage', 'growGateFailureMessage', 'joinerFailureMessage', 'keyExportFailureMessage', 'plainPasteFailureMessage', 'sealedFailureMessage', 'vaultExportFailureMessage'];

test('DU3 every helper shows THE sentence for the coded error (and a look-alike), never its generic one, and does not log it as an unknown failure', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    for (const [name, fn] of HELPERS) {
      const generic = fn(new Error('plain failure'));
      assert.notEqual(generic, SENTENCE, `${name}: the generic sentence must differ from the blocked one`);
      calls.length = 0;
      assert.equal(fn(new DbUpgradeBlocked()), SENTENCE, name);
      assert.equal(fn({ code: 'db-upgrade-blocked' }), SENTENCE, `${name} by code`);
      assert.equal(calls.length, 0, `${name}: an expected stop is not logged as an unknown failure`);
      // not by text: the OLD plain message is just a failure now
      assert.equal(fn(new Error(OLD_TEXT)), generic, `${name}: the old text is not a code`);
    }
    assert.equal(classifyRestoreFailure(new DbUpgradeBlocked()).code, 'db-upgrade-blocked', 'a screen that only logs on code "unknown" does not log it');
  } finally { console.error = real; }
});

test('DU4 THE HELPER LIST IS SCANNED: every exported *FailureMessage function and classifyRestoreFailure in the source is in the table above, and the table names none that is gone', () => {
  const found = new Set<string>();
  for (const { text } of sources()) for (const m of text.matchAll(/^export (?:async )?function ([A-Za-z]*FailureMessage|classifyRestoreFailure)\(/gm)) found.add(m[1]);
  assert.deepEqual([...found].sort(), [...HELPER_NAMES].sort(), 'a new failure-message helper must ask dbUpgradeBlockedMessage first and be added to HELPERS and HELPER_NAMES');
  for (const n of HELPER_NAMES) assert.ok(HELPERS.some(([h]) => h === n || h.startsWith(`${n}(`)), `${n} is named in HELPER_NAMES but has no entry in HELPERS, so DU3 would never run it`);
});

test('DU5 EVERY indexedDB.open( call site in the source has an onblocked that rejects with the coded error (paired by variable), and the scan is not vacuous', () => {
  const sites: Array<{ rel: string; variable: string }> = [];
  for (const { rel, text } of sources()) {
    const opens = [...text.matchAll(/\b(?:const|let|var)\s+(\w+)\s*=\s*indexedDB\.open\(/g)];
    const bare = (text.match(/indexedDB\.open\(/g) ?? []).length;
    assert.equal(opens.length, bare, `${rel}: every indexedDB.open( must be assigned to a variable so its handlers can be checked`);
    for (const m of opens) sites.push({ rel, variable: m[1] });
    for (const m of opens) {
      const handler = new RegExp(`\\b${m[1]}\\.onblocked = \\(\\) => reject\\(new DbUpgradeBlocked\\(\\)\\);`, 'g');
      const count = (text.match(handler) ?? []).length;
      const sameVar = opens.filter((o) => o[1] === m[1]).length;
      assert.equal(count, sameVar, `${rel}: the opener "${m[1]}" needs ${m[1]}.onblocked = () => reject(new DbUpgradeBlocked()); (found ${count} for ${sameVar} site(s))`);
    }
    if (opens.length > 0) assert.ok(!text.includes('is upgrading'), `${rel}: the old plain message is gone`);
  }
  // not vacuous: the three known openers are found (a scan that finds none would pass for any code)
  assert.deepEqual([...new Set(sites.map((x) => x.rel))].sort(), ['components/biometric/biometric-seam.ts', 'lib/identity/client-store.ts', 'lib/messaging/store.ts']);
  // and no onblocked handler exists in a file that has no opener to pair it with
  const handlersWithoutOpener = sources().filter(({ rel, text }) => /\bonblocked\b/.test(text) && !sites.some((x) => x.rel === rel));
  assert.deepEqual(handlersWithoutOpener.map((h) => h.rel), []);
});
