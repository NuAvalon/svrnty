// Run: npx tsx --test src/components/export/vault-export-copy.test.ts
// The vault-export dialog shows ONE fixed sentence when the export does not finish (copy ledger row 232h), never an error's own text. The real error is logged by tag only, and the blocked-upgrade stop keeps its own sentence.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { VAULT_EXPORT_FAILED, vaultExportFailureMessage } from './vault-export-copy';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';

const HERE = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const dialog = (): string => stripComments(readFileSync(join(HERE, 'VaultExportDialog.tsx'), 'utf8'));
const quiet = <T,>(fn: () => T): { out: T; logged: unknown[][] } => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: fn(), logged }; } finally { console.error = real; }
};

test('VE1 the sentence is the copy owner\'s words byte for byte (row 232h) and plain ASCII', () => {
  assert.equal(VAULT_EXPORT_FAILED, "The vault export didn't finish. Try again.");
  assert.ok(/^[\x20-\x7e]+$/.test(VAULT_EXPORT_FAILED));
});

test('VE2 any other failure shows the fixed sentence and never the error\'s own text', () => {
  for (const e of [new Error('Identity not found'), new Error('Session locked — call initSessionKey() first'), new TypeError('x is not a function 4242'), 'a string', null, undefined, { message: 'looks like an error 4242' }]) {
    const { out } = quiet(() => vaultExportFailureMessage(e));
    assert.equal(out, VAULT_EXPORT_FAILED);
  }
});

test('VE3 the blocked-upgrade stop keeps its own sentence, by CODE (a look-alike message is not it), and is not logged as an unknown failure', () => {
  const real = quiet(() => vaultExportFailureMessage(new DbUpgradeBlocked()));
  assert.equal(real.out, DB_UPGRADE_BLOCKED_MESSAGE);
  assert.deepEqual(real.logged, []);
  const lookalike = quiet(() => vaultExportFailureMessage(new Error(DB_UPGRADE_BLOCKED_MESSAGE)));
  assert.equal(lookalike.out, VAULT_EXPORT_FAILED);
});

test('VE4 an unknown failure is logged ONCE and by class and code only: exactly the tag, never the error object or its message', () => {
  class Coded extends Error { code = 'x-code'; }
  // The logged arguments are pinned EXACTLY. (JSON.stringify of an Error is "{}", so a text search cannot tell whether an error object was logged; the exact arguments can.)
  for (const [err, tag] of [[new Error('SECRET-MESSAGE-4242 something broke'), 'Error'], [new TypeError('SECRET-MESSAGE-4242'), 'TypeError'], [new Coded('SECRET-MESSAGE-4242'), 'Error:x-code'], ['SECRET-MESSAGE-4242', 'string']] as const) {
    const { logged } = quiet(() => vaultExportFailureMessage(err));
    assert.deepEqual(logged, [['Vault export failed:', tag]]);
  }
});

test('VE5 THE DIALOG asks the helper once, reads no error text, and the old fallback is gone', () => {
  const c = dialog();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the dialog: ${needle}`);
  once("import { vaultExportFailureMessage } from './vault-export-copy';");
  once('setError(vaultExportFailureMessage(err));');
  assert.ok(!/\.message\b/.test(c), 'the dialog must not read an error\'s own text');
  assert.ok(!c.includes('Vault export failed'), 'the old fallback must not return');
  assert.ok(!c.includes("didn't finish"), 'the sentence lives in the copy module only');
});
