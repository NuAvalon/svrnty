// Run: npx tsx --test src/components/soverentity-frontend-copy.test.ts
// The main screen shows a sentence chosen by the SITE or by the refusal's code, never an error's own text (copy ledger row 229). The sentences are pinned byte for byte here,
// apart from the module that holds them; the component is checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorTag } from '@/lib/contacts/contact-io-errors';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { FRONTEND_FAILURE_MESSAGES, frontendFailureMessage } from './soverentity-frontend-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const HOSTILE = 'x"\n\u202E<b>Failed to store key';

test('SF1 the two sentences are the copy owner\'s words, byte for byte (ledger row 229b, 229d), and are all there are', () => {
  assert.equal(FRONTEND_FAILURE_MESSAGES.createIdentity, "Creating your identity didn't finish. Reload the page before you try again.");
  assert.equal(FRONTEND_FAILURE_MESSAGES.sendUpdate, "Sending your update didn't finish. Some contacts may already have it. You can send it again.");
  assert.deepEqual(Object.keys(FRONTEND_FAILURE_MESSAGES).sort(), ['createIdentity', 'sendUpdate']);
  assert.ok(Object.isFrozen(FRONTEND_FAILURE_MESSAGES));
});

test('SF2 any error shows the site\'s fixed sentence and none of the thrower\'s text; it is logged by class name and code only', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    for (const site of ['createIdentity', 'sendUpdate'] as const) {
      const m = frontendFailureMessage(new TypeError(HOSTILE), site);
      assert.equal(m, FRONTEND_FAILURE_MESSAGES[site]);
      assert.ok(!m.includes('\u202E') && !m.includes('<b>') && !m.includes('Failed to store key'));
      assert.equal(frontendFailureMessage(HOSTILE, site), FRONTEND_FAILURE_MESSAGES[site]);
    }
    assert.deepEqual(calls[0], ['createIdentity failed:', 'TypeError']);
    assert.ok(!JSON.stringify(calls).includes('Failed to store key'), 'no thrower text in the log');
    const named = Object.assign(new Error(HOSTILE), { name: 'Evil\u202E\n"name', code: 'c\nx' });
    frontendFailureMessage(named, 'sendUpdate');
    assert.deepEqual(calls.at(-1), ['sendUpdate failed:', errorTag(named)]);
  } finally { console.error = real; }
});

test('SF3 THE COMPONENT: no error text is read, the three restore refusals use the constants, the share path reuses the contact book\'s typed refusal and sentence, and the old fallbacks are gone', () => {
  const sf = code('SoverentityFrontend.tsx');
  assert.ok(!/\.message\b/.test(sf.replace(/\b(result|failure|view|status)\.message\b/g, '')), 'no error .message left in the main screen');
  assert.ok(!/Restore refused\./.test(sf), 'the unreachable fallback is dropped');
  assert.equal((sf.match(/setRestoreError\(restoreDomainRefusalMessage\(err\)\)/g) ?? []).length, 3, 'the three restore-domain refusal sites show the constants');
  assert.equal((sf.match(/isRestoreDomainRefusal\(err\)/g) ?? []).length >= 4, true, 'the refusal is still recognised BEFORE the failure is classified (the existing guards pin each handler)');
  assert.equal(sf.split("setError(frontendFailureMessage(err, 'createIdentity'))").length - 1, 1);
  assert.equal(sf.split("message: frontendFailureMessage(e, 'sendUpdate')").length - 1, 1);
  assert.equal(sf.split("setShareError(contactFailureMessage(e, 'share'))").length - 1, 1, 'the share failure is the contact book\'s sentence, not a retyped one');
  assert.equal(sf.split("throw new ContactInputError('share-no-key')").length - 1, 1, 'the locked-key refusal is the contact book\'s typed one');
  assert.ok(!/throw new Error\('Unlock your identity first to share a signed card\.'\)/.test(sf));
  assert.match(sf, /from '\.\/contact-management-copy'/, 'imported from area one\'s module');
});

test('SF4 a blocked database upgrade shows THE one sentence at both sites, is not logged as an unknown failure, and the old plain text is just a failure', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    for (const site of Object.keys(FRONTEND_FAILURE_MESSAGES) as Array<keyof typeof FRONTEND_FAILURE_MESSAGES>) {
      assert.equal(frontendFailureMessage(new DbUpgradeBlocked(), site), DB_UPGRADE_BLOCKED_MESSAGE, site);
      assert.equal(frontendFailureMessage({ code: 'db-upgrade-blocked' }, site), DB_UPGRADE_BLOCKED_MESSAGE, `${site} by code`);
      assert.notEqual(DB_UPGRADE_BLOCKED_MESSAGE, FRONTEND_FAILURE_MESSAGES[site]);
    }
    assert.equal(calls.length, 0, 'an expected stop is not logged');
    assert.equal(frontendFailureMessage(new Error('svrnty database is upgrading — close other svrnty tabs and reload'), 'createIdentity'), FRONTEND_FAILURE_MESSAGES.createIdentity);
  } finally { console.error = real; }
});
