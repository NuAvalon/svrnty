// The contact writes in the trust-map handlers (app/page.tsx) are decided on the record the store holds when each write runs, the block is an
// owner-protecting write, and every allowed-senders consent there comes from a stored record or from no consent. A static guard over the source,
// using the same balanced-parentheses walker as the contact-manager guard.
//
// Run: npx tsx --test src/lib/contacts/trustmap-writes-guard.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { callsOf } from '../identity/static-guard-kit';

const page = readFileSync(new URL('../../../app/page.tsx', import.meta.url), 'utf8');
const code = page.split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
// One patch helper called with the bare identifier `fresh` as its first argument (one argument or more), and nothing else in the body.
const FRESH_BODY = /^updateContact\([^,]+,\s*\(fresh\)\s*=>\s*\(?\s*\w+Patch\(\s*fresh\s*(?:,[^]*)?\)\s*,?\s*\)?\s*,?\s*\)$/;

test('GUARD: every updateContact in app/page.tsx is a function-form write of ONE patch helper on the held record, and reads no screen or snapshot copy', () => {
  const calls = callsOf(code, 'updateContact');
  assert.equal(calls.length, 6, 'bulk tags, owner verify, distress, block, accept introduction, contact edit; a new write here needs a guard line');
  for (const c of calls) {
    assert.match(c, FRESH_BODY, `not one patch helper called on fresh: ${c.replace(/\s+/g, ' ').slice(0, 140)}`);
    const body = c.slice(c.indexOf('=>'));
    assert.doesNotMatch(body, /\bedge\b|\brec\b|\brecords\b|\brecMeta\b|\bcontacts\b|\bselectedContact\b/, `the body reads a captured record: ${body.replace(/\s+/g, ' ').slice(0, 140)}`);
  }
});

test('GUARD: the trust-map block is an owner-protecting write: under the safety lock, on the held record, with the consent read back and plain words when it cannot be saved', () => {
  const a = code.indexOf('onBlockContact={async');
  const b = code.indexOf('onAcceptIntro={async');
  assert.ok(a > 0 && b > a, 'the block handler was found');
  const h = code.slice(a, b);
  assert.match(h, /await withSafetyWrite\(edge\.id, \(\) => updateContact\(edge\.id, \(fresh\) => blockPatch\(fresh, blocked\)\)\);/);
  assert.match(h, /describeSafetyWriteFailure\(err, blocked \? 'Block' : 'Unblock'\);\s*throw words \? new Error\(words\) : err;/);
  assert.match(h, /const afterBlock = await getContact\(edge\.id\);/);
  assert.match(h, /consent: afterBlock \? consentFromRecord\(afterBlock\) : NO_CONSENT,/);
  assert.doesNotMatch(h, /getAllContacts|recMeta/, 'the block no longer reads a snapshot of the book');
});

test('GUARD: every allowed-senders consent in app/page.tsx is read back from a stored record or is no consent; none is built here', () => {
  const reconciles = callsOf(code, 'reconcileAllowedOnConsentChange');
  assert.ok(reconciles.length >= 2, 'the remove and the block');
  for (const r of reconciles) {
    const consent = /consent:\s*([^\n]*)/.exec(r)?.[1] ?? '';
    assert.match(consent, /^(NO_CONSENT|afterBlock \? consentFromRecord\(afterBlock\) : NO_CONSENT),?\s*\}?\)?;?$/, `a consent is built from something else: ${consent}`);
  }
  assert.doesNotMatch(code, /consent:\s*\{/, 'no consent object literal in the file');
});

test('GUARD: the converted trust-map handlers no longer build their patches from the old persist helpers or a snapshot of the book', () => {
  assert.doesNotMatch(code, /ownerVerifyPersistPatch|distressWentPersistPatch/, 'the old copy-based helpers are not used here');
  const slice = (from: string, to: string) => code.slice(code.indexOf(from), code.indexOf(to));
  // The region from the owner-verify handler through the trust toggle: the toggle no longer reads the book either (it reads the consent back).
  for (const h of [slice('onOwnerVerify={async', 'onBlockContact={async'), slice('onBlockContact={async', 'onSendMethodUpdate={')]) {
    assert.doesNotMatch(h, /getAllContacts/, 'none of these handlers reads the book to build a write');
  }
});

test('GUARD: the bulk tag handler uses the snapshot only to find ids', () => {
  const a = code.indexOf('onAssignGroup={async');
  const b = code.indexOf('onOwnerVerify={async');
  const h = code.slice(a, b);
  assert.match(h, /await updateContact\(id, \(fresh\) => addLabelHeldPatch\(fresh, label\)\);/);
  assert.doesNotMatch(h, /prevTags|rec as any|metadata:\s*\{ \.\.\./, 'no tag list or metadata is built from the snapshot');
});
