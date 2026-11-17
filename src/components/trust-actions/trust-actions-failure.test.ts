// Run: npx tsx --test src/components/trust-actions/trust-actions-failure.test.ts
// What the trust actions (trust, break, remove, block, unblock) say when the local update fails (copy ledger row 257). The catch maps by CLASS and never shows an error's own text: the words a lost
// lock or compare race has ("Block not saved. Try again."), then the contact book's own sentence for the site (a store refusal by its code, a blocked upgrade, else the fixed one). The sentences are the
// contact book's constants and are imported, not retyped. The page and this module are checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { CONTACT_REFUSAL_MESSAGES } from '@/lib/contacts/contact-refusal';
import { SafetyLockTimeout } from '@/lib/contacts/safety-write';
import { ContactConflictError } from '@/lib/identity/contact-cas';
import { CONTACT_FAILURE_MESSAGES } from '../contact-management-copy';
import { applyTrustAction, type TrustActionKind, type TrustActionTarget } from './trust-actions';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const quiet = async <T,>(fn: () => Promise<T>): Promise<{ out: T; logged: unknown[][] }> => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: await fn(), logged }; } finally { console.error = real; }
};
// a target for which each kind is allowed to run (the preconditions in applyTrustAction pass), and the site and safety words each kind uses
const TARGET: Record<TrustActionKind, TrustActionTarget> = {
  trust: { id: 'c1', fingerprint: 'fp', name: 'Alice', trusted: false, ownerVerified: true },
  break: { id: 'c1', fingerprint: 'fp', name: 'Alice', trusted: true },
  remove: { id: 'c1', fingerprint: 'fp', name: 'Alice', trusted: false },
  block: { id: 'c1', fingerprint: 'fp', name: 'Alice', trusted: false, blocked: false },
  unblock: { id: 'c1', fingerprint: 'fp', name: 'Alice', trusted: false, blocked: true },
};
const KINDS = Object.keys(TARGET) as TrustActionKind[];
const SITE: Record<TrustActionKind, 'trust' | 'remove' | 'block' | 'unblock'> = { trust: 'trust', break: 'trust', remove: 'remove', block: 'block', unblock: 'unblock' };
const WORDS: Partial<Record<TrustActionKind, string>> = { remove: 'Remove not saved. Try again.', block: 'Block not saved. Try again.', unblock: 'Unblock not saved. Try again.' };
const fail = (kind: TrustActionKind, err: unknown) => quiet(() => applyTrustAction(kind, TARGET[kind], { applyLocal: async () => { throw err; } }));

test('TA1 the block sentence is the copy owner\'s new words byte for byte (row 257c: it no longer reads as a permission), plain ASCII, with the frozen hash; the other sentences are the contact book\'s own', () => {
  const s = CONTACT_FAILURE_MESSAGES.block;
  assert.equal(s, "Blocking didn't finish, so this person might not be blocked yet. Check the contact and try again.");
  assert.ok(/^[\x20-\x7e]+$/.test(s));
  assert.equal(s.length, 97);
  assert.equal(createHash('sha256').update(s).digest('hex').slice(0, 16), 'c037efae2b67bbc5');
  assert.ok(!/\bmay not be blocked\b/.test(s));
  assert.equal(CONTACT_FAILURE_MESSAGES.unblock, "Unblocking didn't finish. Check the contact and try again.");
  assert.equal(CONTACT_FAILURE_MESSAGES.remove, "Removing the contact didn't finish. Check your contacts before you try again.");
  assert.equal(CONTACT_FAILURE_MESSAGES.trust, "Changing trust didn't finish. Check the contact before you try again.");
});

test('TA2 a lost lock or compare race shows its own words for block, unblock and remove ("<What> not saved. Try again."), and the site sentence for trust and break, with the failure result', async () => {
  for (const kind of KINDS) {
    for (const err of [new SafetyLockTimeout('c1'), new ContactConflictError('c1', 3)]) {
      const { out, logged } = await fail(kind, err);
      assert.equal(out.ok, false);
      assert.equal((out as { reason: string }).reason, 'local-failed');
      assert.equal(out.message, WORDS[kind] ?? CONTACT_FAILURE_MESSAGES[SITE[kind]], `${kind} ${err.constructor.name}`);
      // a contention failure has its own words and is not logged as an unknown failure, except for trust and break which have none
      assert.equal(logged.length, WORDS[kind] ? 0 : 1, `${kind} ${err.constructor.name} logs`);
    }
  }
});

test('TA3 a store REFUSAL shows its own sentence by CODE at every kind (never the site\'s "didn\'t finish"), and a look-alike message is not one', async () => {
  const REFUSALS: ReadonlyArray<readonly [unknown, string]> = [
    [Object.assign(new Error('HOSTILE'), { code: 'contact-refused', reason: 'verify-before-trust' }), CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust],
    [Object.assign(new Error('HOSTILE'), { code: 'trust-refused', reason: 'blocked' }), CONTACT_REFUSAL_MESSAGES.blocked],
    [Object.assign(new Error('HOSTILE'), { code: 'contact-update-refused', reason: 'identity-immutable' }), CONTACT_REFUSAL_MESSAGES.identityImmutable],
  ];
  for (const kind of KINDS) {
    for (const [err, sentence] of REFUSALS) {
      const { out, logged } = await fail(kind, err);
      assert.equal(out.message, sentence, kind);
      assert.deepEqual(logged, [], `${kind}: a refusal is not logged as an unknown failure`);
    }
    const lookalike = await fail(kind, new Error(CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust));
    assert.equal(lookalike.out.message, CONTACT_FAILURE_MESSAGES[SITE[kind]], `${kind}: text is never the key`);
  }
});

test('TA4 a blocked database upgrade shows its own sentence at every kind, by CODE (a look-alike message is not it), and is not logged as an unknown failure', async () => {
  for (const kind of KINDS) {
    const real = await fail(kind, new DbUpgradeBlocked());
    assert.equal(real.out.message, DB_UPGRADE_BLOCKED_MESSAGE, kind);
    assert.deepEqual(real.logged, []);
    assert.equal((await fail(kind, new Error(DB_UPGRADE_BLOCKED_MESSAGE))).out.message, CONTACT_FAILURE_MESSAGES[SITE[kind]], kind);
  }
});

test('TA5 any other failure shows the site\'s fixed sentence and never the thrower\'s text; it is logged ONCE, by class and code only (the exact arguments); a non-Error throw is the same', async () => {
  class Coded extends Error { code = 'x-code'; }
  for (const kind of KINDS) {
    for (const [err, tag] of [[new Error('SECRET-4242 quota exceeded'), 'Error'], [new TypeError('SECRET-4242'), 'TypeError'], [new Coded('SECRET-4242'), 'Error:x-code'], ['SECRET-4242', 'string']] as const) {
      const { out, logged } = await fail(kind, err);
      assert.equal(out.message, CONTACT_FAILURE_MESSAGES[SITE[kind]], `${kind} ${tag}`);
      assert.ok(!out.message.includes('SECRET'));
      assert.deepEqual(logged, [[`Contact ${SITE[kind]} failed:`, tag]], `${kind} ${tag}`);
    }
  }
});

test('TA6 WHY THE PAGE RETHROWS THE ORIGINAL (row 257b): a contention failure wrapped in a plain Error has lost its class, so its words are gone and only the site sentence is left', async () => {
  const wrapped = new Error('Block not saved. Try again.');   // what app/page.tsx used to throw
  assert.equal((await fail('block', wrapped)).out.message, CONTACT_FAILURE_MESSAGES.block);
  assert.equal((await fail('block', new SafetyLockTimeout('c1'))).out.message, 'Block not saved. Try again.');
});

test('TA7 THE MODULE: the catch asks the safety words first and the contact book\'s helper second, once each, reads no caught error\'s text, and the old fallback is gone', () => {
  const c = code('trust-actions.ts');
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once: ${needle}`);
  once("import { describeSafetyWriteFailure } from '@/lib/contacts/safety-write';");
  once("import { contactFailureMessage, type ContactFailureSite } from '../contact-management-copy';");
  once('describeSafetyWriteFailure(err, what)');
  once('contactFailureMessage(err, FAILURE_SITE[kind])');
  assert.ok(!/\b(?:e|err)\??\.message\b/.test(c) && !c.includes('instanceof Error'), 'no caught error\'s own text is read');
  assert.ok(!c.includes('Local update failed.'), 'the old fallback is gone');
  assert.ok(c.indexOf('describeSafetyWriteFailure(err, what)') < c.indexOf('contactFailureMessage(err, FAILURE_SITE[kind])'), 'the safety words come first');
});

test('TA8 THE PAGE (row 257b): the trust map\'s remove and block callbacks rethrow the ORIGINAL error: no wrapping, no safety words built there, and each still takes the safety write', () => {
  const p = code('../../../app/page.tsx');
  const remove = p.slice(p.indexOf('onRemoveContact={async (edge) => {'), p.indexOf('onBlockContact={async (edge, blocked) => {'));
  const block = p.slice(p.indexOf('onBlockContact={async (edge, blocked) => {'), p.indexOf('onAcceptIntro={async (edge) => {'));
  assert.ok(remove.length > 100 && block.length > 100, 'both callbacks are found');
  assert.equal(remove.split('await withSafetyWrite(edge.id, () => removeContact(edge.id));').length - 1, 1);
  assert.equal(block.split('await withSafetyWrite(edge.id, () => updateContact(edge.id, (fresh) => blockPatch(fresh, blocked)));').length - 1, 1);
  for (const [name, body] of [['remove', remove], ['block', block]] as const) {
    assert.ok(!body.includes('describeSafetyWriteFailure'), `${name}: no safety words are built in the page`);
    assert.ok(!/throw words|new Error\(words\)/.test(body), `${name}: the error is not wrapped`);
    assert.ok(!/\bcatch\b/.test(body), `${name}: no catch (bare, with a binding, or .catch) around the safety write: a failed write must propagate`);
  }
});
