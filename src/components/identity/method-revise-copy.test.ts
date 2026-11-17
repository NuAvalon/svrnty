// Run: npx tsx --test src/components/identity/method-revise-copy.test.ts
// The "revise a contact method" dialog shows a fixed sentence when saving or sending does not finish (copy ledger rows 232d and 255), never an error's own text. The sentences are pinned byte
// for byte here, apart from the module that holds them; the dialog and the production sender are checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { METHOD_SAVE_FAILED, METHOD_SEND_FAILED, methodSaveFailureMessage, methodSendFailureMessage } from './method-revise-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const dialog = (): string => stripComments(readFileSync(join(HERE, 'ContactMethodReviseDialog.tsx'), 'utf8'));
const frontend = (): string => stripComments(readFileSync(join(HERE, '..', 'SoverentityFrontend.tsx'), 'utf8'));
const quiet = <T,>(fn: () => T): { out: T; logged: unknown[][] } => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: fn(), logged }; } finally { console.error = real; }
};
const HELPERS = [
  ['save', methodSaveFailureMessage, METHOD_SAVE_FAILED, 'Method save failed:'],
  ['send', methodSendFailureMessage, METHOD_SEND_FAILED, 'Method send failed:'],
] as const;

test('MR1 the two sentences are the copy owner\'s words byte for byte (rows 232d and 255), plain ASCII, and the send one has the frozen hash', () => {
  assert.equal(METHOD_SAVE_FAILED, "Saving your change didn't finish. Try again.");
  assert.equal(METHOD_SEND_FAILED, "Your update wasn't sent. Try again.");
  for (const s of [METHOD_SAVE_FAILED, METHOD_SEND_FAILED]) assert.ok(/^[\x20-\x7e]+$/.test(s));
  assert.equal(METHOD_SEND_FAILED.length, 35);
  assert.equal(createHash('sha256').update(METHOD_SEND_FAILED).digest('hex').slice(0, 16), '25a93d600721a055');
});

test('MR2 any other failure shows the fixed sentence and never the error\'s own text; it is logged ONCE, by class and code only (the exact arguments), for each helper', () => {
  class Coded extends Error { code = 'x-code'; }
  for (const [, fn, sentence, label] of HELPERS) {
    for (const [err, tag] of [[new Error('SECRET-4242 quota exceeded'), 'Error'], [new TypeError('SECRET-4242'), 'TypeError'], [new Coded('SECRET-4242'), 'Error:x-code'], ['SECRET-4242', 'string']] as const) {
      const { out, logged } = quiet(() => fn(err));
      assert.equal(out, sentence);
      assert.deepEqual(logged, [[label, tag]]);
    }
    for (const v of [null, undefined, { message: 'x' }]) assert.equal(quiet(() => fn(v)).out, sentence);
  }
});

test('MR3 a blocked database upgrade keeps its own sentence in both places, by CODE (a look-alike message is not it), and is not logged as an unknown failure', () => {
  for (const [, fn, sentence] of HELPERS) {
    const real = quiet(() => fn(new DbUpgradeBlocked()));
    assert.equal(real.out, DB_UPGRADE_BLOCKED_MESSAGE);
    assert.deepEqual(real.logged, []);
    assert.equal(quiet(() => fn(new Error(DB_UPGRADE_BLOCKED_MESSAGE))).out, sentence);
  }
});

test('MR4 THE DIALOG imports both helpers once, uses the save sentence at the Save button and the send sentence at the Send catch, reads no caught error\'s text, and the old fallbacks are gone', () => {
  const c = dialog();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the dialog: ${needle}`);
  once("import { methodSaveFailureMessage, methodSendFailureMessage } from './method-revise-copy';");
  once('setLocalNote(methodSaveFailureMessage(e));');
  once("message: methodSendFailureMessage(e) });");
  assert.equal((c.match(/methodSaveFailureMessage\(/g) ?? []).length, 1);
  assert.equal((c.match(/methodSendFailureMessage\(/g) ?? []).length, 1);
  assert.ok(!c.includes('frontendFailureMessage'), 'the main screen\'s send sentence (row 229d) is not used here: it would claim a contact may already have the update');
  assert.ok(!/\b(?:e|err)\??\.message\b/.test(c) && !c.includes('instanceof Error'), 'no caught error\'s own text is read');
  assert.ok(!c.includes('Could not save locally.') && !c.includes('Send failed.'), 'the old fallbacks are gone');
  assert.ok(!c.includes("didn't finish") && !c.includes("wasn't sent"), 'the sentences live in the copy module only');
});

test('MR5 THE SEND IS ONE TRY (row 255a): the draft save, the history write and sendFn all sit inside it, in that order, and its ONE catch shows the send sentence', () => {
  const c = dialog();
  const body = c.slice(c.indexOf('const handleSend = async'), c.indexOf('const label = '));
  const iTry = body.indexOf('try {');
  const iSave = body.indexOf('await onLocalSave(');
  const iHist = body.indexOf('recordHistory(recipients);');
  const iSend = body.indexOf('await sendFn(');
  const iCatch = body.indexOf('} catch (e) {');
  const iMsg = body.indexOf('methodSendFailureMessage(e)');
  for (const [n, i] of [['try', iTry], ['save', iSave], ['history', iHist], ['send', iSend], ['catch', iCatch], ['message', iMsg]] as const) assert.ok(i >= 0, `${n} found`);
  assert.ok(iTry < iSave && iSave < iHist && iHist < iSend && iSend < iCatch && iCatch < iMsg, 'order: try, save, history, send, then the one catch');
  assert.equal((body.match(/\btry \{/g) ?? []).length, 1, 'one try');
  assert.equal((body.match(/catch \(e\)/g) ?? []).length, 1, 'one catch');
});

test('MR6 THE PREMISE of "wasn\'t sent": the production sender does its throwing steps BEFORE its deposit and the deposit sits in its own try whose catch returns (it never throws)', () => {
  const f = frontend();
  const start = f.indexOf('const handleContactMethodSend: ContactMethodSendFn = async');
  const end = f.indexOf('if (!identity) return null;', start);
  assert.ok(start >= 0 && end > start, 'the sender is found');
  const body = f.slice(start, end);
  const once = (needle: string): number => { assert.equal(body.split(needle).length - 1, 1, `exactly once in the sender: ${needle}`); return body.indexOf(needle); };
  const iKey = once('await loadKey(fp)');
  const iFresh = once('await loadIdentity(fp)');
  const iStore = once('await storeIdentity(fp, bumped)');
  const iDeposit = once('await sendContactUpdate(');
  const iTry = body.lastIndexOf('try {', iDeposit);
  const iCatch = body.indexOf('} catch (e) {', iDeposit);
  assert.ok(iKey < iFresh && iFresh < iStore && iStore < iTry && iTry < iDeposit && iDeposit < iCatch, 'order: the key, identity and persist steps, then the try, then the deposit, then its catch');
  const caught = body.slice(iCatch);
  assert.ok(/return \{ ok: false, reason: 'error'/.test(caught), 'its catch returns a failure');
  assert.ok(!/\bthrow\b/.test(caught), 'its catch never throws');
  assert.ok(!/\bthrow\b/.test(body), 'the sender has no throw of its own');
});
