// Run: npx tsx --test src/components/contact-management-copy.test.ts
// The contact book shows a sentence chosen by a CODE (an intentional refusal) or by the SITE (everything else), never an error's own text (copy ledger row 228).
// The sentences are pinned byte for byte here, apart from the module that holds them. The component is checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONTACT_IO_MESSAGES, errorTag } from '@/lib/contacts/contact-io-errors';
import {
  CONTACT_FAILURE_MESSAGES, CONTACT_INPUT_MESSAGES, ContactInputError, contactFailureMessage,
  type ContactFailureSite, type ContactInputCode,
} from './contact-management-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
// a thrower whose text is hostile: a quote, a newline, a bidi override, markup
const HOSTILE = 'x"\n\u202E<b>Private key not found in local storage';
const shown = (s: string) => assert.ok(!s.includes('\u202E') && !s.includes('<b>') && !s.includes('"') && !s.includes('\n') && !s.includes('Private key'), `thrower text on screen: ${JSON.stringify(s)}`);

const INPUT: ReadonlyArray<readonly [ContactInputCode, string]> = [
  ["invite-no-key", "Unlock your identity first to build an invite."],
  ["share-no-key", "Unlock your identity first to share a signed card."],
  ["add-missing", "Enter a name and a fingerprint."],
  ["add-self", "You can't add yourself as a contact."],
  ["edit-no-name", "Enter a name."],
  ["edit-key-bound", "This contact is tied to their key, so these details can't be edited. You can still change trust, groups and sharing."],
  ["import-incomplete", "This card is missing a fingerprint or public key, so it can't be imported."],
  ["import-self", "You can't import yourself as a contact."],
  ["link-empty", "Paste their SVRNTY fingerprint and public key."],
];
const FAILURE: ReadonlyArray<readonly [ContactFailureSite, string]> = [
  ["load", "Your contacts couldn't be loaded. Reload the page to try again."],
  ["invite", "The invite couldn't be prepared. Check your connection and try again."],
  ["add", "Adding the contact didn't finish. Check your contacts before you try again."],
  ["edit", "Saving your changes didn't finish. Check the contact before you try again."],
  ["remove", "Removing the contact didn't finish. Check your contacts before you try again."],
  ["trust", "Changing trust didn't finish. Check the contact before you try again."],
  ["verify", "Recording your verification didn't finish. Check the contact before you try again."],
  ["block", "Blocking didn't finish, so this person might not be blocked yet. Check the contact and try again."],
  ["unblock", "Unblocking didn't finish. Check the contact and try again."],
  ["share", "Your card couldn't be prepared for sharing. Try again."],
  ["import", "Importing this card didn't finish. Check your contacts before you try again."],
  ["link", "Linking didn't finish. Check the contact before you try again."],
  ["renameGroup", "Renaming the group didn't finish. Check your groups before you try again."],
  ["removeGroup", "Removing the group didn't finish. Check your groups before you try again."],
  ["assignGroup", "Adding the contact to the group didn't finish. Check the contact before you try again."],
  ["export", "The export didn't finish. Try again."],
];

test('CM1 the nine intentional sentences are the copy owner\'s words, byte for byte (ledger row 228b), and are all the sentences there are', () => {
  for (const [c, s] of INPUT) assert.equal(CONTACT_INPUT_MESSAGES[c], s, c);
  assert.deepEqual(Object.keys(CONTACT_INPUT_MESSAGES).sort(), INPUT.map(([c]) => c).sort());
  assert.ok(Object.isFrozen(CONTACT_INPUT_MESSAGES));
});

test('CM2 the sixteen fixed sentences are the copy owner\'s words, byte for byte (ledger row 228c); Block says the risk; export is the import/export screens\' sentence itself', () => {
  for (const [site, s] of FAILURE) assert.equal(CONTACT_FAILURE_MESSAGES[site], s, site);
  assert.deepEqual(Object.keys(CONTACT_FAILURE_MESSAGES).sort(), FAILURE.map(([s]) => s).sort());
  assert.equal(CONTACT_FAILURE_MESSAGES.export, CONTACT_IO_MESSAGES.exportUnknown, 'reused, not retyped');
  assert.ok(code('contact-management-copy.ts').includes('export: CONTACT_IO_MESSAGES.exportUnknown,'), 'the module takes it from the shared constant, it does not retype it');
  assert.match(CONTACT_FAILURE_MESSAGES.block, /might not be blocked yet\./);
  assert.notEqual(CONTACT_FAILURE_MESSAGES.block, CONTACT_FAILURE_MESSAGES.unblock, 'Block and Unblock are two sentences');
  assert.ok(Object.isFrozen(CONTACT_FAILURE_MESSAGES));
  for (const s of [...Object.values(CONTACT_INPUT_MESSAGES), ...Object.values(CONTACT_FAILURE_MESSAGES)]) assert.ok([...s].every((c) => c.charCodeAt(0) < 128), 'plain ASCII');
});

test('CM3 a typed refusal shows ITS sentence at every site; any other error shows the SITE\'s fixed sentence and none of the thrower\'s text', () => {
  const quiet = console.error; console.error = () => undefined;
  try {
    for (const [c, s] of INPUT) for (const [site] of FAILURE) assert.equal(contactFailureMessage(new ContactInputError(c), site), s, `${c} at ${site}`);
    for (const [site, s] of FAILURE) {
      assert.equal(contactFailureMessage(new Error(HOSTILE), site), s, site);
      assert.equal(contactFailureMessage(HOSTILE, site), s, `a thrown string at ${site}`);
      assert.equal(contactFailureMessage(undefined, site), s);
      shown(contactFailureMessage(new Error(HOSTILE), site));
    }
  } finally { console.error = quiet; }
});

test('CM4 a look-alike is not a typed refusal: the same text and code on a plain Error shows the site\'s sentence, not the input sentence', () => {
  const quiet = console.error; console.error = () => undefined;
  try {
    const lookalike = Object.assign(new Error('Enter a name.'), { code: 'edit-no-name', name: 'ContactInputError' });
    assert.equal(contactFailureMessage(lookalike, 'edit'), CONTACT_FAILURE_MESSAGES.edit);
  } finally { console.error = quiet; }
});

test('CM5 an unknown error is logged by class name and code only (never the message, never the object); a typed refusal logs nothing', () => {
  const calls: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { calls.push(a); };
  try {
    contactFailureMessage(new TypeError(HOSTILE), 'add');
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], ['Contact add failed:', 'TypeError']);
    assert.ok(!JSON.stringify(calls).includes('Private key'), 'no thrower text in the log');
    contactFailureMessage(new ContactInputError('add-self'), 'add');
    assert.equal(calls.length, 1, 'a typed refusal is not logged');
    const named = Object.assign(new Error(HOSTILE), { name: 'Evil\u202E\n"name', code: 'c\nx' });
    contactFailureMessage(named, 'edit');
    assert.deepEqual(calls[1], ['Contact edit failed:', errorTag(named)]);
    assert.equal(errorTag(named), 'Evilname:cx');
  } finally { console.error = real; }
});

test('CM6 THE COMPONENT: no error text is read, the nine refusals are typed, the fifteen catches use the site map, and the safety message still comes first', () => {
  const cm = code('ContactManagement.tsx');
  assert.ok(!/\.message\b/.test(cm.replace(/\b(result|exchangeResult|view|failure|status)\.message\b/g, '')), 'no error .message left in the contact book');
  assert.equal((cm.match(/throw new Error\(/g) ?? []).length, 0, 'no sentence is thrown as text');
  for (const [c] of INPUT) assert.equal((cm.match(new RegExp(`throw new ContactInputError\\('${c}'\\)`, 'g')) ?? []).length, 1, `refusal ${c} is raised exactly once`);
  assert.equal((cm.match(/new ContactInputError\(/g) ?? []).length, 9);
  const expected = [
    "setError(contactFailureMessage(err, 'load'))", "setInviteError(contactFailureMessage(e, 'invite'))", "setError(contactFailureMessage(err, 'add'))",
    "setError(contactFailureMessage(err, 'edit'))", "setError(describeSafetyWriteFailure(err, 'Remove') ?? contactFailureMessage(err, 'remove'))",
    "setError(contactFailureMessage(err, 'trust'))", "setError(contactFailureMessage(err, 'verify'))",
    "setError(describeSafetyWriteFailure(err, blocked ? 'Block' : 'Unblock') ?? contactFailureMessage(err, blocked ? 'block' : 'unblock'))",
    "setError(contactFailureMessage(err, 'share'))", "message: contactFailureMessage(err, 'import')", "setError(contactFailureMessage(err, 'export'))",
    "setLinkError(contactFailureMessage(err, 'link'))", "setError(contactFailureMessage(err, 'renameGroup'))", "setError(contactFailureMessage(err, 'removeGroup'))",
    "setError(contactFailureMessage(err, 'assignGroup'))",
  ];
  for (const e of expected) assert.equal(cm.split(e).length - 1, 1, e);
  assert.equal((cm.match(/contactFailureMessage\(/g) ?? []).length, 15, 'fifteen catches, one call each (Block/Unblock is one call, the site chosen by `blocked`)');
});
