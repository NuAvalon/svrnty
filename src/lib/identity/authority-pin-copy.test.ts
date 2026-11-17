// src/lib/identity/authority-pin-copy.test.ts
// #787: the different-pin sentence is pinned word for word, must not coach a re-share (it cannot help under first-write-wins) or use the untaught term
// "pin", and BOTH import paths must raise it (the join-link path used to stay silent on a conflict).
// Security-warning rule: a card-supplied string never appears in a security warning. A name, where shown, is the BOOK's, made frame-safe.
//   npx tsx --test src/lib/identity/authority-pin-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  authorityPinConflictMessage, gateAuthorityPinConflictMessage, unverifiedCardMessage, addedUnverifiedContactMessage,
  warningName, WARNING_NAME_MAX,
} from './authority-pin-copy';

const FSI = '⁨';
const PDI = '⁩';
const iso = (n: string) => FSI + n + PDI;
// A hostile card name: a double quote (to close the sentence's frame), a newline (to start a line of its own) and U+202E (to reverse what follows).
// Its letters are chosen so no 3-character piece of it occurs in the fixed sentences: any match below means card text leaked.
const NEG = 'Zx"\nQj‮wVk';
const grams3 = (s: string) => Array.from({ length: Math.max(0, Array.from(s).length - 2) }, (_, i) => Array.from(s).slice(i, i + 3).join(''));
const leaks = (msg: string, card: string) => grams3(card).filter((g) => msg.includes(g));

test('C1 the different-pin sentence is exactly the reviewed copy (the book name is bidi-isolated)', () => {
  assert.equal(authorityPinConflictMessage('Zed'),
    `A card for "${iso('Zed')}" doesn't match the one you already have, so it wasn't applied. Your existing contact is unchanged. Someone else may have access to their identity. Check with them another way before acting on this card.`);
});
test('C2 it does not tell anyone to re-share, and does not use the word pin', () => {
  for (const m of [authorityPinConflictMessage('Zed'), gateAuthorityPinConflictMessage()].map((x) => x.toLowerCase())) {
    assert.ok(!/re-?share|resend|send again/.test(m));
    assert.ok(!/\bpin\b/.test(m));
  }
});
test('C3 [static] both import paths raise it on a different pin (Contacts import and the join link)', () => {
  for (const f of ['src/components/ContactManagement.tsx', 'src/components/JoinerCeremony.tsx']) {
    const s = readFileSync(f, 'utf8');
    assert.match(s, /authorityPinConflictMessage\(/, f);
    assert.match(s, /existing\.next_authority_commitment !== (d|peer)\.authorityPin/, f);
  }
});

test('C4 [static] on the join link a conflicting pin stops BEFORE any back-fill and before the joiner reply (no back-fill, no reply, only the alarm)', () => {
  const s = readFileSync('src/components/JoinerCeremony.tsx', 'utf8');
  const conflict = s.indexOf('authorityPinConflictMessage(existing.name)');
  const backfill = s.indexOf('await updateContact(existing.id');
  const reply = s.indexOf('void depositJoinerResponse(');
  assert.ok(conflict > 0 && backfill > 0 && reply > 0);
  assert.ok(conflict < backfill, 'the conflict check precedes the back-fill');
  assert.ok(conflict < reply, 'the conflict check precedes the joiner reply');
  assert.match(s.slice(conflict, conflict + 120), /return;/, 'it returns before reaching either');
});

// ── the sentences, byte for byte (ledger rows 200 + 201) ──
test('W1 the Gate sentence, the unverified-card sentence and the first-contact add sentence are exactly the reviewed copy', () => {
  assert.equal(gateAuthorityPinConflictMessage(),
    `This card doesn't match the one already waiting at your Gate for the same person, so it wasn't applied. Nothing at your Gate has changed. Someone else may have access to their identity. Check with the person who sent you this link another way before letting them in.`);
  assert.equal(unverifiedCardMessage('Zed'),
    `A card for "${iso('Zed')}" could not be verified — possible tampering. Your existing contact is unchanged; ask them to re-share over a secure link.`);
  assert.equal(addedUnverifiedContactMessage(),
    `Added a new contact (classical only). Their key material couldn't be verified, so this card may have been tampered with. Ask the person who sent it to share it again over a secure link.`);
});
test('W2 the no-name sentences take NO parameter, so a name cannot be passed in (a type error, checked by tsc)', () => {
  assert.equal(gateAuthorityPinConflictMessage.length, 0);
  assert.equal(addedUnverifiedContactMessage.length, 0);
  // @ts-expect-error a name is not accepted
  gateAuthorityPinConflictMessage(NEG);
  // @ts-expect-error a name is not accepted
  addedUnverifiedContactMessage(NEG);
});
test('W3 no sentence carries a forbidden word or a key value', () => {
  const all = [authorityPinConflictMessage('Zed'), gateAuthorityPinConflictMessage(), unverifiedCardMessage('Zed'), addedUnverifiedContactMessage()].join(' ').toLowerCase();
  for (const w of ['hacked', 'compromised', 'stolen', 'someone else has', 'impersonator', 'fingerprint', ' is safe']) assert.ok(!all.includes(w), w);
});

// ── the hostile card: none of its text reaches a warning, at any of the 5 sites ──
test('N1 the no-name sentences never contain any 3-character piece of a hostile card name', () => {
  assert.deepEqual(leaks(gateAuthorityPinConflictMessage(), NEG), []);
  assert.deepEqual(leaks(addedUnverifiedContactMessage(), NEG), []);
});
test('N2 the book-name sentences show only the book name: the card name given as the book name is frame-safe', () => {
  for (const f of [authorityPinConflictMessage, unverifiedCardMessage]) {
    const m = f(NEG);
    assert.ok(!m.includes('\n'), 'no newline');
    assert.ok(!m.includes('‮'), 'no right-to-left override');
    assert.equal(m.split('"').length - 1, 2, 'exactly the sentence\'s own two quotes');
    assert.ok(m.includes(iso("Zx' Qjw" + 'Vk')), 'the name is cleaned and isolated, in place');
  }
});
test('N3 [static] all 5 call sites pass the BOOK name or nothing: no card name (peer.name / displayName) reaches a security warning', () => {
  const j = readFileSync('src/components/JoinerCeremony.tsx', 'utf8');
  const c = readFileSync('src/components/ContactManagement.tsx', 'utf8');
  assert.equal((j.match(/authorityPinConflictMessage\(existing\.name\)/g) || []).length, 1, 'join link, contact in book');
  assert.equal((j.match(/gateAuthorityPinConflictMessage\(\)/g) || []).length, 1, 'join link, Gate');
  assert.equal((c.match(/unverifiedCardMessage\(existing\.name\)/g) || []).length, 1, 'Contacts, invalid signature');
  assert.equal((c.match(/authorityPinConflictMessage\(existing\.name\)/g) || []).length, 1, 'Contacts, pin conflict');
  assert.equal((c.match(/addedUnverifiedContactMessage\(\)/g) || []).length, 1, 'Contacts, first-contact add');
  for (const s of [j, c]) {
    assert.doesNotMatch(s, /(authorityPinConflictMessage|unverifiedCardMessage)\((peer\.name|displayName)\)/);
    assert.doesNotMatch(s, /possible tampering[^\n]*\$\{(displayName|peer\.name)\}|\$\{(displayName|peer\.name)\}[^\n]*possible tampering/);
  }
});
test('N4 [static] the Gate conflict path writes nothing: it sets the alarm and returns, before any await or Gate write', () => {
  const s = readFileSync('src/components/JoinerCeremony.tsx', 'utf8');
  const at = s.indexOf('if (pinMerge.conflict) {');
  assert.ok(at > 0);
  const branch = s.slice(at, s.indexOf('return;', at) + 'return;'.length);
  assert.match(branch, /setError\(gateAuthorityPinConflictMessage\(\)\);/);
  assert.doesNotMatch(branch, /await|enqueueGateArrival|updateContact|addContact|setGate|put\(|\.set\(/, 'nothing is written on the conflict path');
  assert.ok(at < s.indexOf('await enqueueGateArrival(ownerFp, {'), 'the conflict returns before the enqueue');
});

// ── the clamp (Flint (c)): the book name is bounded and cleaned, and nothing else ──
test('L1 the book name is clamped to WARNING_NAME_MAX code points, counting astral characters as one', () => {
  assert.equal(WARNING_NAME_MAX, 80);
  const long = '\u{1F600}'.repeat(200);
  const out = warningName(long);
  assert.ok(out.startsWith(FSI) && out.endsWith(PDI));
  assert.equal(Array.from(out.slice(1, -1)).length, WARNING_NAME_MAX);
  assert.equal(warningName('A'.repeat(500)), iso('A'.repeat(80)));
});
test('L2 warningName removes C0/C1 controls and bidi controls, folds whitespace, and keeps an ordinary name unchanged', () => {
  assert.equal(warningName('Alice'), iso('Alice'));
  assert.equal(warningName('Al\u0085ice‎⁦ B'), iso('Al ice B'));
  assert.equal(warningName('  O"Neil  '), iso("O'Neil"));
  assert.equal(warningName(undefined), iso(''));
  assert.equal(warningName(42 as unknown as string), iso(''));
});
