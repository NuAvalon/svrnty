// src/lib/identity/authority-pin-copy.test.ts
// #787: the different-pin sentence is pinned word for word, must not coach a re-share (it cannot help under first-write-wins) or use the untaught term
// "pin", and BOTH import paths must raise it (the join-link path used to stay silent on a conflict).
//   npx tsx --test src/lib/identity/authority-pin-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { authorityPinConflictMessage } from './authority-pin-copy';

test('C1 the sentence is exactly the reviewed copy', () => {
  assert.equal(authorityPinConflictMessage('Zed'),
    `A card for "Zed" doesn't match the one you already have, so it wasn't applied. Your existing contact is unchanged. Someone else may have access to their identity. Check with them another way before acting on this card.`);
});
test('C2 it does not tell anyone to re-share, and does not use the word pin', () => {
  const m = authorityPinConflictMessage('Zed').toLowerCase();
  assert.ok(!/re-?share|resend|send again/.test(m));
  assert.ok(!/\bpin\b/.test(m));
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
  const conflict = s.indexOf('authorityPinConflictMessage(peer.name)');
  const backfill = s.indexOf('await updateContact(existing.id');
  const reply = s.indexOf('void depositJoinerResponse(');
  assert.ok(conflict > 0 && backfill > 0 && reply > 0);
  assert.ok(conflict < backfill, 'the conflict check precedes the back-fill');
  assert.ok(conflict < reply, 'the conflict check precedes the joiner reply');
  assert.match(s.slice(conflict, conflict + 120), /return;/, 'it returns before reaching either');
});
