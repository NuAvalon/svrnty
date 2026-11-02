// D2 (Hypatia #776 / Flint #769): the "Triple ratchet is off for <name>" line. It must be TRUE when shown, absent when we cannot tell,
// and there is no "on" line at all: after commit 4a nothing in this app starts a ratchet, so we never announce one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NOTES_COPY, ratchetOffMessage } from './notes-copy';
import { showRatchetOffLine } from './notes-status';

const send = { canSend: true, hasRatchetKeys: true };

test('showRatchetOffLine: shown only for a sendable peer with ratchet keys whose session has NOT received a frame', () => {
  assert.equal(showRatchetOffLine({ ...send, status: 'not-observed' }), true);
});

test('showRatchetOffLine: nothing extra for an observed peer (their app sent us a frame), and nothing when we cannot tell', () => {
  assert.equal(showRatchetOffLine({ ...send, status: 'observed' }), false);
  assert.equal(showRatchetOffLine({ ...send, status: 'unknown' }), false, 'unreadable/locked/other-owner: say nothing, do not guess');
});

test('showRatchetOffLine: not for a peer we cannot send to, nor one without ratchet keys', () => {
  assert.equal(showRatchetOffLine({ canSend: false, hasRatchetKeys: true, status: 'not-observed' }), false);
  assert.equal(showRatchetOffLine({ canSend: true, hasRatchetKeys: false, status: 'not-observed' }), false);
});

test('the line is exactly the ruled wording and never says the ratchet is on / enabled / forward secrecy / post-quantum', () => {
  assert.equal(
    ratchetOffMessage('Ana'),
    "Triple ratchet is off for Ana: this app doesn't start one yet. Messages are still end-to-end encrypted.",
  );
  assert.doesNotMatch(NOTES_COPY.ratchetOff, /ratchet (is|are) (on|enabled|active|running)|forward secrecy|post-quantum|quantum/i);
  assert.equal(ratchetOffMessage('{name}').includes('{name}'), true, 'the name is substituted once, not interpreted');
});

test('NotesInbox renders the ratchet line ONLY through showRatchetOffLine, and has no "on" copy', () => {
  const src = readFileSync(join(__dirname, 'NotesInbox.tsx'), 'utf8');
  assert.equal(src.split('ratchetOffMessage(').length - 1, 1, 'one render site');
  assert.match(src, /showRatchetOffLine\(\{[^}]*status: ratchetStatus/);
  assert.doesNotMatch(src, /ratchet is on|ratchet on for|Triple ratchet is (on|enabled)/i);
});
