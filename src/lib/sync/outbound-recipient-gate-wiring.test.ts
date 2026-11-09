// Run: npx tsx --test src/lib/sync/outbound-recipient-gate-wiring.test.ts
// The call sites that need a live browser or a real agent directory. Source pins: each one must read the book at send time and pass the check on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const src = (p: string) => readFileSync(join(process.cwd(), p), 'utf8');
function between(s: string, from: string, to: string): string {
  const a = s.indexOf(from);
  assert.ok(a >= 0, `missing: ${from}`);
  const b = s.indexOf(to, a + from.length);
  assert.ok(b > a, `missing: ${to}`);
  return s.slice(a, b);
}

test('Notes: Send hands sendNoteFromInbox a loader that reads the book then', () => {
  const body = between(src('src/components/notes/NotesInbox.tsx'), 'const onSend = async', 'const onComposeKey');
  assert.match(body, /loadRecipientGate:\s*async \(\) => recipientGateFromBook\(await getAllContacts\(fp\)\)/);
});

test('Joiner: the ceremony reads the book before depositing and passes the check', () => {
  const body = between(src('src/components/JoinerCeremony.tsx'), 'async function depositJoinerResponse', 'export function JoinerCeremony');
  const read = body.indexOf('blockedInBook(await getAllContacts(ownerFp))');
  const send = body.indexOf('await sendJoinerResponse(');
  assert.ok(read >= 0 && send > read, 'the book is read before the deposit');
  assert.match(body.slice(send), /\{\s*isBlocked\s*\}/);
});

test('devin-comm join passes a blocked check taken from its own book', () => {
  const body = between(src('scripts/devin-comm.ts'), "if (cmd === 'join')", 'admit: (contact) => store.upsertContact(contact)');
  assert.match(body, /isBlocked:\s*blockedInBook\(store\.listContacts\(\)\)/);
});

for (const [cmd, stateful] of [['send-tr', 'withWriterLockAsync'], ['send', 'sendNoteFromHeadless(']] as const) {
  test(`devin-comm ${cmd} refuses a blocked peer before ${stateful}`, () => {
    const s = src('scripts/devin-comm.ts');
    const start = s.indexOf(`if (cmd === '${cmd}')`);
    assert.ok(start >= 0);
    const body = s.slice(start);
    const gate = body.indexOf('recipientGateFromBook(store.listContacts())(fp)');
    const after = body.indexOf(stateful);
    assert.ok(gate >= 0 && after > gate, 'the book is checked before any state moves');
    assert.match(body.slice(gate, after), /formatNotSent\(fp, /);
    assert.match(body.slice(gate, after), /process\.exitCode = 1; return;/);
  });
}

test('the send paths have no default that could admit everyone', () => {
  assert.doesNotMatch(src('src/lib/messaging/transport.ts'), /admit\?:/);
  assert.doesNotMatch(src('src/components/notes/notes-send.ts'), /loadRecipientGate\?:/);
  const joiner = src('src/lib/sync/send-joiner-response.ts');
  assert.doesNotMatch(joiner, /isBlocked\?:/);
  assert.doesNotMatch(between(joiner, 'export async function sendJoinerResponse', '): Promise<JoinerResponseSendResult>'), /= \{\}/);
});
