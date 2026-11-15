// What the restore screen says when a restore fails: decided by the error's type and code, never by its message text.
// Run: node --import tsx --test src/lib/identity/restore-errors.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyRestoreFailure, RestoreFormatUnrecognized, RestoreStoppedPartway, RestoreStoppedNothingSaved, RestoreMayHaveSaved, RESTORE_MESSAGES, contactsReportLines } from './restore-errors';
import { EnvelopeRefused } from '../crypto/password-envelope';

const lookalike = (code: string, message: string) => Object.assign(new Error(message), { code });

test('R1 the errors that really mean a wrong password map to the wrong-password message (a v4 vault gets its recovery-code wording)', () => {
  const envelope = lookalike('wrong-password', 'Incorrect encryption password.');
  const vault = lookalike('vault-could-not-open', 'Could not open vault — wrong passphrase or the file was altered');
  for (const e of [envelope, vault]) {
    assert.deepEqual(classifyRestoreFailure(e), { code: 'wrong-password', message: RESTORE_MESSAGES.wrongPassword });
    assert.deepEqual(classifyRestoreFailure(e, { v4Vault: true }), { code: 'wrong-password', message: RESTORE_MESSAGES.wrongPasswordVaultV4 });
  }
  assert.match(RESTORE_MESSAGES.wrongPassword, /^That password didn't open this file\./);
  assert.match(RESTORE_MESSAGES.wrongPasswordVaultV4, /recovery code/);
});

test('R1b a BARE OperationError is NOT a wrong password: WebCrypto raises it from any failed decrypt, including a step after the file opened', () => {
  const gcm = new DOMException('The operation failed for an operation-specific reason', 'OperationError');
  assert.deepEqual(classifyRestoreFailure(gcm), { code: 'unknown', message: RESTORE_MESSAGES.unknown });
  assert.deepEqual(classifyRestoreFailure(gcm, { v4Vault: true }), { code: 'unknown', message: RESTORE_MESSAGES.unknown });
  assert.deepEqual(classifyRestoreFailure(Object.assign(new Error('x'), { name: 'OperationError' })), { code: 'unknown', message: RESTORE_MESSAGES.unknown });
});

test('R2 NOTHING ELSE reads as a wrong password: an error whose text merely mentions a password, a passphrase or decrypting is not one, and its text is never shown', () => {
  const texts = [
    'Set or enter your device passphrase before importing a plaintext backup — imported keys are encrypted at rest, never stored in the clear.',
    'Could not decrypt the index', 'invalid password policy', 'passphrase', 'password', 'decrypt failed: OperationError', 'Session locked — refusing to store keys without a passphrase',
  ];
  for (const t of texts) {
    const f = classifyRestoreFailure(new Error(t));
    assert.equal(f.code, 'unknown', t);
    assert.equal(f.message, RESTORE_MESSAGES.unknown);
    assert.ok(!f.message.includes(t.slice(0, 12)) || t.length < 12, 'the error text is not echoed');
  }
  for (const junk of [undefined, null, 'a string', 42, {}, { code: 'nope' }, { name: 'SomethingElse' }]) assert.equal(classifyRestoreFailure(junk).code, 'unknown');
});

test('R3 each typed failure has its own sentence: needs-device-passphrase, unsupported format, an unrecognised file, and a refused envelope (its own fixed sentence, nothing echoed)', () => {
  const needs = classifyRestoreFailure(lookalike('needs-device-passphrase', 'Set or enter your device passphrase before importing...'));
  assert.deepEqual(needs, { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.needsDevicePassphrase });
  assert.ok(!/incorrect|wrong/i.test(needs.message), 'and it does not say the password was wrong');
  assert.deepEqual(classifyRestoreFailure(lookalike('vault-unsupported', 'Unsupported vault format: x v9')), { code: 'unsupported-format', message: RESTORE_MESSAGES.unsupportedFormat });
  const un = classifyRestoreFailure(new RestoreFormatUnrecognized());
  assert.equal(un.code, 'unrecognized-format');
  assert.equal(un.message, RESTORE_MESSAGES.unrecognizedFormat);
  assert.doesNotMatch(un.message, /contacts export|sovereign/i, 'it must not name a contacts export as restorable');
  // an envelope the app will not run vs a file that is not an envelope: two sentences, by the envelope's own code, never its text
  for (const c of ['unknown-kdf', 'unsafe-params'] as const) assert.deepEqual(classifyRestoreFailure(new EnvelopeRefused(c, 'This file asks for settings this version will not run.')), { code: 'envelope-refused', message: RESTORE_MESSAGES.unsupportedFormat }, c);
  for (const c of ['bad-field', 'not-an-envelope'] as const) assert.deepEqual(classifyRestoreFailure(new EnvelopeRefused(c, 'This file is missing its salt.')), { code: 'envelope-refused', message: RESTORE_MESSAGES.unrecognizedFormat }, c);
});

test('R2 a stopped restore says what the device holds by the comparison: nothing saved, part saved, or may have been saved (and never "nothing changed" when it could not be read)', () => {
  assert.deepEqual(classifyRestoreFailure(new RestoreStoppedNothingSaved()), { code: 'stopped-nothing-saved', message: RESTORE_MESSAGES.stoppedNothingSaved });
  assert.deepEqual(classifyRestoreFailure(new RestoreStoppedPartway()), { code: 'stopped-partway', message: RESTORE_MESSAGES.stoppedPartway });
  assert.deepEqual(classifyRestoreFailure(new RestoreMayHaveSaved()), { code: 'may-have-saved', message: RESTORE_MESSAGES.mayHaveBeenSaved });
  assert.equal(RESTORE_MESSAGES.stoppedNothingSaved, 'The restore stopped before any of your data was saved. Run the restore again with the same file.');
  assert.match(RESTORE_MESSAGES.mayHaveBeenSaved, /^Part of it may have been saved on this device\./);
  assert.doesNotMatch(RESTORE_MESSAGES.mayHaveBeenSaved, /nothing (on this device )?was changed|before any of your data was saved/i, 'an unreadable comparison never claims nothing was saved or changed');
  assert.doesNotMatch(RESTORE_MESSAGES.stoppedNothingSaved, /nothing (on this device )?was changed/i, 'the salt can change, so this line never claims the device is untouched');
  assert.doesNotMatch(RESTORE_MESSAGES.stoppedPartway, /nothing (on this device )?was changed/i);
});

// ---------- the screen and the throwers use it ----------
const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const code = (s: string) => s.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

test('R4 [static] the restore handler decides by classifyRestoreFailure: no regular expression is tested against an error\'s message, and the typed throw replaced the plain one', () => {
  const fe = code(read('../../components/SoverentityFrontend.tsx'));
  const handler = fe.slice(fe.indexOf('const handleVaultRestore = async'), fe.indexOf('const handleVaultRestore = async') + 14000);
  assert.ok(/classifyRestoreFailure\(err/.test(handler), 'the catch uses the classifier');
  assert.ok(!/looksLikeDecryptFail/.test(handler), 'the old substring test is gone');
  assert.ok(!/\/[^/\n]*(decrypt|passphrase|password)[^/\n]*\/i?\.test\(msg\)/i.test(handler), 'no /…password…/.test(msg)');
  assert.ok(!/throw new Error\('Unrecognized backup format/.test(handler) && /throw new RestoreFormatUnrecognized\(\)/.test(handler));
});

test('R5 [static] the errors the screen has to tell apart are typed where they are thrown (vault, importAll), with the same message texts', () => {
  const vault = code(read('../sync/vault.ts'));
  assert.ok(!/throw new Error\('Could not open vault/.test(vault) && /throw new VaultCouldNotOpen\(\)/.test(vault));
  assert.ok(!/throw new Error\(`Unsupported vault format/.test(vault) && (vault.match(/throw new VaultUnsupportedFormat\(/g) ?? []).length === 2);
  const store = code(read('./client-store.ts'));
  assert.ok(!/throw new Error\('Set or enter your device passphrase/.test(store) && /throw new PlaintextImportNeedsSession\(\)/.test(store));
  assert.match(read('../sync/vault.ts'), /Could not open vault — wrong passphrase or the file was altered/, 'the message text is unchanged');
  assert.match(read('./client-store.ts'), /Set or enter your device passphrase before importing a plaintext backup/, 'and so is this one');
});

test('R5 contact report lines: a line only when its count is above zero, "kept as they are" says so when a block was tightened, and no forbidden word appears', () => {
  assert.deepEqual(contactsReportLines({}), []);
  assert.deepEqual(contactsReportLines({ alreadyPresent: 0, blockTightened: 0 }), []);
  assert.deepEqual(contactsReportLines({ alreadyPresent: 3 }), ['3 contacts were already on this device and were kept as they are.']);
  assert.deepEqual(contactsReportLines({ blockTightened: 2 }), ['2 contacts blocked in your backup are now blocked on this device too.']);
  assert.deepEqual(contactsReportLines({ alreadyPresent: 3, blockTightened: 1 }), [
    '3 contacts were already on this device and were kept as they are, apart from the blocks below.',
    '1 contact blocked in your backup is now blocked on this device too.',
  ]);
  assert.deepEqual(contactsReportLines({ alreadyPresent: 1 }), ['1 contact was already on this device and was kept as it is.']);
  const all = [contactsReportLines({ alreadyPresent: 5, blockTightened: 4 }), contactsReportLines({ alreadyPresent: 1 })].flat().join(' ');
  assert.doesNotMatch(all, /merged|updated|synced|removed|unblock|lifted|cleared/i);
});

test('R6 RULE: the screen never gets an error\'s own text. Every failure maps to one of the RESTORE_MESSAGES constants, whatever the error says', () => {
  const sentences = new Set<string>(Object.values(RESTORE_MESSAGES));
  const marker = 'ZZ-DISTINCT-ERROR-TEXT-ZZ';
  const errors: unknown[] = [
    new Error(marker), lookalike('wrong-password', marker), lookalike('vault-could-not-open', marker), lookalike('needs-device-passphrase', marker),
    lookalike('vault-unsupported', marker), lookalike('restore-format-unrecognized', marker), lookalike('restore-stopped-partway', marker), lookalike('needs-device-password', marker), new RestoreFormatUnrecognized(),
    new EnvelopeRefused('unknown-kdf', marker), new EnvelopeRefused('unsafe-params', marker), new EnvelopeRefused('bad-field', marker), new EnvelopeRefused('not-an-envelope', marker),
    new DOMException(marker, 'OperationError'), undefined, null, 'a string', 42, {},
  ];
  for (const e of errors) for (const ctx of [{}, { v4Vault: true }]) {
    const f = classifyRestoreFailure(e, ctx);
    assert.ok(sentences.has(f.message), `a constant, for ${String((e as { code?: unknown })?.code ?? (e as { name?: unknown })?.name ?? e)}`);
    assert.ok(!f.message.includes(marker), 'the error text is never shown');
  }
});
