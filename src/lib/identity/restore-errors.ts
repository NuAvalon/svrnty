// src/lib/identity/restore-errors.ts
// What the restore screen tells the owner when a restore fails, decided by the error's TYPE and CODE, never by what its message happens to say.
//
// The screen used to test the message with /decrypt|passphrase|password|could not open vault/ and show "Incorrect encryption password" on any match. A message
// that merely mentions a passphrase (for instance "Set or enter your device passphrase before importing...", thrown AFTER the file had opened perfectly) was
// reported as a wrong password: the owner was told they typed it wrong when the real problem was elsewhere, and a real "your backup can't restore" fault hid
// behind it. Now only the errors that really mean a wrong password map to that message; every other failure has its own fixed sentence, and an error nobody
// classified shows one generic sentence that echoes nothing from the error. (Same rule as the #532 fix: an inconsistent record is never read as a wrong
// password.)

import { DEVICE_PASSWORD_MIN } from './device-password';

/** The restore screen could not recognise the file's shape at all. */
export class RestoreFormatUnrecognized extends Error {
  readonly code = 'restore-format-unrecognized' as const;
  constructor() { super("This app can't open this file. It isn't a backup it recognizes."); this.name = 'RestoreFormatUnrecognized'; }
}

/** A restore failed AFTER something was written (read back from the device, never guessed). The same file can be run again. */
export class RestoreStoppedPartway extends Error {
  readonly code = 'restore-stopped-partway' as const;
  constructor() { super('The restore stopped partway.'); this.name = 'RestoreStoppedPartway'; }
}

/** A restore failed and the device was compared with its state just before the first write: identical. Nothing of this owner was saved; the same file can be run again. */
export class RestoreStoppedNothingSaved extends Error {
  readonly code = 'restore-stopped-nothing-saved' as const;
  constructor() { super('The restore stopped before any of your data was saved.'); this.name = 'RestoreStoppedNothingSaved'; }
}

/** A restore failed and the comparison could not be read, so nothing may be claimed either way. */
export class RestoreMayHaveSaved extends Error {
  readonly code = 'restore-may-have-saved' as const;
  constructor() { super('The restore stopped; part of it may have been saved.'); this.name = 'RestoreMayHaveSaved'; }
}

export type RestoreFailureCode =
  | 'wrong-password'
  | 'envelope-refused'
  | 'needs-device-passphrase'
  | 'unsupported-format'
  | 'unrecognized-format'
  | 'stopped-partway'
  | 'stopped-nothing-saved'
  | 'may-have-saved'
  | 'wrong-recovery-code'
  | 'malformed-recovery-code'
  | 'file-truncated'
  | 'backup-unreadable'
  | 'older-identity-format'
  | 'legacy-v2'
  | 'v3-no-recovery'
  | 'no-recovery-vault'
  | 'unknown';

export interface RestoreFailure { code: RestoreFailureCode; message: string }

const codeOf = (e: unknown): string | undefined => (e && typeof e === 'object' ? (e as { code?: unknown }).code as string | undefined : undefined);
const nameOf = (e: unknown): string | undefined => (e && typeof e === 'object' ? (e as { name?: unknown }).name as string | undefined : undefined);

/** The sentences (copy owner's wording, ledger row 174). Every sentence the restore screen shows for a failure is one of these constants, never an error's own text. */
export const RESTORE_MESSAGES = Object.freeze({
  wrongPasswordVaultV4: "That passphrase didn't open this vault. Try again, or use your recovery code below.",
  wrongPassword: "That password didn't open this file. Use the password you set when you exported it.",
  needsDevicePassphrase: 'This backup opened, but this device has no password yet, so nothing was saved.',
  deviceUsesFilePassword: 'This device now unlocks with the same password as your backup file.',
  chooseDevicePasswordTitle: 'Choose a password for this device',
  chooseDevicePasswordWeakFile: "Your backup opened. Its password is shorter than 12 characters, so this device won't use it to unlock. Choose a new password of at least 12 characters. Your backup file keeps its old password.",
  chooseDevicePasswordNoFilePassword: `This backup file doesn't have its own password. Choose a password of at least ${DEVICE_PASSWORD_MIN} characters. It protects your keys on this device.`,
  nothingSavedYet: 'Nothing has been saved yet.',
  stoppedPartway: 'The restore stopped partway, and part of it was saved on this device. Run the restore again with the same file to finish it.',
  stoppedNothingSaved: 'The restore stopped before any of your data was saved. Run the restore again with the same file.',
  mayHaveBeenSaved: 'Part of it may have been saved on this device. Run the restore again with the same file.',
  keyOnlyRestored: 'Your identity key is saved on this device. This file holds only the key, not your profile or contacts. To bring those back, restore a full backup file.',
  unsupportedFormat: "This backup uses a format this version of the app can't read.",
  unrecognizedFormat: "This app can't open this file. It isn't a backup it recognizes.",
  // The recovery-code (seed) restore: decided by the thrower's code (coded-error.ts), copy rows 181-183.
  wrongRecoveryCode: "That recovery code doesn't match this backup.",
  malformedRecoveryCode: "That recovery code isn't in the right form. Check it and enter it again.",
  fileTruncated: "This file ends too early to be a complete backup, so it can't be restored. If you have another copy, try that one.",
  backupPartUnreadable: "Part of this backup can't be read, so it can't be restored. If you have another copy, try that one.",
  olderIdentityFormat: "This backup uses an older identity format that this version of the app can't restore.",
  legacyV2: 'This backup uses an old format this app no longer opens. If your identity is still open on another device, make a new backup there.',
  // These two name the buttons of the passphrase path (the v3 one: the button already on screen; the no-recovery-vault one: the step that brings it back); seed-restore-errors.test.ts pins both labels so they change together.
  v3NoRecovery: "This backup was made before recovery codes existed, so it can't be restored with a recovery code. Use its passphrase with Restore identity instead.",
  noRecoveryVault: "Recovery codes weren't set up for this backup, so it can't be restored with a recovery code. Press I have my passphrase, then Restore identity.",
  unknown: "Something went wrong and the restore didn't finish.",
});

/**
 * Classify a restore failure. `ctx.v4Vault`: the file is a v4 vault (its own wording offers the recovery code). Decided by identity only, and the message is ALWAYS
 * one of RESTORE_MESSAGES: no code path hands an error's own text to the screen.
 *  - the two TYPED wrong-password errors: EnvelopeWrongPassword (the file's own AES-GCM check, code 'wrong-password') and VaultCouldNotOpen. A BARE OperationError is
 *    not one: WebCrypto raises it from any failed decrypt, including steps after the file opened, and says nothing about the password the person typed;
 *  - EnvelopeRefused by its code: a method or settings this version will not run (unknown-kdf, unsafe-params) is an unsupported format; a file that is not an
 *    envelope or lacks a field (not-an-envelope, bad-field) is a file the app does not recognise;
 *  - the typed needs-device-passphrase, unsupported-format and unrecognized-format errors each have their own sentence;
 *  - the recovery-code restore's own codes (coded-error.ts) each have their own sentence (a platform SyntaxError is NOT classified here: the one place a header
 *    fails to parse, readVaultHeader, rethrows it as a coded error);
 *  - anything else is 'unknown': one generic sentence.
 */
export function classifyRestoreFailure(err: unknown, ctx: { v4Vault?: boolean } = {}): RestoreFailure {
  if (codeOf(err) === 'wrong-password' || codeOf(err) === 'vault-could-not-open') {
    return { code: 'wrong-password', message: ctx.v4Vault ? RESTORE_MESSAGES.wrongPasswordVaultV4 : RESTORE_MESSAGES.wrongPassword };
  }
  if (nameOf(err) === 'EnvelopeRefused') {
    const c = codeOf(err);
    return c === 'unknown-kdf' || c === 'unsafe-params'
      ? { code: 'envelope-refused', message: RESTORE_MESSAGES.unsupportedFormat }
      : { code: 'envelope-refused', message: RESTORE_MESSAGES.unrecognizedFormat };
  }
  if (codeOf(err) === 'restore-stopped-partway') return { code: 'stopped-partway', message: RESTORE_MESSAGES.stoppedPartway };
  if (codeOf(err) === 'restore-stopped-nothing-saved') return { code: 'stopped-nothing-saved', message: RESTORE_MESSAGES.stoppedNothingSaved };
  if (codeOf(err) === 'restore-may-have-saved') return { code: 'may-have-saved', message: RESTORE_MESSAGES.mayHaveBeenSaved };
  if (codeOf(err) === 'needs-device-password') return { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.chooseDevicePasswordWeakFile };
  if (codeOf(err) === 'needs-device-passphrase') return { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.needsDevicePassphrase };
  if (codeOf(err) === 'vault-unsupported') return { code: 'unsupported-format', message: RESTORE_MESSAGES.unsupportedFormat };
  if (codeOf(err) === 'restore-format-unrecognized') return { code: 'unrecognized-format', message: RESTORE_MESSAGES.unrecognizedFormat };
  const thrown = codeOf(err);
  if (thrown === 'recovery-code-wrong') return { code: 'wrong-recovery-code', message: RESTORE_MESSAGES.wrongRecoveryCode };
  if (thrown === 'recovery-code-malformed') return { code: 'malformed-recovery-code', message: RESTORE_MESSAGES.malformedRecoveryCode };
  if (thrown === 'vault-truncated') return { code: 'file-truncated', message: RESTORE_MESSAGES.fileTruncated };
  if (thrown === 'vault-recovery-unreadable') return { code: 'backup-unreadable', message: RESTORE_MESSAGES.backupPartUnreadable };
  if (thrown === 'vault-not-a-vault') return { code: 'unrecognized-format', message: RESTORE_MESSAGES.unrecognizedFormat };
  if (thrown === 'identity-older-format') return { code: 'older-identity-format', message: RESTORE_MESSAGES.olderIdentityFormat };
  if (thrown === 'vault-legacy-v2') return { code: 'legacy-v2', message: RESTORE_MESSAGES.legacyV2 };
  if (thrown === 'vault-v3-no-recovery') return { code: 'v3-no-recovery', message: RESTORE_MESSAGES.v3NoRecovery };
  if (thrown === 'vault-no-recovery') return { code: 'no-recovery-vault', message: RESTORE_MESSAGES.noRecoveryVault };
  return { code: 'unknown', message: RESTORE_MESSAGES.unknown };
}

/**
 * The two contact lines after a restore (copy row 173). Counts come from the importer's return value, never from the screen. A line appears only when its count
 * is above zero. A tightened block IS a change, so when both apply the first line says so. Nothing here says merged, updated, synced or removed, names a blocked
 * contact, or implies a block was lifted.
 */
export function contactsReportLines(report: { alreadyPresent?: number; blockTightened?: number }): string[] {
  const present = report.alreadyPresent ?? 0;
  const tightened = report.blockTightened ?? 0;
  const lines: string[] = [];
  if (present > 0) {
    const tail = tightened > 0 ? ', apart from the blocks below' : '';
    lines.push(present === 1
      ? `1 contact was already on this device and was kept as it is${tail}.`
      : `${present} contacts were already on this device and were kept as they are${tail}.`);
  }
  if (tightened > 0) {
    lines.push(tightened === 1
      ? '1 contact blocked in your backup is now blocked on this device too.'
      : `${tightened} contacts blocked in your backup are now blocked on this device too.`);
  }
  return lines;
}
