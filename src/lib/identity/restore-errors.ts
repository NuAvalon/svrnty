// src/lib/identity/restore-errors.ts
// What the restore screen tells the owner when a restore fails, decided by the error's TYPE and CODE, never by what its message happens to say.
//
// The screen used to test the message with /decrypt|passphrase|password|could not open vault/ and show "Incorrect encryption password" on any match. A message
// that merely mentions a passphrase (for instance "Set or enter your device passphrase before importing...", thrown AFTER the file had opened perfectly) was
// reported as a wrong password: the owner was told they typed it wrong when the real problem was elsewhere, and a real "your backup can't restore" fault hid
// behind it. Now only the errors that really mean a wrong password map to that message; every other failure has its own fixed sentence, and an error nobody
// classified shows one generic sentence that echoes nothing from the error. (Same rule as the #532 fix: an inconsistent record is never read as a wrong
// password.)

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

export type RestoreFailureCode =
  | 'wrong-password'
  | 'envelope-refused'
  | 'needs-device-passphrase'
  | 'unsupported-format'
  | 'unrecognized-format'
  | 'stopped-partway'
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
  chooseDevicePasswordNoFilePassword: 'This backup file has no password of its own. Choose a password of at least 12 characters to protect your keys on this device.',
  nothingSavedYet: 'Nothing has been saved yet.',
  stoppedPartway: 'The restore stopped partway, and part of it was saved on this device. Run the restore again with the same file to finish it.',
  keyOnlyRestored: 'Your identity key is saved on this device. This file holds only the key, not your profile or contacts. To bring those back, restore a full backup file.',
  unsupportedFormat: "This backup uses a format this version of the app can't read.",
  unrecognizedFormat: "This app can't open this file. It isn't a backup it recognizes.",
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
  if (codeOf(err) === 'needs-device-password') return { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.chooseDevicePasswordWeakFile };
  if (codeOf(err) === 'needs-device-passphrase') return { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.needsDevicePassphrase };
  if (codeOf(err) === 'vault-unsupported') return { code: 'unsupported-format', message: RESTORE_MESSAGES.unsupportedFormat };
  if (codeOf(err) === 'restore-format-unrecognized') return { code: 'unrecognized-format', message: RESTORE_MESSAGES.unrecognizedFormat };
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
