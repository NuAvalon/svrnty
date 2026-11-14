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
  constructor() { super('Unrecognized backup format. Expected a sovereign backup, contacts export, or identity file.'); this.name = 'RestoreFormatUnrecognized'; }
}

export type RestoreFailureCode =
  | 'wrong-password'
  | 'envelope-refused'
  | 'needs-device-passphrase'
  | 'unsupported-format'
  | 'unrecognized-format'
  | 'unknown';

export interface RestoreFailure { code: RestoreFailureCode; message: string }

const codeOf = (e: unknown): string | undefined => (e && typeof e === 'object' ? (e as { code?: unknown }).code as string | undefined : undefined);
const nameOf = (e: unknown): string | undefined => (e && typeof e === 'object' ? (e as { name?: unknown }).name as string | undefined : undefined);

/** The sentences. The first two are the screen's existing wording; the others are drafts for the copy owner (they say what happened, in plain words). */
export const RESTORE_MESSAGES = Object.freeze({
  wrongPasswordVaultV4: 'Incorrect passphrase. Try again, or recover with your recovery code below.',
  wrongPassword: 'Incorrect encryption password. Use the password you set when you exported this copy.',
  needsDevicePassphrase: 'This backup opened, but it could not be saved on this device: a device passphrase has to be set first.',
  keyOnlyRestored: 'Your identity key is saved on this device. This file holds only the key, not your profile or contacts. To bring those back, restore a full backup file.',
  unsupportedFormat: 'This file is in a format this version does not read.',
  unknown: 'This backup could not be restored.',
});

/**
 * Classify a restore failure. `ctx.v4Vault`: the file is a v4 vault (its own wording offers the recovery code). Decided by identity only:
 *  - AES-GCM's authentication failure (a DOMException named OperationError) and the vault's typed VaultCouldNotOpen are the wrong-password errors;
 *  - EnvelopeRefused carries its own fixed sentence (a file this version will not try: it names no secret and echoes nothing from the file);
 *  - the typed needs-device-passphrase, unsupported-format and unrecognized-format errors each have their own sentence;
 *  - anything else is 'unknown': one generic sentence, never the error's own text.
 */
export function classifyRestoreFailure(err: unknown, ctx: { v4Vault?: boolean } = {}): RestoreFailure {
  if (nameOf(err) === 'OperationError' || codeOf(err) === 'vault-could-not-open') {
    return { code: 'wrong-password', message: ctx.v4Vault ? RESTORE_MESSAGES.wrongPasswordVaultV4 : RESTORE_MESSAGES.wrongPassword };
  }
  if (nameOf(err) === 'EnvelopeRefused') return { code: 'envelope-refused', message: (err as Error).message };
  if (codeOf(err) === 'needs-device-passphrase') return { code: 'needs-device-passphrase', message: RESTORE_MESSAGES.needsDevicePassphrase };
  if (codeOf(err) === 'vault-unsupported') return { code: 'unsupported-format', message: RESTORE_MESSAGES.unsupportedFormat };
  if (codeOf(err) === 'restore-format-unrecognized') return { code: 'unrecognized-format', message: (err as Error).message };
  return { code: 'unknown', message: RESTORE_MESSAGES.unknown };
}
