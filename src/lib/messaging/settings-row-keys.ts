// src/lib/messaging/settings-row-keys.ts
// #720: which keys may be written as encrypted rows in the notes DB's existing 'settings' store. Pure, so the rule is testable without
// IndexedDB. The store also holds ONE plaintext row, 'notes_encryption_salt' (the PBKDF2 salt, not a secret); nothing written through
// the encrypted-row API may be able to overwrite or delete it, so only these exact prefixes are allowed.

// 'notice_seen:' (#731): when the user last dismissed an inbox notice. One ISO time per notice, nothing from any message.
export const SETTINGS_ROW_PREFIXES = ['dead_letter:', 'reset_flag:', 'notice_seen:'] as const;

const MAX_KEY_LENGTH = 200;
// A plain charset: a key is built from validated parts, never from raw wire text.
const KEY_CHARS = /^[A-Za-z0-9._:-]+$/;

function plainKey(key: unknown): key is string {
  return typeof key === 'string' && key.length > 0 && key.length <= MAX_KEY_LENGTH && KEY_CHARS.test(key);
}

/** A key for ONE row: an allowed prefix followed by at least one more character. */
export function isAllowedSettingsRowKey(key: unknown): key is string {
  return plainKey(key) && SETTINGS_ROW_PREFIXES.some((p) => key.startsWith(p) && key.length > p.length);
}

/** A prefix to LIST by: exactly one of the allowed prefixes (so a list can never reach 'notes_encryption_salt'). */
export function isAllowedSettingsPrefix(prefix: unknown): prefix is string {
  return plainKey(prefix) && (SETTINGS_ROW_PREFIXES as readonly string[]).includes(prefix);
}
