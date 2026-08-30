// Thin UI helper — CALLS fleet session APIs only. Does not derive keys or invent crypto.
// Pattern mirrors app/page.tsx unlock: initSessionKey → loadKey → lockSession on failure.
//
// ⚠️ Wrong passphrase REPLACES the in-memory session key, then lockSession() clears it.
// Caller must treat 'wrong' / 'no-keys' as "session may now be locked — send user to unlock".

import {
  hasEncryptedKeys,
  initSessionKey,
  loadKey,
  lockSession,
} from '@/lib/identity/client-store';

export type UnlockVerifyResult = 'ok' | 'wrong' | 'no-keys' | 'skipped-plaintext';

/**
 * Re-verify the unlock passphrase before a sensitive export.
 * If keys are not encrypted-at-rest (legacy), returns 'skipped-plaintext'.
 */
export async function verifyUnlockPassphrase(
  fingerprint: string,
  passphrase: string,
): Promise<UnlockVerifyResult> {
  const encrypted = await hasEncryptedKeys(fingerprint);
  if (!encrypted) return 'skipped-plaintext';

  if (!passphrase || passphrase.length < 1) return 'wrong';

  try {
    await initSessionKey(passphrase);
    const key = await loadKey(fingerprint);
    if (!key) {
      lockSession();
      return 'no-keys';
    }
    return 'ok';
  } catch {
    lockSession();
    return 'wrong';
  }
}
