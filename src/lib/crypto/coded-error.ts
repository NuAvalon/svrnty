// src/lib/crypto/coded-error.ts
// A restore failure with a CODE. The restore screen decides what to tell the owner by this code, never by the error's message text: a message that merely mentions
// a hash or a seed phrase must not read as a wrong recovery code, and a thrower's own text is never put on the screen. No imports on purpose: the crypto and vault
// modules throw these, and they must not pull in any UI code.

export type RestoreThrowCode =
  | 'recovery-code-wrong'        // the recovery code opened nothing: the hash of its master secret is not the backup's
  | 'recovery-code-malformed'    // the recovery code is not in the form of 64 hex characters
  | 'vault-legacy-v2'            // an old format this app no longer opens
  | 'vault-not-a-vault'          // not a .svrnty vault at all
  | 'vault-v3-no-recovery'       // made before recovery codes existed
  | 'vault-no-recovery'          // recovery codes were never set up for this backup
  | 'vault-truncated'            // the file ends before its own header or body does
  | 'vault-recovery-unreadable'  // the recovery vault inside the backup cannot be read, or is malformed
  | 'identity-older-format'      // an identity from before post-quantum identities
  | 'recovery-pieces-insufficient'     // too few pieces that match the backup's list (or its master hash) to rebuild the recovery key
  | 'recovery-pieces-search-too-large'; // so many pieces handed, one of them bad, that trying the combinations is refused rather than cut short

/** The message is the thrower's own text and is for the console only. */
export class RestoreThrow extends Error {
  readonly code: RestoreThrowCode;
  constructor(code: RestoreThrowCode, message: string) {
    super(message);
    this.name = 'RestoreThrow';
    this.code = code;
  }
}
