// Bundled by esbuild and injected into the page by e2e/key-backup-double-hop.spec.ts. It asks the app's OWN functions whether the stored identity key is USABLE: the unlock gate that
// signing and decrypting share (unlockArmoredIdentityKey) and the owner message-key loader (loadOwnerRatchetIdentity: unlock with the stored passphrase, then assemble the x25519 and ML-KEM keys;
// it returns null on any failure, which is exactly the silent "unusable key" a backup must never leave behind). It reports booleans and a LENGTH only: never the passphrase or any key.
import { initSessionKey, listIdentities, loadIdentity, loadKey } from '@/lib/identity/client-store';
import { unlockArmoredIdentityKey } from '@/components/encrypt-decrypt/encrypt-decrypt-keys';
import { loadOwnerRatchetIdentity } from '@/lib/messaging/ratchet-keys';

export interface KeyProbe {
  fingerprint: string;
  hasKey: boolean;
  passphraseLength: number;
  unlocks: boolean;
  /** Only meaningful when an identity record exists (a key-only restore leaves none): null = not asked. */
  ownerMessageKeys: boolean | null;
}

declare global {
  interface Window {
    __ku: {
      init(passphrase: string): Promise<void>;
      /** `fingerprint` is for a device that has a key but no identity record (a key-only restore); otherwise the first stored identity is used. */
      probe(fingerprint?: string): Promise<KeyProbe>;
    };
  }
}

window.__ku = {
  init: (passphrase) => initSessionKey(passphrase) as unknown as Promise<void>,
  async probe(given) {
    const ids = await listIdentities();
    const fingerprint = given ?? String((ids[0] as { fingerprint?: unknown } | undefined)?.fingerprint ?? '');
    const key = fingerprint ? await loadKey(fingerprint) : null;
    let unlocks = false;
    if (key?.privateKey) {
      try { await unlockArmoredIdentityKey(key.privateKey, key.passphrase); unlocks = true; } catch { unlocks = false; }
    }
    const identity = fingerprint ? await loadIdentity(fingerprint) : null;
    const ownerMessageKeys = identity ? (await loadOwnerRatchetIdentity(fingerprint, identity)) !== null : null;
    return { fingerprint, hasKey: !!key?.privateKey, passphraseLength: key?.passphrase?.length ?? 0, unlocks, ownerMessageKeys };
  },
};
