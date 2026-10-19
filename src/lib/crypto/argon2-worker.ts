/// <reference lib="webworker" />
// First-party Web Worker — runs the 64 MiB pure-JS Argon2id (noble) OFF the main thread so vault
// export/restore never freezes the UI (task #542; Flint crypto-design #140287).
//
// The derivation lives in argon2-core.ts (shared with the node fallback), which CALLS the existing
// deriveKeyArgon2id verbatim → the F1 param-guard and the argon2id primitive come along unchanged →
// the key is BYTE-IDENTICAL to the main-thread path BY CONSTRUCTION, so every existing .svrnty file
// still restores. Statically bundled + first-party (Flint hygiene #4) — never load worker code from a
// remote/dynamic source (a swappable KDF worker = a key-derivation injection path).
//
// Passphrase hygiene (Flint #3): the passphrase arrives as TRANSFERRED bytes (main's copy neutered, no
// clone); argon2-core zeros them after deriving; the key is returned as a TRANSFERABLE ArrayBuffer
// (main zeros it after importKey — pack:372 / unpack:498).
import { deriveKeyFromPassphraseBytes } from './argon2-core';
import type { Argon2Params } from './kdf';

interface DeriveRequest {
  passphraseBytes: Uint8Array;
  salt: Uint8Array;
  params: Argon2Params;
}

self.addEventListener('message', (e: MessageEvent<DeriveRequest>) => {
  const { passphraseBytes, salt, params } = e.data;
  const scope = self as unknown as DedicatedWorkerGlobalScope;
  try {
    const out = deriveKeyFromPassphraseBytes(passphraseBytes, salt, params);
    scope.postMessage({ ok: true, key: out.buffer }, [out.buffer]);
  } catch (err) {
    passphraseBytes.fill(0);
    scope.postMessage({
      ok: false,
      error: err instanceof Error ? err.message : 'argon2 derivation failed',
    });
  }
});
