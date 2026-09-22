// src/lib/crypto/argon2-async.ts
// Off-main-thread wrapper for deriveKeyArgon2id (task #542; Flint crypto-design #140287).
//
// A 64 MiB pure-JS Argon2id (noble is sync-only) run inline froze the tab for seconds on mobile during
// vault export AND restore (packVault:365 / unpackVault:488) — a broken safety-net on the only device
// backup path. This spawns a first-party worker that runs the SAME deriveKeyArgon2id, so the UI thread
// stays responsive and the derived key is byte-identical to the sync path (→ old .svrnty files still
// restore; ZERO compat risk — Flint's do-no-harm bar for the recovery path).
//
// Node / SSR (no Worker global) falls back to the sync path — there is no UI thread to protect there,
// and it keeps packVault/unpackVault unit-testable. A worker LOAD failure in the BROWSER rejects
// LOUDLY: never a silent sync fallback that would re-introduce the freeze or mask a bundling break.
import { deriveKeyFromPassphraseBytes } from './argon2-core';
import type { Argon2Params } from './kdf';

interface DeriveResponse {
  ok: boolean;
  key?: ArrayBuffer;
  error?: string;
}

export function deriveKeyArgon2idAsync(
  passphrase: string,
  salt: Uint8Array,
  params: Argon2Params,
): Promise<Uint8Array> {
  if (typeof Worker === 'undefined') {
    // Node / SSR / no-Worker env: no UI thread to protect; run the SAME derivation the worker runs
    // (encode → deriveKeyFromPassphraseBytes) so the fallback is byte-identical to the worker path.
    return Promise.resolve(
      deriveKeyFromPassphraseBytes(new TextEncoder().encode(passphrase), salt, params),
    );
  }
  return new Promise<Uint8Array>((resolve, reject) => {
    const worker = new Worker(new URL('./argon2-worker.ts', import.meta.url), { type: 'module' });
    const passphraseBytes = new TextEncoder().encode(passphrase);
    worker.onmessage = (e: MessageEvent<DeriveResponse>) => {
      worker.terminate();
      if (e.data?.ok && e.data.key) resolve(new Uint8Array(e.data.key));
      else reject(new Error(e.data?.error || 'Argon2 worker failed'));
    };
    worker.onerror = (err: ErrorEvent) => {
      worker.terminate();
      reject(new Error(`Argon2 worker failed to load: ${err.message || 'unknown error'}`));
    };
    // Transfer the passphrase bytes (not clone) so the main-thread copy is neutered (Flint #3).
    worker.postMessage({ passphraseBytes, salt, params }, [passphraseBytes.buffer]);
  });
}
