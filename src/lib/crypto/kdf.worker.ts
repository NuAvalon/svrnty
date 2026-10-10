// src/lib/crypto/kdf.worker.ts
// Web Worker: runs the memory-hard Argon2id OFF the main thread (#542).
//
// WHY: deriveKeyArgon2id (kdf.ts) is a SYNCHRONOUS pure-JS noble argon2id at
// m=64MB. On the main UI thread that call blocks for seconds — the vault
// export/restore "freeze" Peter reported (worst on a memory-constrained Android
// PWA). Moving the SAME computation into a worker keeps the UI responsive.
//
// INVARIANT: this is the identical noble argon2id with the identical params the
// sync path uses — the derived key is BYTE-IDENTICAL, the .svrnty format is
// unchanged, and old backups still open. Only the thread moves; zero crypto
// change. Param validation (F1 clamp) is enforced by the WRAPPER
// (deriveKeyArgon2idAsync) before it posts here, exactly as the sync path runs
// assertParamsWithinLimits at the derivation point.
import { argon2id } from '@noble/hashes/argon2.js';

export interface KdfWorkerRequest {
  id: number;
  passphrase: string;
  salt: Uint8Array;
  time_cost: number;
  memory_cost: number; // KiB
  parallelism: number;
  dkLen: number;
}

export type KdfWorkerResponse =
  | { id: number; key: Uint8Array }
  | { id: number; error: string };

self.onmessage = (e: MessageEvent<KdfWorkerRequest>) => {
  const { id, passphrase, salt, time_cost, memory_cost, parallelism, dkLen } = e.data;
  try {
    const key = argon2id(new TextEncoder().encode(passphrase), salt, {
      t: time_cost,
      m: memory_cost,
      p: parallelism,
      dkLen,
    });
    // Transfer the key buffer (not copy) — it leaves this worker's heap.
    (self as unknown as Worker).postMessage({ id, key } as KdfWorkerResponse, [key.buffer]);
  } catch (err) {
    (self as unknown as Worker).postMessage({
      id,
      error: err instanceof Error ? err.message : 'kdf worker error',
    } as KdfWorkerResponse);
  }
};
