// src/lib/crypto/argon2-worker-core.ts
// What the Argon2 worker does with one request, as a pure function so the worker file is only glue and tests can run the real logic without a worker.
//
// Argon2id at the app's parameters (64 MiB, t=3) takes seconds on the thread that runs it. On the main thread that is a frozen page (the vault export and
// restore freeze), and the library's own "async" variant does not help: it yields with a microtask, which lets neither a paint nor a tap through. So the
// derivation runs here, in a worker, and the page stays alive.

import { deriveKeyArgon2idBytes } from './kdf';

export interface Argon2Request {
  /** UTF-8 passphrase bytes, TRANSFERRED to the worker (the page no longer holds them). */
  passphrase: ArrayBuffer;
  salt: ArrayBuffer;
  params: { time_cost: number; memory_cost: number; parallelism: number };
}

export type Argon2Response =
  | { ok: true; key: ArrayBuffer }
  /** `reason` is one of the fixed strings below or a parameter-limit message; it never contains the passphrase. */
  | { ok: false; reason: string };

/** The first thing the worker says, as soon as its script has loaded: "I started". An error event before this is a start failure; after it, the worker ran. */
export const ARGON2_READY = Object.freeze({ ready: true as const });
export type Argon2Ready = typeof ARGON2_READY;

export const ARGON2_BAD_REQUEST = 'argon2: bad request';
export const ARGON2_FAILED = 'argon2: derivation failed';

/**
 * Derive the key for one request. The limits are checked here again even though the page checked them before it started a worker: a worker is a
 * separate entry point, and the clamp must not depend on who calls it. The passphrase bytes are zeroed before this returns, on every path.
 */
export function handleArgon2Request(req: unknown, derive: typeof deriveKeyArgon2idBytes = deriveKeyArgon2idBytes): Argon2Response {
  const r = req as Partial<Argon2Request> | null;
  if (!r || !(r.passphrase instanceof ArrayBuffer) || !(r.salt instanceof ArrayBuffer) || !r.params || typeof r.params !== 'object') {
    return { ok: false, reason: ARGON2_BAD_REQUEST };
  }
  const pass = new Uint8Array(r.passphrase);
  let key: Uint8Array | null = null;
  try {
    key = derive(pass, new Uint8Array(r.salt), r.params);
    // slice() so the transferred buffer is exactly the key, whatever the library's backing buffer is; the original is wiped below, so the worker's heap
    // does not keep the derived key until the worker is terminated.
    return { ok: true, key: key.slice().buffer };
  } catch (e) {
    const msg = e instanceof Error ? e.message : '';
    // The only messages worth passing through are the parameter limits (a hostile file's numbers, never the passphrase); anything else is one fixed string.
    return { ok: false, reason: /^(KDF |Unsupported KDF)/.test(msg) ? msg : ARGON2_FAILED };
  } finally {
    pass.fill(0);
    if (key) key.fill(0);
  }
}
