// src/lib/crypto/kdf-offthread.ts
// Argon2id for the page: the same derivation as kdf.ts deriveKeyArgon2id, run in a worker so the page does not freeze for the seconds it takes.
//
// Why not the library's own async variant: it "yields" with a microtask, which lets neither a paint nor a tap through. Measured here: 64 MiB, t=3,
// the longest gap between two timer ticks was 2,581 ms synchronous and 2,460 ms with the async variant; the keys were identical.
//
// Rules this file keeps:
//  - The parameter limits are checked BEFORE anything is spawned (and again inside the worker): a hostile file's numbers never start a derivation.
//  - The passphrase goes to the worker as TRANSFERRED bytes (the page's copy is detached) and the worker zeroes them; the string the caller passed
//    in cannot be wiped (strings are immutable), which is true of every caller of the synchronous path too.
//  - One worker per derivation, terminated when it answers or fails: nothing keeps key material or 64 MiB alive between uses.
//  - Where no worker can be had (no Worker global, as in node tests; or the browser refuses to start one) the SAME derivation runs on the calling
//    thread. That keeps a backup possible; it also means a policy that blocks the worker shows up as a freeze, which the browser test for this
//    file measures, not as a failure.

import { assertParamsWithinLimits, deriveKeyArgon2id } from './kdf';
import { ARGON2_FAILED, type Argon2Request, type Argon2Response } from './argon2-worker-core';

export interface Argon2WorkerLike {
  onmessage: ((ev: { data: unknown }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  onmessageerror: ((ev: unknown) => void) | null;
  postMessage(msg: unknown, transfer?: Transferable[]): void;
  terminate(): void;
}
export type Argon2WorkerFactory = () => Argon2WorkerLike | null | Promise<Argon2WorkerLike | null>;

/**
 * The real worker: a same-origin script (the page's policy allows 'self' and refuses blob: workers). null where there is no Worker global. The module
 * that names the script is loaded on demand, so importing this file never touches `import.meta` (see kdf-worker-factory.ts).
 */
export const realWorkerFactory: Argon2WorkerFactory = async () => {
  if (typeof Worker === 'undefined') return null;
  return (await import('./kdf-worker-factory')).createArgon2Worker();
};

export async function deriveKeyArgon2idOffThread(
  passphrase: string,
  salt: Uint8Array,
  params: { time_cost: number; memory_cost: number; parallelism: number },
  factory: Argon2WorkerFactory = realWorkerFactory,
): Promise<Uint8Array> {
  assertParamsWithinLimits(params); // a rejected promise, before any worker exists

  let worker: Argon2WorkerLike | null = null;
  try { worker = await factory(); } catch { worker = null; }
  if (!worker) return deriveKeyArgon2id(passphrase, salt, params);
  const w = worker;

  return new Promise<Uint8Array>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      w.onmessage = null; w.onerror = null; w.onmessageerror = null;
      try { w.terminate(); } catch { /* already gone */ }
      fn();
    };
    const onThisThread = () => finish(() => {
      try { resolve(deriveKeyArgon2id(passphrase, salt, params)); } catch (e) { reject(e); }
    });

    w.onmessage = (ev) => {
      const res = ev.data as Argon2Response | undefined;
      if (res && res.ok === true && res.key instanceof ArrayBuffer) finish(() => resolve(new Uint8Array(res.key)));
      else finish(() => reject(new Error(res && res.ok === false && typeof res.reason === 'string' ? res.reason : ARGON2_FAILED)));
    };
    // The worker could not load or start (e.g. the page's policy refused it): same derivation, this thread.
    w.onerror = onThisThread;
    w.onmessageerror = () => finish(() => reject(new Error(ARGON2_FAILED)));

    // Copies that are exactly the bytes (a view onto a larger buffer would send the whole buffer); the original passphrase bytes are wiped here, and the
    // caller's salt is never the thing that gets transferred.
    const pass = new TextEncoder().encode(passphrase);
    const passBuf = pass.slice().buffer as ArrayBuffer;
    pass.fill(0);
    const saltBuf = salt.slice().buffer as ArrayBuffer;
    const req: Argon2Request = { passphrase: passBuf, salt: saltBuf, params: { time_cost: params.time_cost, memory_cost: params.memory_cost, parallelism: params.parallelism } };
    try { w.postMessage(req, [passBuf, saltBuf]); } catch { onThisThread(); }
  });
}
