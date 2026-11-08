// src/lib/relay/mldsa-verify-pool.server.ts — SERVER ONLY (imported by the relay route handlers, never by client code).
// ML-DSA-87 verification (~20 ms of CPU) moved OFF the event loop that also serves the website. The owner routes inject
// `verifyMlDsaPooled` into verifyOwnerRequestV2 (its `deps.mlDsaVerify`), so the browser bundle never sees worker_threads.
//
// - A small pool of worker threads (RELAY_MLDSA_WORKERS, default min(4, cores - 1)), each importing @noble/post-quantum.
// - A BOUNDED queue: at most RELAY_MLDSA_QUEUE_MAX jobs waiting beyond the ones running. A full queue throws
//   OwnerVerifyBusyError → the route's uniform 503, decided synchronously BEFORE any verify work.
// - Each job has a timeout (5 s): a job that times out reads as a failed verify (false), and its worker is replaced.
// - If the workers can't run (no worker_threads, the module won't load), verification falls back to the main thread, so v2
//   owners are never locked out by the pool itself. The process-wide verify budget (owner-verify-budget.ts) still caps that path.
//   Logged once.
//
// The global budget and this pool are both required: the budget bounds total verify work per second, and the pool keeps whatever
// verify work is admitted off the thread that answers GET /.

import { cpus } from 'node:os';
import { Worker } from 'node:worker_threads';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { OwnerVerifyBusyError } from './owner-verify-budget';
import { logDeposit429 } from './deposit-429-log';

const JOB_TIMEOUT_MS = 5_000;

// Inline worker source (the runtime image has no src/ tree, only node_modules, so the worker can't be a file on disk).
const WORKER_SRC = `
const { parentPort } = require('node:worker_threads');
let mod = null;
parentPort.on('message', async (j) => {
  try {
    mod = mod || (await import(j.specifier));
    parentPort.postMessage({ id: j.id, ok: mod.ml_dsa87.verify(j.sig, j.msg, j.pub) === true });
  } catch (e) {
    parentPort.postMessage({ id: j.id, unavailable: true });
  }
});
`;

interface Job { id: number; sig: Uint8Array; msg: Uint8Array; pub: Uint8Array; resolve: (ok: boolean) => void; timer?: ReturnType<typeof setTimeout> }
interface Slot { worker: Worker; job: Job | null }
interface Pool { slots: Slot[]; queue: Job[]; nextId: number; broken: boolean; stats: { pooled: number; inline: number; shed: number; timeouts: number } }

declare global {
  var __mldsaPool: Pool | undefined;
}

function intEnv(name: string, def: number): number {
  const n = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : def;
}
const workerCount = () => intEnv('RELAY_MLDSA_WORKERS', Math.max(1, Math.min(4, cpus().length - 1)));
const queueMax = () => intEnv('RELAY_MLDSA_QUEUE_MAX', 32);
/** Test seam: the module the workers import (a wrong one simulates "the workers can't load ML-DSA"). */
const specifier = () => process.env.RELAY_MLDSA_WORKER_MODULE_TEST ?? '@noble/post-quantum/ml-dsa.js';

function inline(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): boolean {
  try { return ml_dsa87.verify(sig, msg, pub) === true; } catch { return false; }
}

function markBroken(p: Pool): void {
  if (p.broken) return;
  p.broken = true;
  console.warn('relay mldsa pool unavailable: verifying on the main thread (still capped by the owner verify budget)');
  for (const s of p.slots) void s.worker.terminate().catch(() => {});
  p.slots = [];
  for (const j of p.queue.splice(0)) j.resolve(inline(j.sig, j.msg, j.pub));
}

function spawn(p: Pool): Slot {
  const worker = new Worker(WORKER_SRC, { eval: true });
  const slot: Slot = { worker, job: null };
  worker.on('message', (m: { id: number; ok?: boolean; unavailable?: boolean }) => {
    const job = slot.job;
    if (!job || job.id !== m.id) return;
    clearTimeout(job.timer);
    slot.job = null;
    slot.worker.unref();
    if (m.unavailable) {
      job.resolve(inline(job.sig, job.msg, job.pub));
      markBroken(p);
      return;
    }
    p.stats.pooled++;
    job.resolve(m.ok === true);
    pump(p);
  });
  worker.on('error', () => replace(p, slot, false));
  worker.unref(); // idle workers never keep the process alive; a worker is ref'd only while it holds a job (pump / done)
  return slot;
}

function replace(p: Pool, slot: Slot, timedOut: boolean): void {
  const job = slot.job;
  slot.job = null;
  if (job) { clearTimeout(job.timer); if (timedOut) p.stats.timeouts++; job.resolve(false); }
  void slot.worker.terminate().catch(() => {});
  const i = p.slots.indexOf(slot);
  if (i >= 0 && !p.broken) {
    try { p.slots[i] = spawn(p); } catch { markBroken(p); }
  }
  pump(p);
}

function pump(p: Pool): void {
  for (const slot of p.slots) {
    if (slot.job || p.queue.length === 0) continue;
    const job = p.queue.shift()!;
    slot.job = job;
    slot.worker.ref(); // a pending verify must keep the process alive until it settles
    job.timer = setTimeout(() => replace(p, slot, true), JOB_TIMEOUT_MS);
    job.timer.unref?.();
    slot.worker.postMessage({ id: job.id, sig: job.sig, msg: job.msg, pub: job.pub, specifier: specifier() });
  }
}

function pool(): Pool {
  if (globalThis.__mldsaPool) return globalThis.__mldsaPool;
  const p: Pool = { slots: [], queue: [], nextId: 1, broken: false, stats: { pooled: 0, inline: 0, shed: 0, timeouts: 0 } };
  globalThis.__mldsaPool = p;
  try {
    for (let i = 0; i < workerCount(); i++) p.slots.push(spawn(p));
  } catch {
    markBroken(p);
  }
  return p;
}

/**
 * Verify an ML-DSA-87 signature off the event loop. Resolves true/false. THROWS OwnerVerifyBusyError synchronously-at-submit when
 * the bounded queue is full (the caller's route turns that into the uniform 503). Falls back to the main thread if the pool can't run.
 */
export function verifyMlDsaPooled(sig: Uint8Array, msg: Uint8Array, pub: Uint8Array): Promise<boolean> {
  const p = pool();
  if (p.broken) { p.stats.inline++; return Promise.resolve(inline(sig, msg, pub)); }
  const busySlots = p.slots.filter((s) => s.job).length;
  if (busySlots >= p.slots.length && p.queue.length >= queueMax()) {
    p.stats.shed++;
    logDeposit429('owner_verify_busy');
    throw new OwnerVerifyBusyError();
  }
  return new Promise<boolean>((resolve) => {
    p.queue.push({ id: p.nextId++, sig, msg, pub, resolve });
    pump(p);
  });
}

/** Counters (tests + metrics). */
export function mldsaPoolStats(): Pool['stats'] & { workers: number; broken: boolean; queued: number } {
  const p = pool();
  return { ...p.stats, workers: p.slots.length, broken: p.broken, queued: p.queue.length };
}

/** Test seam: tear the pool down (the next call builds a fresh one with the current env). */
export async function resetMldsaPool(): Promise<void> {
  const p = globalThis.__mldsaPool;
  globalThis.__mldsaPool = undefined;
  if (!p) return;
  for (const j of p.queue.splice(0)) j.resolve(false);
  await Promise.all(p.slots.map((s) => { if (s.job) { clearTimeout(s.job.timer); s.job.resolve(false); } return s.worker.terminate().catch(() => 0); }));
}
