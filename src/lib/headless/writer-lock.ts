/**
 * One writer per agent dir (Flint 2026-10-24, store race part 3). poll-json, send, send-tr, grow, join,
 * admit and admit-gate all read-modify-write store.json / ratchet-sessions.json / gate.json /
 * issued-codes.json. Two processes interleaving lose each other's update; on ratchet-sessions.json a lost
 * update means the next send re-uses a chain index (key reuse). So every mutation runs inside this lock,
 * scoped to one read-modify-write unit: acquire → RE-READ from disk → mutate → writeFileAtomic → release.
 *
 *  - Lock = mkdir <dir>/.writer.lock (atomic) holding owner.json {pid, start, started, cmd}.
 *  - Stale = owner process gone: kill(pid, 0) → ESRCH, dead-but-unreaped (a zombie still answers
 *    kill(pid, 0) and keeps its /proc row — /proc/<pid>/stat state field reports it; only with one thread
 *    left: a leader whose main thread exited also shows Z while its other threads run on), or the pid was
 *    reused (its /proc start time no longer matches the recorded one). A lock dir with no owner.json
 *    past OWNERLESS_STALE_MS is a crash between
 *    mkdir and the owner write. Valid because poll-json runs via docker exec INSIDE the container's pid ns
 *    and bare-metal runs in the host ns: holder and waiter always share a pid namespace.
 *  - Takeover is serialized by a second, short-lived mkdir lock (.writer.lock.takeover) so two takers can't
 *    both judge the same stale lock and one rename away the other's fresh, live lock. Under it the taker
 *    re-checks staleness, renames the dead lock to .writer.lock.stale.<rand> and removes it.
 *  - Bounded wait (default 30s), then throw. Never proceed unlocked.
 *  - Re-entrant within a process (depth count per dir), so a locked unit can call locked helpers.
 */
import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';

export const LOCK_NAME = '.writer.lock';
const OWNERLESS_STALE_MS = 5_000;
const TAKEOVER_STALE_MS = 10_000;

export interface WriterLockOpts {
  waitMs?: number;
  pollMs?: number;
  cmd?: string;
}

interface Owner {
  pid: number;
  start: string;
  started: string;
  cmd: string;
}

const depth = new Map<string, number>();

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Process start time (clock ticks since boot, /proc/<pid>/stat field 22); '' where /proc is unavailable. */
function procStart(pid: number): string {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19] ?? '';
  } catch {
    return '';
  }
}

/** Thread count (/proc/<pid>/status Threads:); 0 where /proc is unavailable. */
function procThreads(pid: number): number {
  try {
    const m = /^Threads:\s*(\d+)/m.exec(readFileSync(`/proc/${pid}/status`, 'utf8'));
    return m ? Number(m[1]) : 0;
  } catch {
    return 0;
  }
}

/** Process state letter (/proc/<pid>/stat field 3: R/S/Z/…); '' where /proc is unavailable. */
function procState(pid: number): string {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[0] ?? '';
  } catch {
    return '';
  }
}

function ownerAlive(o: Owner): boolean {
  try {
    process.kill(o.pid, 0);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EPERM') return false;   // ESRCH: gone
  }
  // zombie: answers kill, dead-but-unreaped. Z with >1 thread = the leader exited but other threads still run (and
  // may still write), so it stays alive; an unreadable count also stays alive (never risk two writers).
  if (procState(o.pid) === 'Z' && procThreads(o.pid) === 1) return false;
  const now = procStart(o.pid);
  return !(o.start && now && now !== o.start);                            // same pid, different process = reused
}

function readOwner(lockDir: string): Owner | null {
  try {
    const o = JSON.parse(readFileSync(join(lockDir, 'owner.json'), 'utf8'));
    return typeof o?.pid === 'number' ? (o as Owner) : null;
  } catch {
    return null;
  }
}

function ageMs(path: string): number {
  try {
    return Date.now() - statSync(path).mtimeMs;
  } catch {
    return 0;
  }
}

/** True when the lock at lockDir is held by a dead process (or was orphaned before its owner was written). */
function isStale(lockDir: string): boolean {
  const o = readOwner(lockDir);
  if (!o) return ageMs(lockDir) > OWNERLESS_STALE_MS;
  return !ownerAlive(o);
}

function tryTakeover(lockDir: string): void {
  const guard = `${lockDir}.takeover`;
  try {
    mkdirSync(guard, { mode: 0o700 });
  } catch {
    if (ageMs(guard) > TAKEOVER_STALE_MS) rmSync(guard, { recursive: true, force: true });  // a taker crashed mid-takeover
    return;
  }
  try {
    if (!isStale(lockDir)) return;                                        // re-check under the guard
    const dead = `${lockDir}.stale.${randomBytes(6).toString('hex')}`;
    try {
      renameSync(lockDir, dead);
    } catch {
      return;                                                             // already gone
    }
    rmSync(dead, { recursive: true, force: true });
  } finally {
    rmSync(guard, { recursive: true, force: true });
  }
}

/** Acquire the agent-dir writer lock; returns the release function. Throws after waitMs. */
export function acquireWriterLock(dir: string, opts: WriterLockOpts = {}): () => void {
  const held = depth.get(dir) ?? 0;
  let released = false;
  const release = () => {
    if (released) return;                                                 // a double release must never drop someone else's lock
    released = true;
    const d = (depth.get(dir) ?? 1) - 1;
    if (d > 0) {
      depth.set(dir, d);
      return;
    }
    depth.delete(dir);
    rmSync(join(dir, LOCK_NAME), { recursive: true, force: true });
  };
  if (held > 0) {
    depth.set(dir, held + 1);
    return release;
  }
  const lockDir = join(dir, LOCK_NAME);
  const deadline = Date.now() + (opts.waitMs ?? 30_000);
  for (;;) {
    try {
      mkdirSync(lockDir, { mode: 0o700 });
      const owner: Owner = {
        pid: process.pid,
        start: procStart(process.pid),
        started: new Date().toISOString(),
        cmd: opts.cmd ?? process.argv.slice(2, 3).join(' '),
      };
      writeFileSync(join(lockDir, 'owner.json'), JSON.stringify(owner), { flag: 'wx', mode: 0o600 });
      depth.set(dir, 1);
      return release;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
    }
    if (isStale(lockDir)) {
      tryTakeover(lockDir);
      continue;
    }
    if (Date.now() >= deadline) {
      const o = readOwner(lockDir);
      throw new Error(
        `${lockDir} held by pid ${o?.pid ?? '?'} (${o?.cmd ?? '?'}, since ${o?.started ?? '?'}): ` +
        'gave up waiting; nothing was written. Retry once it finishes.',
      );
    }
    sleepSync(opts.pollMs ?? 50);
  }
}

export function withWriterLock<T>(dir: string, fn: () => T, opts?: WriterLockOpts): T {
  const release = acquireWriterLock(dir, opts);
  try {
    return fn();
  } finally {
    release();
  }
}

export async function withWriterLockAsync<T>(dir: string, fn: () => Promise<T>, opts?: WriterLockOpts): Promise<T> {
  const release = acquireWriterLock(dir, opts);
  try {
    return await fn();
  } finally {
    release();
  }
}
