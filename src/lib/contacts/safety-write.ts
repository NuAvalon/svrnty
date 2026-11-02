// A write that protects the owner (block, trust demotion, go-private, the unlock privacy sweep) must not lose a race to a write a contact can
// provoke (the poll applying their update). The contact write is a compare-and-swap with a bounded number of attempts, so without this a
// stream of updates could make a block lose its comparison every time and not be saved.
//
// The rule is one exclusive lock per contact, shared by every tab of the origin (Web Locks, name `svrnty-contact:<id>`):
//   - a safety write takes the lock and waits its turn (it also waits for a poll write that is already in flight);
//   - the poll takes it only if it is free (`ifAvailable`) and otherwise DEFERS that contact: its change stays on the relay and is applied
//     on a later poll, not dropped; the poll holds the lock while it writes, so a safety write never races it.
// A lock is released when its callback settles, throws, or the tab dies, so a failed safety write cannot leave a contact deferred forever.
//
// Where `navigator.locks` does not exist (old browsers, the headless store) the fallback is an in-memory per-contact count within this
// context: it protects a single tab, which is the best that context can do.
//
// DO NOT nest withSafetyWrite for the same contact (the inner request would wait on the outer forever). Wrap the write once, at the handler.
//
// Run: npx tsx --test src/lib/contacts/safety-write.test.ts

export const SAFETY_LOCK_PREFIX = 'svrnty-contact:';
/** How long a safety write waits for the lock before it gives up with an error (a frozen holder must not hang the unlock path). */
export const SAFETY_LOCK_WAIT_MS = 10_000;

export function safetyLockName(contactId: string): string {
  return `${SAFETY_LOCK_PREFIX}${contactId}`;
}

/** The part of LockManager used here, so a test can supply a fake. */
export interface LockManagerLike {
  request(
    name: string,
    options: { mode?: 'exclusive' | 'shared'; ifAvailable?: boolean; signal?: AbortSignal },
    callback: (lock: unknown) => Promise<unknown> | unknown,
  ): Promise<unknown>;
}

function defaultLocks(): LockManagerLike | null {
  try {
    const nav = (globalThis as { navigator?: { locks?: LockManagerLike } }).navigator;
    return nav?.locks ?? null;
  } catch {
    return null;
  }
}

// Fallback state: contacts with a safety write in flight in THIS context.
const pending = new Map<string, number>();

export class SafetyLockTimeout extends Error {
  constructor(readonly contactId: string) {
    super(`could not take the lock for contact ${contactId} within ${SAFETY_LOCK_WAIT_MS} ms`);
    this.name = 'SafetyLockTimeout';
  }
}

/** Run a safety write for `contactId` under the exclusive per-contact lock. Resolves with what `run` resolves with. */
export async function withSafetyWrite<T>(
  contactId: string,
  run: () => Promise<T>,
  locks: LockManagerLike | null = defaultLocks(),
  waitMs: number = SAFETY_LOCK_WAIT_MS,
): Promise<T> {
  if (locks) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), waitMs);
    try {
      return (await locks.request(safetyLockName(contactId), { mode: 'exclusive', signal: ctl.signal }, async () => {
        clearTimeout(timer); // granted: the wait is over; the write itself is not on a clock
        return run();
      })) as T;
    } catch (e) {
      if ((e as { name?: string } | null)?.name === 'AbortError') throw new SafetyLockTimeout(contactId);
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }
  pending.set(contactId, (pending.get(contactId) ?? 0) + 1);
  try {
    return await run();
  } finally {
    const n = (pending.get(contactId) ?? 1) - 1;
    if (n <= 0) pending.delete(contactId); else pending.set(contactId, n);
  }
}

export type PollWrite<T> = { deferred: true } | { deferred: false; value: T };

/**
 * Run a poll-driven write for `contactId` only if no safety write holds (or waits on) the contact. `deferred: true` means it was NOT run:
 * the caller must leave the update where it can be applied on a later poll. While `run` executes it holds the contact's lock, so a safety
 * write that arrives meanwhile waits for it to finish.
 */
export async function pollWriteUnlessSafety<T>(
  contactId: string,
  run: () => Promise<T>,
  locks: LockManagerLike | null = defaultLocks(),
): Promise<PollWrite<T>> {
  if (locks) {
    return (await locks.request(safetyLockName(contactId), { mode: 'exclusive', ifAvailable: true }, async (lock) => {
      if (!lock) return { deferred: true } as PollWrite<T>;
      return { deferred: false, value: await run() } as PollWrite<T>;
    })) as PollWrite<T>;
  }
  if ((pending.get(contactId) ?? 0) > 0) return { deferred: true };
  return { deferred: false, value: await run() };
}

/** For tests: forget the fallback state. */
export function resetSafetyWriteFallbackForTests(): void {
  pending.clear();
}
