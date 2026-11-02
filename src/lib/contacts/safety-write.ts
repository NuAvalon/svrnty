// A write that protects the owner (block, trust demotion, go-private, the unlock privacy sweep) must not lose to a write a contact can
// provoke (the poll applying their update). The contact write is a compare-and-swap with a bounded number of attempts, so without this a
// stream of updates could make a block lose its comparison every time and not be saved.
//
// The conflict domain is the whole BOOK, not one contact: every attempt also compares the book manifest, and an applied update sets the
// contact's version to a number the CONTACT chooses, so a version-bumped update from contact X changes the manifest and makes a block of
// contact Y lose its comparison. So the rule is book-wide, with two locks, always taken in this order (book, then contact):
//   - the BOOK lock `svrnty-contact-book`: a safety write takes it SHARED (safety writes do not wait on each other); the poll's write takes
//     it EXCLUSIVE and only if free (`ifAvailable`). So a poll write is deferred while any safety write is held or queued, and a safety
//     write waits only for a poll write that is already in flight;
//   - the CONTACT lock `svrnty-contact:<id>`: a safety write takes it EXCLUSIVE after the book lock, so two safety writes on the same contact
//     run one after the other.
// A deferred poll write leaves its update on the relay (the consumer returns `retryable`) and it is applied on a later poll, not dropped. A
// lock is released when its callback settles, throws, or the tab dies, so a failed safety write cannot leave the book deferred forever.
// Locks are shared by every tab of the origin (Web Locks).
//
// Where `navigator.locks` does not exist (old browsers, the headless store) the fallback is an in-memory count of safety writes in flight
// in THIS context: the poll defers while the count is above zero. In that fallback the poll does not mark the book while it runs, so a safety
// write in the same context can start alongside a poll write that is already running. That is correct, not an oversight: the poll writes once
// per tick and the compare-and-swap makes the safety write retry. It protects a single tab, which is the best that context can do.
//
// DO NOT nest withSafetyWrite (the inner request would wait on the outer for a contact lock forever if it is the same contact). Wrap the write
// once, at the handler.
//
// Run: npx tsx --test src/lib/contacts/safety-write.test.ts

import { ContactConflictError } from '../identity/contact-cas';

export const SAFETY_LOCK_PREFIX = 'svrnty-contact:';
export const SAFETY_BOOK_LOCK = 'svrnty-contact-book';
/** How long a safety write waits for each lock before it gives up with an error (a frozen holder must not hang the unlock path). */
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

// Fallback state: safety writes in flight in THIS context.
let pendingSafety = 0;

export class SafetyLockTimeout extends Error {
  constructor(readonly contactId: string) {
    super(`could not take the lock for contact ${contactId} within ${SAFETY_LOCK_WAIT_MS} ms`);
    this.name = 'SafetyLockTimeout';
  }
}

/** Run a safety write for `contactId` under the shared book lock and the exclusive contact lock. Resolves with what `run` resolves with. */
export async function withSafetyWrite<T>(
  contactId: string,
  run: () => Promise<T>,
  locks: LockManagerLike | null = defaultLocks(),
  waitMs: number = SAFETY_LOCK_WAIT_MS,
): Promise<T> {
  if (locks) {
    const take = async <R>(name: string, mode: 'shared' | 'exclusive', inner: () => Promise<R>): Promise<R> => {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), waitMs);
      try {
        return (await locks.request(name, { mode, signal: ctl.signal }, async () => {
          clearTimeout(timer); // granted: the wait is over; the write itself is not on a clock
          return inner();
        })) as R;
      } catch (e) {
        if ((e as { name?: string } | null)?.name === 'AbortError') throw new SafetyLockTimeout(contactId);
        throw e;
      } finally {
        clearTimeout(timer);
      }
    };
    return take(SAFETY_BOOK_LOCK, 'shared', () => take(safetyLockName(contactId), 'exclusive', run));
  }
  pendingSafety++;
  try {
    return await run();
  } finally {
    pendingSafety--;
  }
}

export type PollWrite<T> = { deferred: true } | { deferred: false; value: T };

/**
 * Run a poll-driven write only if no safety write holds (or waits on) the book. `deferred: true` means `run` was NOT run: the caller must
 * leave the update where it can be applied on a later poll. While `run` executes it holds the book lock, so a safety write that arrives
 * meanwhile waits for it to finish.
 */
export async function pollWriteUnlessSafety<T>(
  run: () => Promise<T>,
  locks: LockManagerLike | null = defaultLocks(),
): Promise<PollWrite<T>> {
  if (locks) {
    return (await locks.request(SAFETY_BOOK_LOCK, { mode: 'exclusive', ifAvailable: true }, async (lock) => {
      if (!lock) return { deferred: true } as PollWrite<T>;
      return { deferred: false, value: await run() } as PollWrite<T>;
    })) as PollWrite<T>;
  }
  if (pendingSafety > 0) return { deferred: true };
  return { deferred: false, value: await run() };
}

/**
 * The words for a protecting write that could not be saved because of contention (a lock wait that timed out, or the compare lost every
 * attempt), or null for any other error. `what` is the thing the owner did, e.g. "Block".
 */
export function describeSafetyWriteFailure(err: unknown, what: string): string | null {
  return err instanceof SafetyLockTimeout || err instanceof ContactConflictError ? `${what} not saved. Try again.` : null;
}

/** For tests: forget the fallback state. */
export function resetSafetyWriteFallbackForTests(): void {
  pendingSafety = 0;
}
