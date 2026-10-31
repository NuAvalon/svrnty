// src/lib/messaging/peer-session-lock.ts
//
// R5: one exclusive lock per (owner, peer) ratchet session, held across the WHOLE load -> advance -> persist cycle.
// The session row is a read-modify-write. Two tabs (or an overlapping poll and a send) that both read the same state each advance
// it and the last write wins: a SEND would reuse one message key for two different plaintexts, and a RECEIVE would lose the other's
// advance and skipped-key consumption (a replay window for an already-consumed key). navigator.locks is the cross-tab primitive;
// the version check on the row (store.ts, putRatchetSession) is the net underneath it for a browser or context without locks.
//
// Waiting is BOUNDED. A holder that never releases (a frozen tab mid-await) must not hang every send and receive to that peer:
// after LOCK_WAIT_MS the acquire throws RatchetSessionBusyError and the caller fails closed with no session state touched (a send
// is "not sent", a receive stays retryable in the mailbox).

export class RatchetSessionBusyError extends Error {
  constructor() {
    super('ratchet session busy: another tab or task is using it; nothing was changed');
    this.name = 'RatchetSessionBusyError';
  }
}

export type LockRelease = () => void;

export const LOCK_WAIT_MS = 10_000;

/** `tr:<owner>:<peer>`. The notes DB is per identity, so two identities talking to the same peer must not block each other. */
export function peerSessionLockName(ownerScope: string | undefined, peerFingerprint: string): string {
  return `tr:${ownerScope ? `${ownerScope}:` : ''}${peerFingerprint}`;
}

type LockManagerLike = {
  request: (
    name: string,
    options: { mode: 'exclusive'; signal: AbortSignal },
    callback: () => Promise<void>,
  ) => Promise<unknown>;
};

function webLocks(): LockManagerLike | null {
  const nav = typeof navigator !== 'undefined' ? (navigator as unknown as { locks?: LockManagerLike }) : undefined;
  return nav?.locks && typeof nav.locks.request === 'function' ? nav.locks : null;
}

// In-process fallback (no navigator.locks): a promise chain per name. Same exclusivity inside one JS context; cross-context safety
// then rests on the version check alone.
const tails = new Map<string, Promise<void>>();

function acquireInProcess(name: string, waitMs: number): Promise<LockRelease> {
  const prev = tails.get(name) ?? Promise.resolve();
  let release!: LockRelease;
  const mine = new Promise<void>((r) => { release = () => r(); });
  const tail = prev.then(() => mine);
  tails.set(name, tail);
  void tail.then(() => { if (tails.get(name) === tail) tails.delete(name); });
  return new Promise<LockRelease>((resolve, reject) => {
    const timer = setTimeout(() => {
      release(); // give our slot back so waiters queued behind us are not blocked by a request that gave up
      reject(new RatchetSessionBusyError());
    }, waitMs);
    void prev.then(() => { clearTimeout(timer); resolve(release); });
  });
}

function acquireWeb(locks: LockManagerLike, name: string, waitMs: number): Promise<LockRelease> {
  return new Promise<LockRelease>((resolve, reject) => {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), waitMs);
    let release!: LockRelease;
    const held = new Promise<void>((r) => { release = () => r(); });
    locks
      .request(name, { mode: 'exclusive', signal: abort.signal }, async () => {
        clearTimeout(timer);
        resolve(release);
        await held; // the lock stays held until the caller releases
      })
      .catch((e: unknown) => {
        clearTimeout(timer);
        reject((e as { name?: string })?.name === 'AbortError' ? new RatchetSessionBusyError() : e);
      });
  });
}

/** Wait (bounded) for the exclusive lock `name`. The returned release is idempotent. */
export function acquirePeerSessionLock(name: string, waitMs: number = LOCK_WAIT_MS): Promise<LockRelease> {
  const locks = webLocks();
  return locks ? acquireWeb(locks, name, waitMs) : acquireInProcess(name, waitMs);
}
