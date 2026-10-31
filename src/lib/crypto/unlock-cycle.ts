// N10 (scratch prototype, shape per Flint #178198): ONE per-poll-cycle unlock context.
// The iterated-S2K decryptKey is ~65% of poll active time when paid per blob per decryptor; a cycle pays it once.
// Lifetime is the CYCLE, never the session: created at the start of a poll cycle, passed to every decryptor and
// the poll/ack signer of that cycle, dropped at cycle end, and unusable after any lock/identity switch.
// No module-level cache, and the passphrase is never used as a map key.
import { readPrivateKey, decryptKey, type PrivateKey } from 'openpgp';
import { onSessionLock } from '@/lib/identity/client-store';

// Bumped on lockSession AND setActiveFingerprint (the universal switch chokepoint) via the one session-lock hook.
// Registered once at module load: the hook list is append-only, so per-cycle registration would leak.
let lockEpoch = 0;
onSessionLock(() => {
  lockEpoch += 1;
});

export class UnlockCycleEnded extends Error {
  constructor() {
    super('unlock cycle ended (dropped or session locked/switched)');
    this.name = 'UnlockCycleEnded';
  }
}

export interface UnlockCycle {
  /** True once the cycle was dropped or the session locked/switched. Callers must treat everything after as UNDECIDED, never as "undecryptable". */
  readonly ended: boolean;
  /** The unlocked key, unlocked lazily once. A rejected unlock is NOT cached. Throws if the cycle was dropped or the session locked/switched. */
  key(): Promise<PrivateKey>;
  /** Release the reference. Idempotent. */
  drop(): void;
}

export function makeUnlockCycle(privateKeyArmored: string, passphrase: string, opts: { onUnlock?: () => void } = {}): UnlockCycle {
  const epoch = lockEpoch;
  let dropped = false;
  let pending: Promise<PrivateKey> | null = null;
  const live = () => !dropped && epoch === lockEpoch;
  return {
    get ended() {
      return !live();
    },
    key() {
      if (!live()) return Promise.reject(new UnlockCycleEnded());
      if (!pending) {
        opts.onUnlock?.();
        const p = (async () => decryptKey({ privateKey: await readPrivateKey({ armoredKey: privateKeyArmored }), passphrase }))();
        pending = p;
        p.catch(() => {
          if (pending === p) pending = null; // never cache a failure
        });
      }
      return pending.then((k) => {
        if (!live()) throw new UnlockCycleEnded();
        return k;
      });
    },
    drop() {
      dropped = true;
      pending = null;
    },
  };
}
