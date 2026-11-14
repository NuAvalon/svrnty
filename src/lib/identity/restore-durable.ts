// src/lib/identity/restore-durable.ts — #532 C1: a seed restore carries the identity's DURABLE epoch and id instead of hard-coding genesis.
/**
 * The seed bundle (PrivateKeyBundle, inside the AES-GCM body that only the seed opens, so these fields are authenticated) carries:
 *   durable_epoch        the key epoch of the identity when the bundle was sealed (genesis = 0)
 *   durable_fingerprint  the DURABLE id (the genesis fingerprint; it never changes across rotations, while identity_fingerprint does)
 * Restore reads them here and derives the authority pin for epoch + 1. Before this, restore wrote epoch 0, the CURRENT fingerprint
 * as the durable id and the commitment for epoch 1, which is wrong for any identity that has rotated even once.
 *
 * Rules (fail-closed; a refusal never echoes the bundle's bytes):
 *  - durable_epoch absent -> 0 (every bundle sealed before this field is a genesis bundle: nothing rotated before #816 existed).
 *  - present -> a safe integer >= 0, else refuse.
 *  - durable_fingerprint absent -> allowed ONLY at epoch 0, where the durable id IS the current fingerprint. At epoch > 0 an absent
 *    durable id cannot be reconstructed, so refuse rather than guess (guessing the current fp breaks the second rotation, R7.3).
 *  - present -> a canonical fingerprint (64 lowercase hex, any epoch: a malformed durable id would break the NEXT rotation, R7.3);
 *    at epoch 0 it must EQUAL the current fingerprint (a genesis identity has one id).
 * Pure: no I/O, no clock, no secrets. The caller derives the commitment from the master secret.
 */

const CANONICAL_FP = /^[0-9a-f]{64}$/;

export const RESTORE_DURABLE_CODE = 'restore-durable';
/** The ONE user-facing string. The recovery code DID open the bundle, so it must never read as a wrong code; the reason stays out of it. */
export const RESTORE_DURABLE_MESSAGE = "This backup file can't be used: the identity record inside it is inconsistent. Nothing was restored.";

export class RestoreDurableRefused extends Error {
  readonly code = RESTORE_DURABLE_CODE;
  /** For logs and tests only; never shown. */
  constructor(public readonly reason: 'bad-epoch' | 'missing-durable-id' | 'bad-durable-id' | 'genesis-id-mismatch') {
    super(RESTORE_DURABLE_MESSAGE);
    this.name = 'RestoreDurableRefused';
  }
}

/** Recognisable without instanceof (the restore module is loaded by a dynamic import, so class identity is not guaranteed). */
export function isRestoreDurableRefusal(e: unknown): e is RestoreDurableRefused {
  return typeof e === 'object' && e !== null && (e as { code?: unknown }).code === RESTORE_DURABLE_CODE;
}

export interface SeedBundleDurable {
  durable_epoch?: unknown;
  durable_fingerprint?: unknown;
}

export interface RestoredDurable {
  fingerprint: string;
  epoch: number;
  /** The epoch whose authority commitment the restored identity pins next: epoch + 1. */
  nextCommitmentEpoch: number;
}

export function durableFromSeedBundle(bundle: SeedBundleDurable, currentFingerprint: string): RestoredDurable {
  const rawEpoch = bundle.durable_epoch;
  let epoch = 0;
  if (rawEpoch !== undefined) {
    if (typeof rawEpoch !== 'number' || !Number.isSafeInteger(rawEpoch) || rawEpoch < 0) throw new RestoreDurableRefused('bad-epoch');
    epoch = rawEpoch;
  }
  // epoch + 1 must stay a safe integer for the derivation
  if (!Number.isSafeInteger(epoch + 1)) throw new RestoreDurableRefused('bad-epoch');
  const rawId = bundle.durable_fingerprint;
  let fingerprint: string;
  if (rawId === undefined) {
    if (epoch !== 0) throw new RestoreDurableRefused('missing-durable-id');
    fingerprint = currentFingerprint;
  } else {
    if (typeof rawId !== 'string' || !CANONICAL_FP.test(rawId)) throw new RestoreDurableRefused('bad-durable-id');
    if (epoch === 0 && rawId !== currentFingerprint) throw new RestoreDurableRefused('genesis-id-mismatch');
    fingerprint = rawId;
  }
  return { fingerprint, epoch, nextCommitmentEpoch: epoch + 1 };
}
