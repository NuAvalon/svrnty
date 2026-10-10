// src/lib/trust/relay-migration.ts
//
// Relay-switch MIGRATION ORCHESTRATOR — the keystone that makes "bring your own relay / move off
// svrnty.is" actually work. It is NOT the low-level pointer primitive (publishMailboxPointer) nor the
// legacy contact-model migration (migration.ts). It is the product-trust flow:
//
//     register new mailbox on the destination relay
//   → enumerate ALL trusted peers
//   → publish a monotonic epoch+1 mailbox-pointer to EACH (sealed to that peer's CURRENT mailbox)
//   → hold the overlap window (old mailbox keeps decapsulating in-flight deposits)
//   → retire the old mailbox ONLY once every peer is pointered AND the window has elapsed.
//
// Authored by Apollo (migration-semantics lane). Built to Flint's 5 security-review criteria
// (conch #169327) — each is annotated [F1]..[F5] at its enforcement point:
//   [F1] enumerate ALL trusted peers — no-peer-left-behind (an un-pointered peer = silent-loss of
//        their future deposits to a dead relay). A peer we FAIL to pointer is recorded, never skipped.
//   [F2] each pointer sealed to THAT peer's current mailbox — no peer-list / broadcast leak.
//   [F3] idempotent + RESUMABLE — crash mid-migrate → re-run completes, no skipped peer, no epoch reuse.
//   [F4] monotonic epoch+1 — one epoch per migration; a stale (lower) epoch can't roll the owner back.
//   [F5] overlap honored + old-stops-LOUD — retire only after all-pointered + window; the LOUD stop of
//        a post-retire stale-relay deposit is the downstream relay/consume gate (see note on retireAfter).
//
// The orchestrator is DEPENDENCY-INJECTED and PURE (no direct network/crypto): the caller (serve-daemon
// migrate / relay-config UI migrate-button / fed-qa run.sh migrate) wires the real
// publishMailboxPointer + registry + trust-store + a durable progress sink. This keeps the trust-graph
// logic auditable + unit-testable against the 5 criteria without standing up relays.

import type { MailboxPublicKeys } from '../crypto/mailbox-envelope.js';

/** A trusted peer to notify of the relay switch, with everything publishMailboxPointer needs. */
export interface MigratePeer {
  fingerprint: string;
  edPub: Uint8Array; // peer identity ed25519 pubkey (derives S_pair with my seed)
  did: string; // peer DID (rendezvous tag)
}

/** MY new mailbox's advertised pubkeys (registered on the destination relay), carried INSIDE each pointer. */
export interface NewMailboxAdvert {
  x25519Pub: Uint8Array;
  mlkemEk: Uint8Array;
}

/** Where a given peer opens the pointer we seal to them (their CURRENT mailbox) [F2]. */
export interface PeerSealTarget {
  sealTarget: MailboxPublicKeys;
  sealTargetFp: string;
}

/** Per-migration progress, persisted so a crash mid-migrate resumes without re-pointering done peers [F3]. */
export interface MigrateProgress {
  pointerEpoch: number;
  /** [F5] when THIS migration first started — anchors the overlap window across resumes (never recomputed). */
  startedAtMs: number;
  /** fingerprints already successfully pointered AT THIS epoch (idempotency key = fp@epoch). */
  pointeredFps: string[];
}

export interface MigrateRelayDeps {
  /** [F1] ALL trusted peers (the full set; the impl reads the decrypted trust store). */
  enumerateTrustedPeers: () => Promise<MigratePeer[]>;
  /** Register MY new mailbox on the destination relay (idempotent — safe to re-call on resume). */
  registerNewMailbox: () => Promise<NewMailboxAdvert>;
  /** [F2] Resolve a peer's CURRENT mailbox (registry GET /mailbox/{fp}, or identity-enc for bootstrap).
   *  Return null if genuinely unresolvable → that peer is a RECORDED FAILURE, never a silent skip. */
  resolvePeerSealTarget: (peer: MigratePeer) => Promise<PeerSealTarget | null>;
  /** Publish the epoch+1 pointer to one peer (wraps publishMailboxPointer). true iff deposited. */
  publishPointer: (args: {
    peer: MigratePeer;
    sealTarget: PeerSealTarget;
    newMailbox: NewMailboxAdvert;
    pointerEpoch: number;
  }) => Promise<boolean>;
  /** [F3] Load prior progress for THIS epoch (null on a fresh migration). */
  loadProgress: (pointerEpoch: number) => Promise<MigrateProgress | null>;
  /** [F3] Persist the whole progress (startedAt + pointered set) after each change → crash-resumable. */
  saveProgress: (progress: MigrateProgress) => Promise<void>;
}

export interface MigrateRelayOptions {
  /** [F4] The new mailbox rotation epoch. MUST be prevEpoch+1 (caller supplies; orchestrator asserts >=1). */
  pointerEpoch: number;
  /** [F5] How long the OLD mailbox must keep decapsulating in-flight deposits (default ~7d, cap 30d). */
  overlapWindowMs?: number;
  /** Injected clock (deterministic tests). */
  now?: () => number;
}

export interface MigrateRelayResult {
  pointerEpoch: number;
  totalPeers: number;
  /** Peers pointered this run OR already done (resumed). */
  pointeredFps: string[];
  /** [F1] Peers we could NOT pointer (unresolvable mailbox, or deposit failed) — migration INCOMPLETE. */
  failedFps: string[];
  /** True iff every trusted peer is pointered. Only then may the old mailbox be retired. */
  complete: boolean;
  /** [F5] The old mailbox's decap key stays valid until this epoch-ms; retire only when complete AND past it. */
  overlapUntil: number;
  /** [F5] Convenience: safe to retire the old mailbox now? (complete && now >= overlapUntil). */
  safeToRetire: boolean;
}

const DEFAULT_OVERLAP_MS = 7 * 24 * 60 * 60 * 1000; // ~7d (weekly-active peers come online + resolve)
const MAX_OVERLAP_MS = 30 * 24 * 60 * 60 * 1000; // satellite UNDELIVERED_MSG_TTL — beyond it old mail is GC'd

/**
 * Orchestrate a relay switch. Idempotent + resumable: call repeatedly (e.g. on a schedule or after a
 * crash) with the SAME pointerEpoch until `complete`. Never retires the old mailbox itself — it returns
 * `safeToRetire` so the caller retires under the overlap+complete gate [F5].
 */
export async function migrateRelay(
  deps: MigrateRelayDeps,
  opts: MigrateRelayOptions,
): Promise<MigrateRelayResult> {
  const now = opts.now ?? (() => Date.now());
  const pointerEpoch = opts.pointerEpoch;
  // [F4] monotonic: a rotation is epoch >= 1 (0 is bootstrap, not a migration). Reject a non-advancing epoch.
  if (!Number.isInteger(pointerEpoch) || pointerEpoch < 1) {
    throw new Error(`migrateRelay: pointerEpoch must be an integer >= 1 (rotation), got ${pointerEpoch}`);
  }
  // [F5] clamp the overlap to [0, 30d]; default ~7d.
  const overlapWindowMs = Math.min(Math.max(opts.overlapWindowMs ?? DEFAULT_OVERLAP_MS, 0), MAX_OVERLAP_MS);

  // Step 0: register my new mailbox on the destination (idempotent — safe on resume).
  const newMailbox = await deps.registerNewMailbox();

  // [F1] enumerate ALL trusted peers — the full set is the migration's scope.
  const peers = await deps.enumerateTrustedPeers();

  // [F3] resume: load prior progress for THIS epoch; init (persisting startedAt) on a fresh migration so the
  // overlap window is anchored to the migration START, not recomputed each run [F5].
  const prior = await deps.loadProgress(pointerEpoch);
  const progress: MigrateProgress =
    prior && prior.pointerEpoch === pointerEpoch
      ? prior
      : { pointerEpoch, startedAtMs: now(), pointeredFps: [] };
  if (!(prior && prior.pointerEpoch === pointerEpoch)) await deps.saveProgress(progress); // persist start
  const done = new Set<string>(progress.pointeredFps);

  const pointeredFps: string[] = [...done];
  const failedFps: string[] = [];

  for (const peer of peers) {
    if (done.has(peer.fingerprint)) continue; // [F3] already pointered this epoch → skip (idempotent)
    // [F2] seal to THIS peer's current mailbox — resolved per-peer, never a shared/broadcast target.
    let sealTarget: PeerSealTarget | null;
    try {
      sealTarget = await deps.resolvePeerSealTarget(peer);
    } catch {
      sealTarget = null;
    }
    if (!sealTarget) {
      failedFps.push(peer.fingerprint); // [F1] recorded, NOT silently skipped — migration stays incomplete
      continue;
    }
    let deposited = false;
    try {
      deposited = await deps.publishPointer({ peer, sealTarget, newMailbox, pointerEpoch });
    } catch {
      deposited = false;
    }
    if (deposited) {
      progress.pointeredFps.push(peer.fingerprint);
      await deps.saveProgress(progress); // [F3] persist after each success → crash-resumable
      pointeredFps.push(peer.fingerprint);
    } else {
      failedFps.push(peer.fingerprint); // [F1] deposit failed → recorded for retry, migration incomplete
    }
  }

  // [F1] complete iff EVERY trusted peer is pointered — no-peer-left-behind.
  const complete = failedFps.length === 0;
  // [F5] overlap: anchored to the migration START (persisted), so a later resume past the window flips
  // safeToRetire true. Old mailbox keeps decapsulating until this instant; retire only when complete AND elapsed.
  const overlapUntil = progress.startedAtMs + overlapWindowMs;
  return {
    pointerEpoch,
    totalPeers: peers.length,
    pointeredFps,
    failedFps,
    complete,
    overlapUntil,
    safeToRetire: complete && now() >= overlapUntil, // (window-start run → false; a later run past the window → true)
  };
}
