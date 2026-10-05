// src/lib/trust/mailbox-migration.ts
/**
 * Mailbox migration orchestrator — SAME-RELAY rekey (W4, day-1). KB#92332 / #92342 / #92346.
 *
 * Rotates MY device mailbox to a fresh random keypair and conveys the new mailbox to every peer who
 * holds the old one, sovereignly and relay-blind, by fanning out a signed MailboxPointer over each
 * pair's blind rendezvous (mailbox-pointer-transport.ts). This is the orchestration on top of the
 * already-pinned crypto primitives — the ONE net-new survivor-critical control loop in the mailbox
 * lifecycle. It is PUBLISHER-side only (the peer's resolve side is resolveMailboxPointer).
 *
 * SCOPE — SAME-RELAY ONLY (the relay does NOT change). Cross-relay transfer-away (G4) is a FAST-FOLLOW
 * (KB#92347/#92348): it additionally needs a cold-seed-signed DID-Doc serviceEndpoint endpoint-move and
 * its per-peer-sealed propagation, none of which this module touches. Here the mailbox KEYS rotate; the
 * deposit relay stays the caller's own.
 *
 * ★ DELIBERATE DIVERGENCE FROM THE SEALED SPEC (KB#92332 step 2), grounded on origin/main @658168e and
 *   flagged to Flint + Archie: the spec listed "register the new mailbox on the relay (POST
 *   /mailbox/register)". That endpoint is UNWIRED by Archie's blind-binding constitution gate —
 *   /mailbox/register has ZERO non-test callers and client-store.ts:336 + device-mailbox.ts:8 both state
 *   it "stays unwired". A mailbox is a SEAL-TARGET conveyed via the signed card / the sealed pointer, NOT
 *   a relay-queryable identity->mailbox index; per-pair DEPOSIT is deriveRouteId(RouteRatchet(s_AB)), not
 *   the mailbox_fp. So the pointer fan-out is self-sufficient — a peer learns the new mailbox from the
 *   sealed pointer and keeps depositing over the same per-pair route. Registering would re-introduce the
 *   exact correlation surface the gate forbids. => step 2 is DROPPED. Net effect: SMALLER + SAFER surface.
 *
 * THREE FAIL-SAFE CONSTANTS (Flint-ruled, KB#92342/#92346) — each enforced + unit-tested here:
 *   1. FAN-OUT SET = {contacts that hold my old mailbox} ∩ {¬blocked}, blocked-minus BY CONSTRUCTION
 *      (Hypatia HARD assertion #160664): the injected `listFanoutTargets` yields ONLY non-blocked
 *      holders — the orchestrator mints NO sealed copy for a blocked peer because a blocked peer is
 *      never in the set. `isBlockedTripwire` is a DEFENSE-IN-DEPTH guard (fail-closed SKIP + loud count),
 *      not the primary filter: it must read 0 when upstream honors by-construction, and it guarantees we
 *      never seal the new location to a blocked peer even if upstream regresses (anti-safety: a survivor
 *      blocked them). Over-fan to blocked = leaks new location; under-fan to a legit holder = silent loss.
 *   2. pointerEpoch = durably persisted, monotonic, NEVER rolled back, FLOORED ON RECOVERY. On a
 *      wiped/recovered device (loadEpoch===null) we REFUSE to default to 0 — publishing a low epoch a
 *      peer has already surpassed would be ignored by selectLatestValidPointer's highest-epoch-wins and
 *      the peer would keep sealing to my DEAD mailbox = silent loss. Fail-closed: require an explicit
 *      recovery floor above anything previously published (KB#92342 D2, ties to satellite per-mailbox
 *      epoch floor). resolveMailboxPointer already enforces highest-epoch-wins on the read side.
 *   3. OVERLAP WINDOW = time-bounded MAX, old decap key valid ONLY through the window, retire never before
 *      it expires. The OLD keypair is stashed in a transient overlap record BEFORE the device_mailbox
 *      flips (so in-flight mail sealed to the old mailbox still drains — early retire = lose in-flight
 *      deposits = betray a survivor mid-transfer). Confirm-based EARLY-CLOSE (all non-blocked holders
 *      ACK) is supported by shouldRetireOverlap but DORMANT at launch-v1 (no ack wire exists yet, grep 0)
 *      → v1 is pure time-based, which is sound ONLY if windowMs >= the rendezvous propagation+poll cycle
 *      AND the drain-drop honesty caveat ships (Flint/Hypatia open-Q#4).
 *
 * UNLINKABLE-HANDOFF (Archie W4 invariant) holds BY CONSTRUCTION: the new mailbox_fp = SHA256(a FRESH
 * random keypair) with no backref to the old; the pointer is sealed per-peer over the blind rendezvous
 * (no cross-peer correlation); nothing on the wire binds old↔new.
 *
 * DARK + DI'd (piece-2 pattern): every I/O side effect is an injected dependency, so the real crypto
 * round-trips in unit tests with an in-memory relay and zero IndexedDB, and NOTHING here is wired to
 * app-load. The real encrypted overlap/epoch persistence is an additive client-store v4->v5 schema add
 * (Athena's lane) that satisfies these dep signatures.
 */
import type { TrustRelay } from './trust-rendezvous.js';
import { publishMailboxPointer } from './mailbox-pointer-transport.js';
import {
  generateMailboxKeypair,
  mailboxFpOf,
  serializeMailboxKeypair,
  type MailboxKeypair,
} from '../crypto/mailbox-keys.js';
import type { MailboxPublicKeys } from '../crypto/mailbox-envelope.js';

/**
 * One non-blocked fan-out target: a contact who holds my OLD mailbox and must learn the new one. The
 * seal target is the peer's CURRENT mailbox (rotation seal-model, pointerEpoch >= 1). Built upstream from
 * getAllContacts ∩ ¬blocked ∩ has-device-mailbox (blocked-minus BY CONSTRUCTION); this module treats the
 * list as authoritative non-blocked holders and defends with isBlockedTripwire.
 */
export interface MigrationFanoutTarget {
  peerDid: string;
  /** Peer identity Ed25519 pubkey — derives the pair rendezvous R_e AND verifies the pointer sig (their side). */
  peerEdPub: Uint8Array;
  /** Peer's CURRENT mailbox pubkeys — WHERE the peer opens the sealed pointer (rotation seal target). */
  sealTarget: MailboxPublicKeys;
  /** deriveMailboxFp(sealTarget) — the recipient content-address for the #129 seal. */
  sealTargetFp: string;
  /** Local-only, for fan-out accounting/logging. NEVER on the wire. */
  contactFp?: string;
}

/**
 * The transient overlap record: the OLD keypair kept decryptable through the window so in-flight mail
 * sealed to the old mailbox still drains. SECRET key material — the real store MUST persist this
 * ENCRYPTED at rest (Blocker-C fail-closed, exactly like device_mailbox); zeroize/clear at retirement.
 */
export interface MailboxOverlapRecord {
  /**
   * The owner identity fingerprint (64-hex). This is the store's keyPath — named `fingerprint` to MATCH
   * device_mailbox's keyPath exactly (Athena #160726), so both mailbox stores key on the same canonical
   * value and getMyDeviceMailbox / overlap lookups read consistently. The real v4->v5 store is
   * createObjectStore('mailbox_overlap', { keyPath: 'fingerprint' }).
   */
  fingerprint: string;
  /** Serialized OLD keypair (INCLUDES SECRETS — encrypted at rest only). */
  oldKeypair: ReturnType<typeof serializeMailboxKeypair>;
  oldMailboxFp: string;
  newMailboxFp: string;
  /** Epoch of the NEW mailbox (audit). */
  epoch: number;
  /** ms since epoch, from the injected clock. */
  openedAt: number;
  /** openedAt + windowMs — the time-bounded MAX; old decap valid ONLY through here. */
  expiresAt: number;
  /** Peer DIDs that confirmed receipt — for confirm-based EARLY-CLOSE (DORMANT at v1, no ack wire). */
  ackedPeerDids: string[];
}

export interface MigrateMailboxDeps {
  relay: TrustRelay;
  /** My registered identity fingerprint (the migration subject). */
  ownerFp: string;
  myDid: string;
  /** My identity seed — in-memory only; signs each pointer and derives each pair's S_pair/R_e. */
  myEdPriv: Uint8Array;

  // ── state accessors (real impls wrap client-store; injected in tests — DARK, no IndexedDB in tests) ──
  /** My CURRENT (old) device-mailbox keypair. null => absent: NOT a rekey subject, fail-closed throw. */
  loadCurrentMailbox: () => Promise<MailboxKeypair | null>;
  /** Flip the device_mailbox to the NEW keypair (storeDeviceMailbox — overwrites the single record). */
  storeNewMailbox: (kp: MailboxKeypair) => Promise<void>;
  /** Current pointerEpoch, durably persisted. null => absent/wiped (recovery) — see fail-safe #2. */
  loadEpoch: () => Promise<number | null>;
  /** Persist the new epoch durably. Caller (this module) never rolls back. */
  saveEpoch: (epoch: number) => Promise<void>;
  /** Persist the old keypair + window (ENCRYPTED at rest). Written BEFORE the device_mailbox flip. */
  saveOverlap: (rec: MailboxOverlapRecord) => Promise<void>;
  /**
   * The current UN-RETIRED overlap record for this fingerprint, or null. The resume-guard (Flint KB#92350)
   * reads it on entry: an un-retired overlap means a prior migration crashed mid-flight, and its
   * oldMailboxFp is the SOURCE OF TRUTH for the true original mailbox — so a retry resumes from it rather
   * than re-deriving "old" from the (possibly already-flipped) live device, which would orphan the original
   * + its in-flight mail (the mid-transfer survivor betrayal fail-safe #3 guards).
   */
  loadOverlap: () => Promise<MailboxOverlapRecord | null>;
  /** Non-blocked holders of my old mailbox, blocked-minus BY CONSTRUCTION (fail-safe #1). */
  listFanoutTargets: () => Promise<MigrationFanoutTarget[]>;

  // ── policy + determinism ──
  /** Injected clock (ms). Tests pass a fixed value to avoid Date.now nondeterminism. */
  now: () => number;
  /** Overlap window (ms) — time-bounded MAX (fail-safe #3). Must be >= rendezvous propagation+poll cycle. */
  windowMs: number;
  /**
   * Floor-on-recovery epoch (fail-safe #2). Used ONLY when loadEpoch()===null (wiped/recovered state):
   * the new epoch is floored ABOVE this so a recovered device never republishes a low epoch a peer has
   * already surpassed. REQUIRED on recovery — omitting it on a null-epoch device is a fail-closed throw.
   */
  recoveryFloorEpoch?: number;

  // ── seams (default to the real primitives; overridable for test spying) ──
  generateKeypair?: () => MailboxKeypair;
  publishPointer?: typeof publishMailboxPointer;
  /**
   * DEFENSE-IN-DEPTH tripwire (NOT the primary filter). true => this target is blocked => SKIP (never
   * seal) + count the hit. Must stay 0 when listFanoutTargets honors blocked-minus-by-construction.
   */
  isBlockedTripwire?: (target: MigrationFanoutTarget) => boolean | Promise<boolean>;
}

export interface MigrateMailboxResult {
  oldMailboxFp: string;
  newMailboxFp: string;
  epoch: number;
  fanned: Array<{ peerDid: string; deposited: boolean }>;
  /** MUST be 0 if listFanoutTargets honors blocked-minus-by-construction (asserted in tests). */
  blockedTripwireHits: number;
  /** Holders skipped because they carried no current seal target (fail-closed under-reveal). */
  skippedNoSealTarget: number;
  overlapExpiresAt: number;
  /**
   * true ONLY when this call RESUMED an in-flight migration via the flip-done path — i.e. it RE-FANNED
   * the already-current mailbox at the recorded epoch rather than rotating to a fresh one (Flint honesty
   * ask). A caller/UI must not report a coalesced re-fan as a fresh rekey. false for a genuine rotation
   * (fresh start OR a flip-not-done resume, both of which mint + publish a new mailbox).
   */
  resumed: boolean;
}

/**
 * Compute the next monotonic pointerEpoch, enforcing fail-safe #2. Pure + exported for unit pinning.
 *  - normal (loaded != null): loaded + 1.
 *  - recovery (loaded == null): recoveryFloor + 1 if a floor is supplied; otherwise THROW (fail-closed —
 *    never default to 0 and risk republishing a low epoch peers have surpassed → silent loss).
 */
export function nextMailboxEpoch(loaded: number | null, recoveryFloor?: number): number {
  if (loaded !== null) {
    if (!Number.isSafeInteger(loaded) || loaded < 0) {
      throw new Error(`mailbox-migration: corrupt persisted epoch ${loaded} — fail-closed`);
    }
    return loaded + 1;
  }
  // wiped / recovered state
  if (recoveryFloor === undefined) {
    throw new Error(
      'mailbox-migration: epoch state absent and no recoveryFloorEpoch supplied — refusing to rekey ' +
        'from a wiped state (would risk republishing a stale-low epoch = silent loss). Fail-closed (#2).',
    );
  }
  if (!Number.isSafeInteger(recoveryFloor) || recoveryFloor < 0) {
    throw new Error(`mailbox-migration: invalid recoveryFloorEpoch ${recoveryFloor} — fail-closed`);
  }
  return recoveryFloor + 1;
}

/**
 * Fan the advertised mailbox out to every non-blocked holder as a signed, per-peer-sealed pointer over the
 * blind rendezvous. Shared by the fresh-rotation and flip-done-resume paths. Enforces fail-safe #1
 * (blocked-minus: the defense-in-depth tripwire SKIPs, never seals) + the fail-closed no-seal-target skip.
 */
async function fanOutMailbox(
  deps: MigrateMailboxDeps,
  publish: typeof publishMailboxPointer,
  advertiseKp: MailboxKeypair,
  epoch: number,
): Promise<Pick<MigrateMailboxResult, 'fanned' | 'blockedTripwireHits' | 'skippedNoSealTarget'>> {
  const targets = await deps.listFanoutTargets();
  const fanned: Array<{ peerDid: string; deposited: boolean }> = [];
  let blockedTripwireHits = 0;
  let skippedNoSealTarget = 0;

  for (const t of targets) {
    // DEFENSE-IN-DEPTH: never seal the new location to a blocked peer, even if upstream regressed.
    if (deps.isBlockedTripwire && (await deps.isBlockedTripwire(t))) {
      blockedTripwireHits++;
      continue; // SKIP — mint NOTHING for a blocked peer (anti-safety to leak the new location).
    }
    // Fail-closed: a holder with no current seal target under-reveals rather than seal to nothing.
    if (!t.sealTarget || !t.sealTargetFp) {
      skippedNoSealTarget++;
      continue;
    }
    const res = await publish({
      relay: deps.relay,
      myEdPriv: deps.myEdPriv,
      myDid: deps.myDid,
      peerEdPub: t.peerEdPub,
      peerDid: t.peerDid,
      sealTarget: t.sealTarget,
      sealTargetFp: t.sealTargetFp,
      myMailboxX25519Pub: advertiseKp.x25519Pub, // ADVERTISE this mailbox (goes inside the signed pointer)
      myMailboxMlkemEk: advertiseKp.mlkem1024Pub,
      pointerEpoch: epoch,
    });
    fanned.push({ peerDid: t.peerDid, deposited: res.deposited });
  }
  return { fanned, blockedTripwireHits, skippedNoSealTarget };
}

/**
 * Rotate from `current` — which IS the true original mailbox to preserve — to a fresh keypair: stash the
 * current keypair as the overlap's OLD *before* flipping (so in-flight mail to it still drains — fail-safe
 * #3), flip the live mailbox, persist epoch, fan out. Used by the fresh path and the flip-NOT-done resume
 * path; in both, `current` is the mailbox that must be preserved, so no intermediate is ever stashed as
 * "old". The drain window starts now (current stops being live at the flip).
 */
async function rotateFrom(
  deps: MigrateMailboxDeps,
  publish: typeof publishMailboxPointer,
  generate: () => MailboxKeypair,
  current: MailboxKeypair,
  currentFp: string,
  epoch: number,
): Promise<MigrateMailboxResult> {
  const newKp = generate();
  const newMailboxFp = mailboxFpOf(newKp);
  if (newMailboxFp === currentFp) {
    // CSPRNG collision is cryptographically impossible; a match means a broken/stubbed keygen.
    throw new Error('mailbox-migration: new mailbox fp == old — refusing (broken keygen?) — fail-closed');
  }

  const openedAt = deps.now();
  const expiresAt = openedAt + deps.windowMs;
  await deps.saveOverlap({
    fingerprint: deps.ownerFp, // store keyPath = 'fingerprint', aligned with device_mailbox (Athena #160726)
    oldKeypair: serializeMailboxKeypair(current),
    oldMailboxFp: currentFp,
    newMailboxFp,
    epoch,
    openedAt,
    expiresAt,
    ackedPeerDids: [],
  });

  await deps.storeNewMailbox(newKp);
  await deps.saveEpoch(epoch);

  const f = await fanOutMailbox(deps, publish, newKp, epoch);
  return { oldMailboxFp: currentFp, newMailboxFp, epoch, ...f, overlapExpiresAt: expiresAt, resumed: false };
}

/**
 * SAME-RELAY mailbox rekey. Rotates my device mailbox to a fresh keypair and fans the new mailbox out to
 * every non-blocked holder as a signed, per-peer-sealed pointer over the blind rendezvous.
 *
 * CRASH-SAFETY — RESUME-GUARD (Flint co-verify, load-bearing). Writes are ordered saveOverlap(old) → flip
 * → saveEpoch → fan-out, but fan-out is NETWORK (cannot live inside an IndexedDB transaction), so making
 * the store writes atomic alone does NOT make a crashed run safe to retry: once the flip commits,
 * device_mailbox = NEW (B), and a NAIVE retry would read loadCurrentMailbox()=B, treat B as "old",
 * re-rotate B→C and OVERWRITE the original A's overlap → A + its in-flight mail orphaned (the mid-transfer
 * survivor betrayal fail-safe #3 exists to prevent). Note generate() mints a FRESH keypair every run, so a
 * re-run does NOT reproduce B — it rotates onward and loses A. The guard closes this: on entry, an
 * un-retired overlap record is the SOURCE OF TRUTH for the original mailbox, and we resume from it rather
 * than re-deriving "old" from the live device:
 *   • device == overlap.new  → flip already happened (crash at/after flip, maybe mid-fan-out): re-fan the
 *     CURRENT keypair at overlap.epoch; do NOT re-rotate, do NOT touch the overlap (A stays old).
 *   • device == overlap.old  → flip had NOT happened (crash after saveOverlap, before flip): the live
 *     mailbox is still the original A (== current), so rotate from A — A stays old, window refreshes
 *     (A only now stops being live). Because current == A, nothing intermediate is stashed as "old".
 *   • device matches NEITHER → inconsistent (device rotated out-of-band vs an un-retired overlap): refuse,
 *     surface for recovery rather than risk orphaning A (fail-closed).
 * (a) single-transaction store writes [Athena's lane] are valuable hardening on top — they remove the
 * epoch/device desync class — but (b) this resume-guard is the piece that makes retry correct.
 */
export async function migrateMailbox(deps: MigrateMailboxDeps): Promise<MigrateMailboxResult> {
  const generate = deps.generateKeypair ?? generateMailboxKeypair;
  const publish = deps.publishPointer ?? publishMailboxPointer;

  // Load the CURRENT live mailbox. Absent => this identity has no mailbox to rotate — fail-closed.
  const current = await deps.loadCurrentMailbox();
  if (!current) {
    throw new Error('mailbox-migration: no current device mailbox to rotate (absent) — fail-closed');
  }
  const currentFp = mailboxFpOf(current);

  // RESUME-GUARD: an un-retired overlap means a prior migration crashed mid-flight — resume it from the
  // overlap's recorded original, never re-derive "old" from the (possibly already-flipped) live device.
  const inProgress = await deps.loadOverlap();
  if (inProgress) {
    if (currentFp === inProgress.newMailboxFp) {
      // FLIP ALREADY DONE — re-fan the current keypair at the recorded epoch; overlap untouched (A=old).
      await deps.saveEpoch(inProgress.epoch); // idempotent: ensure the persisted epoch matches the device
      const f = await fanOutMailbox(deps, publish, current, inProgress.epoch);
      return {
        oldMailboxFp: inProgress.oldMailboxFp,
        newMailboxFp: inProgress.newMailboxFp,
        epoch: inProgress.epoch,
        ...f,
        overlapExpiresAt: inProgress.expiresAt,
        resumed: true, // coalesced re-fan of an in-flight migration, NOT a fresh rotation (Flint honesty)
      };
    }
    if (currentFp === inProgress.oldMailboxFp) {
      // FLIP NOT DONE — the live mailbox is still the original A (== current). Rotate from A at the
      // already-chosen epoch; A stays old (current == A), window refreshes (A stops being live now).
      return rotateFrom(deps, publish, generate, current, currentFp, inProgress.epoch);
    }
    // device matches neither the overlap's old nor its new → inconsistent; refuse rather than orphan A.
    throw new Error(
      'mailbox-migration: un-retired overlap matches neither the current device mailbox nor its recorded ' +
        'new mailbox — inconsistent state, refusing to rekey (manual recovery) — fail-closed',
    );
  }

  // No in-progress overlap → a fresh rotation. Epoch = monotonic bump + floor-on-recovery (fail-safe #2).
  const epoch = nextMailboxEpoch(await deps.loadEpoch(), deps.recoveryFloorEpoch);
  return rotateFrom(deps, publish, generate, current, currentFp, epoch);
}

/**
 * Retirement predicate for the overlap window (fail-safe #3). Pure + exported for unit pinning.
 *  - TIME-BOUNDED MAX: retire once now >= expiresAt (the launch-v1 path).
 *  - CONFIRM-BASED EARLY-CLOSE: retire early once every non-blocked holder has ACKed (DORMANT at v1 —
 *    no ack wire exists yet; ackedPeerDids stays []; wire it and this path activates with no logic change).
 * NEVER retire before the window on time alone — early retire drops in-flight deposits = silent loss.
 */
export function shouldRetireOverlap(
  overlap: Pick<MailboxOverlapRecord, 'expiresAt' | 'ackedPeerDids'>,
  nonBlockedHolderDids: readonly string[],
  now: number,
): boolean {
  if (now >= overlap.expiresAt) return true; // time-bounded MAX reached
  // confirm-based early-close: all non-blocked holders acked (and there is at least one to ack).
  if (nonBlockedHolderDids.length > 0) {
    const acked = new Set(overlap.ackedPeerDids);
    if (nonBlockedHolderDids.every((did) => acked.has(did))) return true;
  }
  return false;
}
