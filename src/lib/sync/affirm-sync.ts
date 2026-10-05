// src/lib/sync/affirm-sync.ts
/**
 * Piece-2 mutual-block — the EMIT + RECEIVE wiring for visible-affirmatives (task #579, spec KB#92246,
 * Flint §F seal KB#92252, build package KB#92278). This is the layer the payload (crypto/visible-affirm.ts),
 * the viewer store (trust/held-affirmatives.ts), the emit-side suppression set (trust/suppression.ts), the
 * shared onion transport (sync/onion-transport.ts), and Athena's card-borne device mailbox
 * (identity/device-mailbox.ts + client-store) all DEFERRED to — "the EMIT/APPLY units built on top."
 *
 * THE MECHANISM (why a block becomes unobservable). F's client, on a default-ON cadence, emits a fresh signed
 * visible-affirm to each NON-suppressed contact over that pair's blinded rotating route. A viewer (Anna)
 * surfaces F — directly or transitively as a mutual-of-mutual — ONLY WHILE she holds a fresh affirmative from
 * F. When F suppresses Anna (per-person block / per-group / global go-private) F STOPS emitting to her ⇒ her
 * held affirmative EXPIRES within ≤ MAX_AFFIRM_TTL (20min) ⇒ F drops from her graph, including the transitive
 * path (#156420). ABSENCE is indistinguishable from offline ⇒ the block is UNOBSERVABLE (Fork-1a, Peter).
 *
 * ★ FAIL-CLOSED EVERYWHERE (survivor-safety; every failure UNDER-reveals, never over-reveals):
 *   · EMIT: suppression record unreadable (null) ⇒ isPartySuppressed=true ⇒ emit to NO ONE (§F3). A missing
 *     peer seal-target / unresolvable peer signing key / any seal error ⇒ skip that peer (under-reveal).
 *   · EMIT re-filters FRESH every tick (live suppression record + live per-contact `blocked`) — NEVER a cached
 *     emit-set — so no churn-recovery can replay a since-suppressed party (§F3).
 *   · RECEIVE: receiveFromRoute is already fully fail-closed (bad route / transport error / un-openable /
 *     tampered / wrong-kind ⇒ dropped). verifyVisibleAffirm rejects wrong-peer / expired / rolled-back /
 *     far-future (§F1). An unverifiable affirmative simply isn't recorded ⇒ the viewer under-reveals that peer.
 *
 * ★ §F5 CADENCE (no bursts). EMIT never deposits directly — it ENQUEUEs sealed cells onto a CadenceEmitter that
 * drains ONE per slot (a real cell if queued, else a cover), so a fan-out to N peers trickles across slots
 * indistinguishably from the uniform cover baseline. CadenceEmitter.start() app-wide (the uniform baseline for
 * ALL users) is the §8-DEPLOYED integration — a ship-time + Flint §8 + Peter call, DEFERRED here. startAffirmSync
 * is the drivable runner; it is not auto-started, and nothing imports it on the live path until flip.
 *
 * ★ DARK. Everything here is inert until isPiece2MutualBlockLive() flips: the reveal AND-gate
 * (held-affirmatives.gateEdgeTransitiveSets) is what SURFACES the held set, and it is gated. Emit/receive only
 * produce owner-local data that nothing READS pre-flip. DON'T SHIP; flip is Peter-GO after churn-GREEN.
 *
 * ★ OPEN DECISIONS routed to Flint (DDR piece2_emit_receive_DDR):
 *   DECISION-1 (§F1b): epoch = floor(emit now_seconds) — time-derived + stateless (monotonic by construction at
 *     ≥interval cadence; relay-replay has a lower epoch ⇒ rejected). Replaces the handoff's persisted per-peer
 *     counter: no persistence surface, no stale-replay/churn concern, multi-device-friendly.
 *   DECISION-2 (K1 unlinkability): a FIXED global route anchor (PIECE2_ROUTE_ANCHOR_WINDOW). Every absolute
 *     window folds a distinct index ⇒ distinct route_id (prop-1 holds). A daily re-anchor would make the
 *     hour-0 route_id repeat each day (deriveRouteId(rk₀)) ⇒ cross-day linkability — REJECTED. Cost (now−anchor
 *     HKDF steps) ≈0 at launch; the PCS rekey (route-ratchet prop-3) is the principled long-term re-anchor.
 *   DECISION-3 (crypto-handling): the raw owner seed lives ONLY in a closure (AffirmSyncContext.ownerSeed),
 *     exactly as buildPsiSyncOptions holds it for signFn — never persisted / logged.
 *
 * Alias imports (`@/`) + DI: the client-store accessors are injected (defaults wired to the real IndexedDB
 * store) so the ticks are unit-testable IndexedDB-free — the test drives real crypto end-to-end through an
 * in-memory satellite (peelOnion) with raw noble keys. Matches know-layer-sync.ts' seam-injection.
 */
import { readKey, readPrivateKey, decryptKey } from 'openpgp';
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js';

import {
  buildVisibleAffirm,
  verifyVisibleAffirm,
  MAX_AFFIRM_TTL_SECONDS,
} from '@/lib/crypto/visible-affirm';
import {
  sealForRoute,
  receiveFromRoute,
  routeIdForPeer,
  httpOnionRelay,
  CadenceEmitter,
} from '@/lib/sync/onion-transport';
import { currentWindowIndex } from '@/lib/crypto/route-ratchet';
import { deriveSharedSecret } from '@/lib/crypto/mutual-trust';
import {
  recordAffirmative,
  emptyHeld,
  type HeldAffirmatives,
} from '@/lib/trust/held-affirmatives';
import { isPartySuppressed, type SuppressionRecord } from '@/lib/trust/suppression';
import { peerDeviceMailbox } from '@/lib/identity/device-mailbox';
import { signPubFromOpenPgpPublic } from '@/lib/identity/fingerprint';
import { extractRawSign } from '@/lib/identity/raw-sign';
import {
  getAllContacts as realGetAllContacts,
  getSuppressionRecord as realGetSuppressionRecord,
  getHeldAffirmatives as realGetHeldAffirmatives,
  setHeldAffirmatives as realSetHeldAffirmatives,
  getMyDeviceMailbox as realGetMyDeviceMailbox,
  loadKey as realLoadKey,
  type ContactRecord,
} from '@/lib/identity/client-store';
import type { MailboxPublicKeys, MailboxSecretKeys } from '@/lib/crypto/mailbox-envelope';

// ── Parameters ──────────────────────────────────────────────────────────────────────────────────────────

/** Clock skew headroom reserved under the §F1c cap so a viewer up to this far BEHIND still accepts a legit
 *  affirmative (visible-affirm.ts §F1c note). EMIT_TTL = MAX_AFFIRM_TTL − this. */
export const AFFIRM_SKEW_MARGIN_SECONDS = 60;
/** The validity horizon the emitter stamps (seconds). < MAX_AFFIRM_TTL so positive viewer-skew stays under the
 *  verifier cap; the ≤20min block-latency bound (MAX_AFFIRM_TTL) is unchanged — the cap stays exactly MAX. */
export const AFFIRM_EMIT_TTL_SECONDS = MAX_AFFIRM_TTL_SECONDS - AFFIRM_SKEW_MARGIN_SECONDS; // 1140
/**
 * ★ DECISION-2: the FIXED global route-ratchet anchor window. All pairs anchor here; route_ids still rotate
 * per window (each absolute window index is folded into the ratchet) and differ per pair (by s_AB + direction).
 * Value = floor(2026-10-01T00:00:00Z / ROUTE_WINDOW_SECONDS[3600]) = floor(1759276800/3600) = 488688. Cost to
 * fast-forward anchor→now is ≈0 at launch; the PCS rekey is the principled long-term re-anchor. (Flint co-verify.)
 */
export const PIECE2_ROUTE_ANCHOR_WINDOW = 488688;
/** Default emit/receive tick cadence (mirrors the KNOW-layer 5-min loop). The §F5 cover cadence (CadenceEmitter
 *  slot period) is a separate, finer tempo tuned at §8. */
export const DEFAULT_AFFIRM_SYNC_INTERVAL_MS = 5 * 60 * 1000;
/** Cover bytes length for an idle cadence slot (opaque; frameUniform pads to the uniform cell size anyway). */
const COVER_PAYLOAD_LEN = 32;

// ── Clock + seams ───────────────────────────────────────────────────────────────────────────────────────

/** Unix SECONDS clock. Injectable for deterministic tests; defaults to the wall clock. */
export type Clock = () => number;
const systemClock: Clock = () => Math.floor(Date.now() / 1000);

/** Resolve a peer's CURRENT raw Ed25519 signing pubkey (32B) from their contact. Default parses the stored
 *  armored `public_key` (§F2 pinned-current-key). Injectable so tests use raw noble keys. null ⇒ can't verify
 *  / can't derive s_AB ⇒ that peer is skipped (under-reveal). */
export type ResolvePeerSignPub = (contact: ContactRecord) => Promise<Uint8Array | null> | Uint8Array | null;

const defaultResolvePeerSignPub: ResolvePeerSignPub = async (contact) => {
  const armored = (contact.public_key || '').trim();
  if (!armored) return null;
  try {
    const key = await readKey({ armoredKey: armored });
    const pub = signPubFromOpenPgpPublic(key);
    return pub.length === 32 ? pub : null;
  } catch {
    return null;
  }
};

/** The injectable store/clock/relay seam (defaults wired to the real IndexedDB client-store + wall clock +
 *  real relay). Tests supply fakes so no IndexedDB/network is touched. */
export interface AffirmSyncDeps {
  getAllContacts: (owner: string) => Promise<ContactRecord[]>;
  getSuppressionRecord: (owner: string) => Promise<SuppressionRecord | null>;
  getHeldAffirmatives: (owner: string) => Promise<HeldAffirmatives | null>;
  setHeldAffirmatives: (owner: string, map: HeldAffirmatives) => Promise<void>;
  resolvePeerSignPub: ResolvePeerSignPub;
  /** Relay used by the RECEIVE poll; defaults to httpOnionRelay. Only `poll` is used (receiveFromRoute). */
  relay: Pick<typeof httpOnionRelay, 'poll'>;
  clock: Clock;
}

export function defaultAffirmSyncDeps(): AffirmSyncDeps {
  return {
    getAllContacts: realGetAllContacts,
    getSuppressionRecord: realGetSuppressionRecord,
    getHeldAffirmatives: realGetHeldAffirmatives,
    setHeldAffirmatives: realSetHeldAffirmatives,
    resolvePeerSignPub: defaultResolvePeerSignPub,
    relay: httpOnionRelay,
    clock: systemClock,
  };
}

/**
 * Per-session emit/receive context. Holds the resolved owner identity + the IN-MEMORY raw seed (DECISION-3),
 * this device's mailbox (receive secrets + the published seal-target), the satellite routing keys to seal the
 * onion outer to, and the route anchor. Built by buildAffirmSyncContext (the only client-store/openpgp
 * importer); tests construct it directly from raw keys.
 */
export interface AffirmSyncContext {
  /** Owner canonical fingerprint (lowercase hex). */
  owner: string;
  /** Raw 32B Ed25519 seed — IN-MEMORY closure ONLY; never persist/log (DECISION-3). Signs affirms + derives s_AB. */
  ownerSeed: Uint8Array;
  /** This device's mailbox: `secrets` open inbound onion mail; `publicKeys`/`fp` are the self seal-target for cover. */
  me: { secrets: MailboxSecretKeys; publicKeys: MailboxPublicKeys; fp: string };
  /** Verified satellite routing public keys (K0 outer seal target). Resolved by the deferred wiring. */
  satelliteKeys: MailboxPublicKeys;
  /** Route-ratchet anchor window (DECISION-2). Defaults to PIECE2_ROUTE_ANCHOR_WINDOW. */
  anchorWindow: number;
}

/**
 * Build the emit/receive context for an unlocked identity: unlock the vaulted OpenPGP key, scalar-extract the
 * raw seed into memory (DECISION-3), load this device's mailbox, and attach the (already-verified) satellite
 * keys. Returns null (fail-closed, no emit/receive) if locked / missing key / no device mailbox. The satellite
 * keys are an INPUT (the deferred wiring resolves + anti-swap-verifies them via the piece-1 fetchAndVerify
 * path) so this module neither duplicates that fetch nor couples to a private helper.
 */
export async function buildAffirmSyncContext(
  args: {
    owner: string;
    satelliteKeys: MailboxPublicKeys;
    anchorWindow?: number;
  },
  deps: { loadKey?: typeof realLoadKey; getMyDeviceMailbox?: typeof realGetMyDeviceMailbox } = {},
): Promise<AffirmSyncContext | null> {
  const owner = (args.owner || '').trim().toLowerCase();
  if (!owner) return null;
  const loadKey = deps.loadKey ?? realLoadKey;
  const getMyDeviceMailbox = deps.getMyDeviceMailbox ?? realGetMyDeviceMailbox;

  const key = await loadKey(owner);
  if (!key?.privateKey || !key.passphrase) return null; // locked / absent ⇒ no emit (fail-closed)

  let ownerSeed: Uint8Array;
  try {
    const locked = await readPrivateKey({ armoredKey: key.privateKey });
    const decrypted = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: key.passphrase });
    ({ seed: ownerSeed } = extractRawSign(decrypted));
  } catch {
    return null; // can't unlock the seed ⇒ fail-closed
  }

  let me: Awaited<ReturnType<typeof realGetMyDeviceMailbox>>;
  try {
    me = await getMyDeviceMailbox(owner);
  } catch {
    return null; // present-but-unreadable mailbox ⇒ surface by not emitting (don't churn)
  }
  if (!me) return null; // no device mailbox yet ⇒ can't receive; don't emit a seal-target we can't back

  return {
    owner,
    ownerSeed,
    me,
    satelliteKeys: args.satelliteKeys,
    anchorWindow: args.anchorWindow ?? PIECE2_ROUTE_ANCHOR_WINDOW,
  };
}

// ── EMIT ────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Pure emit-eligibility predicate (independently testable). Emit a visible-affirm to a contact IFF it has a
 * real fingerprint, is NOT a grow-gate arrival, is NOT blocked (record or metadata — piece-1 block
 * auto-suppresses), and is NOT suppressed by the durable record (person / group / global). ★ §F3 fail-closed:
 * a null suppression record makes isPartySuppressed TRUE for everyone ⇒ emit to NO ONE. Mirrors getKnownPeers'
 * disclosure base-set (know-layer-sync.ts:71/78) minus the suppressed — the right altitude (emit only to whom
 * the KNOW layer would disclose).
 */
export function isEmitEligible(c: ContactRecord, suppRec: SuppressionRecord | null): boolean {
  const fp = (c.fingerprint || '').trim();
  if (!fp) return false;
  if (c.metadata?.grow_gate === true) return false; // gate arrivals never participate
  if (c.blocked || c.metadata?.blocked) return false; // piece-1 block ⇒ auto-suppress
  const groupIds = (c.tags || c.metadata?.tags || []) as string[];
  return !isPartySuppressed(suppRec, { durableId: fp, groupIds });
}

/**
 * Run ONE emit pass: for each eligible contact, seal a fresh visible-affirm to that pair's current-window route
 * and ENQUEUE it on the cadence emitter (never deposit directly — §F5). Recomputes suppression + contacts FRESH
 * (no cached emit-set — §F3). Returns counts: `emitted` enqueued, `skipped` = eligible-but-unemittable
 * (missing seal-target / unresolvable signing key / seal error — each an under-reveal). Never throws.
 */
export async function runAffirmEmitTick(
  ctx: AffirmSyncContext,
  cadence: Pick<CadenceEmitter, 'enqueue'>,
  deps: Pick<AffirmSyncDeps, 'getAllContacts' | 'getSuppressionRecord' | 'resolvePeerSignPub' | 'clock'>,
): Promise<{ emitted: number; skipped: number }> {
  const now = deps.clock();
  const nowWindow = currentWindowIndex(now * 1000);
  // ★ §F3: read the live record + live book THIS pass; never reuse a prior emit-set.
  const [suppRec, contacts] = await Promise.all([
    deps.getSuppressionRecord(ctx.owner),
    deps.getAllContacts(ctx.owner),
  ]);

  let emitted = 0;
  let skipped = 0;
  for (const c of contacts) {
    if (!isEmitEligible(c, suppRec)) continue; // suppressed/blocked/gated — intentional non-emit, not a skip
    const peerFp = (c.fingerprint || '').trim().toLowerCase();
    if (peerFp === ctx.owner) continue; // never emit to self (directionTag would throw)

    const mailbox = peerDeviceMailbox(c);
    if (!mailbox) { skipped++; continue; } // no verified seal-target ⇒ under-reveal

    let peerSignPub: Uint8Array | null;
    try { peerSignPub = await deps.resolvePeerSignPub(c); } catch { peerSignPub = null; }
    if (!peerSignPub || peerSignPub.length !== 32) { skipped++; continue; } // can't key the route ⇒ under-reveal

    try {
      const epoch = now; // ★ DECISION-1: time-derived, stateless, monotonic at cadence
      const validUntil = now + AFFIRM_EMIT_TTL_SECONDS;
      const payload = buildVisibleAffirm({ epoch, validUntil }, ctx.ownerSeed, hexToBytes(peerFp));
      const sAB = deriveSharedSecret(ctx.ownerSeed, peerSignPub);
      const routeId = routeIdForPeer({
        rootSecret: sAB,
        senderFp: ctx.owner,
        recipientFp: peerFp,
        anchorWindow: ctx.anchorWindow,
        nowWindow,
      });
      const outer = await sealForRoute({
        payload,
        frameType: 'visible-affirm',
        recipientDevice: mailbox.publicKeys,
        satellite: ctx.satelliteKeys,
        routeId,
      });
      cadence.enqueue(outer); // §F5: ride the cadence; NEVER httpOnionRelay.deposit directly
      emitted++;
    } catch {
      skipped++; // any seal/crypto failure ⇒ emit nothing to this peer (fail-closed under-reveal)
    }
  }
  return { emitted, skipped };
}

/**
 * Build a cover cell for an idle cadence slot: random bytes framed 'cover', sealed to THIS device (self) and
 * onion-sealed to the satellite on a fresh random route. Indistinguishable on the wire from a real emit (same
 * /onion path, same uniform 2048B cell, same slot). Never meant to be received — it just fills a slot so a
 * real fan-out never bursts (§F5).
 */
export async function makeAffirmCover(ctx: AffirmSyncContext) {
  const coverBytes = crypto.getRandomValues(new Uint8Array(COVER_PAYLOAD_LEN));
  const routeId = bytesToHex(crypto.getRandomValues(new Uint8Array(16))); // 32 lowercase hex
  return sealForRoute({
    payload: coverBytes,
    frameType: 'cover',
    recipientDevice: ctx.me.publicKeys, // self — opaque to the relay either way
    satellite: ctx.satelliteKeys,
    routeId,
  });
}

// ── RECEIVE ─────────────────────────────────────────────────────────────────────────────────────────────

/**
 * Run ONE receive pass: for each contact, derive the PEER→ME route for the edge-window set {W-1, W, W+1}
 * (§5-F clock-skew / boundary tolerance), poll each, verify every recovered visible-affirm against the peer's
 * CURRENT signing key bound to MY fingerprint, and record the freshest (monotonic epoch) into the held store.
 * Persists once at the end iff anything changed. FULLY FAIL-CLOSED: unresolvable key / bad route / transport
 * error / tamper / wrong-peer / expired / rollback ⇒ that affirmative simply isn't recorded (under-reveal).
 * Relay-blind: the payload carries NO sender id — the ROUTE identifies the pair. Never throws.
 */
export async function runAffirmReceiveTick(
  ctx: AffirmSyncContext,
  deps: Pick<AffirmSyncDeps, 'getAllContacts' | 'getHeldAffirmatives' | 'setHeldAffirmatives' | 'resolvePeerSignPub' | 'relay' | 'clock'>,
): Promise<{ accepted: number }> {
  const now = deps.clock();
  const nowWindow = currentWindowIndex(now * 1000);
  const ownerBinding = hexToBytes(ctx.owner);
  const contacts = await deps.getAllContacts(ctx.owner);

  let held = (await deps.getHeldAffirmatives(ctx.owner)) ?? emptyHeld();
  let accepted = 0;
  let changed = false;

  for (const c of contacts) {
    const peerFp = (c.fingerprint || '').trim().toLowerCase();
    if (!peerFp || peerFp === ctx.owner) continue;

    let peerSignPub: Uint8Array | null;
    try { peerSignPub = await deps.resolvePeerSignPub(c); } catch { peerSignPub = null; }
    if (!peerSignPub || peerSignPub.length !== 32) continue; // can't verify ⇒ under-reveal

    let sAB: Uint8Array;
    try { sAB = deriveSharedSecret(ctx.ownerSeed, peerSignPub); } catch { continue; }

    // PEER→ME direction; edge-window set (never below the anchor — routeIdForPeer throws on nowWindow<anchor).
    const routeIds = new Set<string>();
    for (const w of [nowWindow - 1, nowWindow, nowWindow + 1]) {
      if (w < ctx.anchorWindow) continue;
      try {
        routeIds.add(routeIdForPeer({ rootSecret: sAB, senderFp: peerFp, recipientFp: ctx.owner, anchorWindow: ctx.anchorWindow, nowWindow: w }));
      } catch { /* skip this window */ }
    }

    for (const routeId of routeIds) {
      const cells = await receiveFromRoute({
        routeId,
        deviceSecrets: ctx.me.secrets,
        deviceMailboxFpHex: ctx.me.fp,
        frameType: 'visible-affirm',
        relay: deps.relay,
      });
      for (const cell of cells) {
        const lastSeen = held[peerFp]?.epoch ?? -1;
        const v = verifyVisibleAffirm(cell.payload, peerSignPub, { recipientBinding: ownerBinding, lastSeenEpoch: lastSeen, now });
        if (!v) continue; // wrong-peer / expired / rollback / far-future ⇒ drop
        const next = recordAffirmative(held, peerFp, { validUntil: v.validUntil, epoch: v.epoch });
        if (next !== held) { held = next; changed = true; accepted++; }
      }
    }
  }

  if (changed) await deps.setHeldAffirmatives(ctx.owner, held);
  return { accepted };
}

// ── §8-DEPLOYED runner (DEFERRED / gated — build the mechanism, don't auto-start live) ────────────────────

export interface AffirmSyncHandle {
  stop: () => void;
}

/**
 * ★ GATED INTEGRATION SEAM (§8-DEPLOYED). Drive emit+receive on a cadence: an immediate first tick + interval,
 * NON-OVERLAPPING (inFlight guard), FAIL-SOFT (a locked identity / transient error never throws out), mirroring
 * startKnowLayerSync. EMIT enqueues onto a CadenceEmitter that is itself started on the §F5 cover cadence, so
 * real cells trickle (never burst). This exists so the mechanism is drivable + reviewable; wiring it always-on
 * for all users (and the uniform cover baseline it rides) is the ship-time Flint §8 + Peter call — NOT done here.
 */
export function startAffirmSync(
  ctx: AffirmSyncContext,
  opts: {
    deps?: AffirmSyncDeps;
    intervalMs?: number;
    /** CadenceEmitter slot period (§F5). */
    cadencePeriodMs: number;
    cadenceJitterMs?: number;
  },
): AffirmSyncHandle {
  const deps = opts.deps ?? defaultAffirmSyncDeps();
  const intervalMs = opts.intervalMs ?? DEFAULT_AFFIRM_SYNC_INTERVAL_MS;
  const cadence = new CadenceEmitter({ makeCover: () => makeAffirmCover(ctx) });
  cadence.start({ periodMs: opts.cadencePeriodMs, jitterMs: opts.cadenceJitterMs });

  let stopped = false;
  let inFlight = false;
  const tick = async () => {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      await runAffirmEmitTick(ctx, cadence, deps);
      await runAffirmReceiveTick(ctx, deps);
    } catch (err) {
      // local-only diagnostic; one bad tick must not wedge the loop. Nothing leaks (fail-closed throughout).
      console.error('[affirm-sync] tick failed (will retry):', err);
    } finally {
      inFlight = false;
    }
  };

  void tick(); // immediate first pass
  const timer = typeof setInterval === 'function' ? setInterval(() => void tick(), intervalMs) : null;

  return {
    stop: () => {
      stopped = true;
      if (timer !== null) clearInterval(timer);
      cadence.stop();
    },
  };
}
