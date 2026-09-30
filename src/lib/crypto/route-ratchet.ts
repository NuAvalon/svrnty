// src/lib/crypto/route-ratchet.ts
/**
 * Blinded rotating route-id ratchet — the #558 keystone K1 (§5).
 *
 * WHAT IT IS: a per-window, forward-secret routing tag for a pair of trusted clients. It REPLACES the
 * opaque passthrough `route` string in the K0 onion outer shell (onion-envelope.ts `OnionOuterPayload.route`)
 * with a value that ROTATES every time window and that a hosted satellite cannot link across windows or to a
 * device. NO new crypto core: HKDF-SHA256 over the pairwise handshake secret (the same `s_AB` produced by
 * mutual-trust.ts `deriveSharedSecret`). Composition, not invention — the K0 ethos.
 *
 * CONSTRUCTION (Flint §5 co-verify, KB#91387; delta KB#91382). All labels are versioned domain separators:
 *   rk₀              = HKDF(s_AB, "svrnty-route-root-v1" ‖ dir)          // per-direction root ratchet key
 *   rk_W             = HKDF(rk_{W-1}, "svrnty-route-ratchet-v1" ‖ W)     // one forward step per elapsed window
 *   route_id(W)      = HKDF(rk_W, "svrnty-route-id-v1")[:16]             // 128-bit routing tag (hex)
 *   window_index(t)  = ⌊t / WINDOW_DUR⌋                                  // PURE TIME (Flint §5-F, below)
 *
 * THE FOUR PROTECT-THE-PERSON PROPERTIES this module is gated on (adversarial refutation, not mechanic-confirm):
 *
 *  (1) UNLINKABILITY — an observer holding route_id(W) and route_id(W+k) for the SAME pair cannot tell they
 *      belong to the same pair, and cannot derive one from the other. Each is HKDF output over an independent
 *      ratchet key; without the rk chain there is no recoverable relation. (This is the keystone's point.)
 *
 *  (2) FORWARD-SECRECY (retro-linkage, §5-A) — an adversary who SEIZES the ratchet state at window W cannot
 *      recompute route_id for ANY window < W. HKDF is one-way, so rk_W ↛ rk_{W-1}. The mechanism is DELETION:
 *      advancing overwrites rk_{W-1} and NEVER retains it.
 *      ★ CLAIM BOUNDARY (honest, do-no-harm): this FS is relative to seizure of the RATCHET STATE. It requires
 *        that `s_AB` is NOT co-resident with the ratchet — an adversary who also holds `s_AB` (or the long-term
 *        identity keys that recompute it via deriveSharedSecret) can re-derive rk₀ and chain forward to any past
 *        window, defeating retro-linkage. So: this module NEVER stores `s_AB` in the ratchet state (see
 *        RouteRatchet), the caller MUST discard `s_AB` after init, and the residual long-term-key exposure is
 *        what the PCS re-key (property 3) closes with entropy the long-term keys cannot reproduce.
 *
 *  (3) POST-COMPROMISE SECURITY (§5-A, Flint's PCS gap, my v1 call for the DV/device-seizure pop) — a hash
 *      ratchet alone gives NO PCS: seizing rk_W lets the adversary compute ALL FUTURE windows. So we fold fresh
 *      handshake DH entropy into a new root on reconnect/period: newRoot = HKDF(fresh_DH, salt=oldRoot, "pcs").
 *      An adversary who seized PRE-rekey state lacks fresh_DH and cannot derive post-rekey route_ids. Coarse
 *      (per reconnect/period), so within-period offline derivation still works.
 *
 *  (4) §5-F DETERMINISM (do-no-harm delivery) — window_index is PURE ⌊now/WINDOW_DUR⌋, so sender and recipient
 *      compute the SAME window with NO shared runtime state (no reopen-driven index → no desync → no lost
 *      rendezvous). A desynced route_id does NOT match (returns false) — a failure DETECTED, never a silent
 *      mis-delivery. The recipient accepts the [W-1, W, W+1] edge window for clock skew / in-flight boundary
 *      crossing WITHOUT weakening FS: it derives W and W+1 on demand from rk_W, and retains only the DERIVED
 *      route_id(W-1) MATCHER (a terminal 16-byte value, one-way from rk_{W-1}) — never rk_{W-1} itself
 *      (retaining rk_{W-1} would recompute all of window W-1 = a 1-window linkable-history reintroduction; §5-B).
 *
 * SCOPE (K1 = this crypto primitive + its adversarial tests). DEFERRED (a separate reviewable unit, as K0
 * deferred satellite-serve): wiring route_id into the Family-B send/register path (trust-rendezvous.ts /
 * mailbox-pointer-transport.ts), §5-D per-route write-caps (anti-Sybil, must-never-de-blind), and the §5-C
 * contact-degree honest-labeling. WHERE `s_AB` / the anchor window come from is the wiring's concern; here they
 * are inputs.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// ── Parameters ────────────────────────────────────────────────────────
/** Route-id rotation period (seconds). K3/§8 measurement tunes the CADENCE (bandwidth vs hiding-latency),
 *  never the architecture. 1h: coarse enough that the ±1 edge window absorbs realistic clock skew + in-flight
 *  latency, fine enough that a hosted relay sees a fresh tag many times a day. */
export const ROUTE_WINDOW_SECONDS = 3600;
const ROUTE_SECRET_LEN = 32; // HKDF-SHA256 full output for ratchet keys
const ROUTE_ID_LEN = 16; // 128-bit routing tag

// Versioned domain-separation labels (spec v0.2 §5). Never reuse a label across derivations.
const LABEL_ROOT = 'svrnty-route-root-v1';
const LABEL_RATCHET = 'svrnty-route-ratchet-v1';
const LABEL_ID = 'svrnty-route-id-v1';
const LABEL_PCS = 'svrnty-route-pcs-v1';

/** Canonical per-pair direction tag. `lh` = message from the lexicographically-lower fp to the higher;
 *  `hl` = the reverse. Both parties compute the SAME tag for a given (sender→recipient) ordering, so the two
 *  directions get INDEPENDENT ratchet chains (A→B route_ids never coincide with B→A). */
export type Direction = 'lh' | 'hl';

// ── Pure derivation primitives ─────────────────────────────────────────

/** window_index(t) = ⌊t / WINDOW_DUR⌋. Pure time — the §5-F determinism guarantee. `nowMs` is injectable so
 *  both the wiring and the tests are deterministic; defaults to the wall clock. */
export function currentWindowIndex(
  nowMs: number = Date.now(),
  windowSeconds: number = ROUTE_WINDOW_SECONDS,
): number {
  return Math.floor(nowMs / 1000 / windowSeconds);
}

/** dir(sender→recipient) from the two fingerprints (lexicographic, matching mutual-trust's sortFingerprints). */
export function directionTag(senderFp: string, recipientFp: string): Direction {
  if (senderFp === recipientFp) throw new Error('route-ratchet: sender and recipient fp must differ');
  return senderFp < recipientFp ? 'lh' : 'hl';
}

/** rk₀ = HKDF(s_AB, "svrnty-route-root-v1" ‖ dir). The per-direction root ratchet key at the anchor window. */
export function deriveRootRatchetKey(rootSecret: Uint8Array, dir: Direction): Uint8Array {
  return hkdf(sha256, rootSecret, undefined, utf8ToBytes(`${LABEL_ROOT}|${dir}`), ROUTE_SECRET_LEN);
}

/** rk_W = HKDF(rk_{W-1}, "svrnty-route-ratchet-v1" ‖ W). One forward ratchet step, folding the ABSOLUTE window
 *  index W so each rung is bound to its window number. One-way: given rk_W you cannot recover rk_{W-1}. */
export function advanceRatchetKey(prevRk: Uint8Array, window: number): Uint8Array {
  return hkdf(sha256, prevRk, undefined, utf8ToBytes(`${LABEL_RATCHET}|${window}`), ROUTE_SECRET_LEN);
}

/** route_id(W) = HKDF(rk_W, "svrnty-route-id-v1")[:16] as hex. The public routing tag; one-way from rk_W. */
export function deriveRouteId(rk: Uint8Array): string {
  return bytesToHex(hkdf(sha256, rk, undefined, utf8ToBytes(LABEL_ID), ROUTE_ID_LEN));
}

/** PCS re-key: fold fresh handshake DH entropy into a new root. newRoot = HKDF(fresh_DH, salt=oldRoot, "pcs").
 *  `freshDhShared` is a fresh ephemeral DH output from a reconnect handshake (the wiring supplies it — e.g.
 *  mutual-trust.deriveSharedSecret over fresh ephemeral keys). An adversary who seized the PRE-rekey state
 *  holds `oldRoot`/`rk` but NOT `freshDhShared`, so cannot compute `newRoot` → no post-rekey route_ids. */
export function rekeyRootSecret(oldRootSecret: Uint8Array, freshDhShared: Uint8Array): Uint8Array {
  if (freshDhShared.length === 0) throw new Error('route-ratchet: PCS re-key needs fresh DH entropy');
  return hkdf(sha256, freshDhShared, oldRootSecret, utf8ToBytes(LABEL_PCS), ROUTE_SECRET_LEN);
}

// ── Stateful ratchet (retention discipline = the FS mechanism) ──────────

/**
 * A one-direction route ratchet. Holds ONLY what forward-secrecy allows: the current ratchet key `rk`, the
 * window it belongs to, the direction tag, and a single DERIVED matcher for the immediately-previous window
 * (the edge window). It NEVER holds `s_AB`, and NEVER holds any past `rk`. Advancing is forward-only and
 * deletes the predecessor `rk` in place (the FS mechanism, property 2).
 *
 * Both sender and recipient use the same object: the sender reads `currentRouteId()` to address the recipient
 * for this window; the recipient additionally uses `matches()` to accept the [W-1, W, W+1] edge window.
 */
export class RouteRatchet {
  private rk: Uint8Array;
  private window: number;
  /** route_id(W-1), the ONLY retained artifact of the previous window (one-way; NOT rk_{W-1}). */
  private prevMatcher: string | null;
  readonly dir: Direction;

  private constructor(rk: Uint8Array, window: number, dir: Direction, prevMatcher: string | null) {
    this.rk = rk;
    this.window = window;
    this.dir = dir;
    this.prevMatcher = prevMatcher;
  }

  /**
   * Initialize a ratchet at `anchorWindow` from the pairwise root secret, then fast-forward to `nowWindow`.
   * `s_AB` is used ONLY here to derive rk₀ and is NOT retained — the caller MUST discard it after this call
   * (see the FS claim boundary at the top of the file). `anchorWindow` is the window the pair established
   * `s_AB` in (or the window of the last PCS re-key); the wiring supplies it.
   */
  static init(
    rootSecret: Uint8Array,
    dir: Direction,
    anchorWindow: number,
    nowWindow: number = currentWindowIndex(),
  ): RouteRatchet {
    if (nowWindow < anchorWindow) {
      throw new Error('route-ratchet: nowWindow precedes anchorWindow (clock before pairing?)');
    }
    const r = new RouteRatchet(deriveRootRatchetKey(rootSecret, dir), anchorWindow, dir, null);
    r.advanceTo(nowWindow);
    return r;
  }

  /** The current window this ratchet is positioned at. */
  get currentWindow(): number {
    return this.window;
  }

  /**
   * Advance forward to `targetWindow`, folding each elapsed absolute window and retaining ONLY the last
   * previous-window matcher. No-op if already at/after target (forward-only; never rewinds). Each step
   * overwrites `rk` — the predecessor is not kept (FS). A multi-window jump keeps only route_id(target-1)
   * as the matcher, not the intermediates (no linkable-history reintroduction; §5-B tight bound).
   */
  advanceTo(targetWindow: number): void {
    while (this.window < targetWindow) {
      // Derive the matcher for the window we are LEAVING before we lose its rk, then step forward.
      this.prevMatcher = deriveRouteId(this.rk);
      this.rk = advanceRatchetKey(this.rk, this.window + 1);
      this.window += 1;
    }
  }

  /** route_id for the current window — the tag a sender writes / a recipient registers this window. */
  currentRouteId(): string {
    return deriveRouteId(this.rk);
  }

  /**
   * Recipient-side accept check over the [W-1, W, W+1] edge window (§5-B / §5-F), WITHOUT retaining rk_{W-1}:
   *   W    → derived from the current rk
   *   W+1  → derived on demand from the current rk (rk_{W+1} = advance(rk_W); not retained)
   *   W-1  → the retained one-way matcher (route_id(W-1)); null before the first advance
   * A route_id from any other window returns false — a desync is DETECTED, never silently accepted.
   */
  matches(routeId: string): boolean {
    if (routeId === this.currentRouteId()) return true;
    if (this.prevMatcher !== null && routeId === this.prevMatcher) return true;
    const nextRk = advanceRatchetKey(this.rk, this.window + 1);
    return routeId === deriveRouteId(nextRk);
  }

  /**
   * Re-key for post-compromise security (property 3): fold fresh DH entropy into a new root and re-anchor at
   * `rekeyWindow`, discarding the old ratchet key. State seized before this call cannot follow past it.
   * `newRootSecret` = rekeyRootSecret(oldRoot, freshDH); the caller derives it (it needs the old root, which
   * the ratchet deliberately does not keep) and MUST discard it after this call.
   */
  rekey(newRootSecret: Uint8Array, rekeyWindow: number, nowWindow: number = currentWindowIndex()): void {
    this.rk = deriveRootRatchetKey(newRootSecret, this.dir);
    this.window = rekeyWindow;
    this.prevMatcher = null;
    this.advanceTo(nowWindow);
  }
}
