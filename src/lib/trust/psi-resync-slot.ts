// src/lib/trust/psi-resync-slot.ts
// #704 D-S51 option (A): distress rides the PSI resync (contract svrnty_704A_distress_rides_resync_v3.md).
//
// Every tick sends a constant number (K) of initiate-shaped PSI requests. Each one:
//   - pads its blinded set to exactly N entries with dummies made the SAME way as real entries (x25519 with the
//     request's own PSI scalar over a uniform 32-byte input, which is distributed like H(fp)), so the set size is
//     hidden from the satellite AND the responder. Raw random bytes would NOT do: real outputs always have the
//     top bit clear and no torsion component, so ~half of random dummies are recognizable (Apollo F-4, #1282);
//   - carries exactly ONE slot = a full K1 onion (sealForRoute: uniform 2048B frame → guardian DEVICE seal →
//     satellite seal + route_id). A queued cry → a 'distress' onion; otherwise a 'cover' onion built the same
//     way to a dummy device + random route, so the two are the same length and the PSI satellite (which
//     forwards the slot opaque, S59) cannot tell them apart;
//   - is padded as a WHOLE JSON body to one fixed byte length BEFORE the satellite seal (inside the AEAD, R1).
// A tick with no due peer sends a cover initiate (cover:true inside the seal; the satellite creates no session).
//
// No new crypto: composition over sealForRoute / sealPsiToSatellite (G4). Timing (R6): nothing here sends;
// enqueueCry only records the cry, and the next scheduled tick picks it up.
//
// KNOWN RESIDUAL (G2), true in the current single-satellite deployment: the PSI satellite and the guardian's
// satellite are the same operator, so it can link a route-R deposit to the guardian's poll of R within a
// window. No "metadata-private" claim until guardian-poll batching lands (Flint C5).
// NOT covered here: the respond-phase traffic (pending / blinded / respond) stays per-session. It carries no
// slot and is PSI metadata the satellite already holds, so it does not decide distress indistinguishability.
// The reply bucket is S58.

import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { sealForRoute } from '../sync/onion-transport.js';
import { buildCoverPayload } from '../crypto/distress-mark.js';
import { generateMailboxKeypair, toPublicKeys } from '../crypto/mailbox-keys.js';
import type { MailboxEnvelopePackage, MailboxPublicKeys } from '../crypto/mailbox-envelope.js';
import { deriveSubRouteId, currentSubRouteIndex, currentWindowIndex, SUB_ROUTES_PER_WINDOW } from '../crypto/route-ratchet.js';

/** N: blinded entries per request (product number, Peter; proposed 64). */
export const PSI_BLINDED_BUCKET_N = 64;
/** K: initiate-shaped requests per tick (product number, Peter; proposed 1). */
export const PSI_REQUESTS_PER_TICK_K = 1;
/** R5: a cry rides this many consecutive ticks, re-sealed fresh each time; the guardian dedups by epoch. */
export const CRY_TICKS = 3;
/** Whole initiate body length in bytes before the satellite seal (R1). Measured max real body at N=64 =
 *  14738B (N blinded + one ~10KB slot + response_pub + fixed fields); 16384 leaves 1.6KB headroom. Sealed wire
 *  ≈ 24KB per request. padInitiateBody throws if exceeded (and the length test catches it). Re-measure if N moves. */
export const PSI_INITIATE_BODY_BYTES = 16384;

/** What a cry needs to be sealed again each tick (fresh KEM + nonce every time: the seal is re-run, never reused). */
export interface CryInput {
  /** The signed distress cell (buildDistressCell). Must fit one uniform frame. */
  payload: Uint8Array;
  /** Guardian DEVICE mailbox keys (the inner seal). */
  guardianDevice: MailboxPublicKeys;
  /** Guardian's satellite routing keys (the outer seal). */
  guardianSatellite: MailboxPublicKeys;
  /** The guardian-direction ratchet key rk_W for the window containing nowMs (G3: called at seal time, so a cry
   *  spanning a window re-routes). The slot goes to the per-TICK sub-route of that window (DW10), never the
   *  per-window route_id, so a cry riding 3 ticks shows 3 different ids, like cover. */
  routeKeyAt: (nowMs: number) => Uint8Array;
}

/**
 * The per-device slot source the tick draws from. One instance per running sync loop.
 * enqueueCry never sends (R6/D-6). nextSlot is called exactly once per request.
 */
export class ResyncSlotSource {
  private cry: { input: CryInput; ticksLeft: number } | null = null;
  /** F-7 (DW15): sub-route indices this DEVICE used for any cry, per window. Kept across cries (a replacement cry
   *  must not restart at the clock's index), pruned below W-1. Local state only. */
  private readonly usedSubRoutes = new Map<number, Set<number>>();

  constructor(
    /** Satellite keys used for the cover onion's outer seal: the same satellite a real cry goes to today (G2). */
    private readonly coverSatellite: MailboxPublicKeys,
    /** Clock (injectable for tests). Sub-route index comes from wall-clock time so the guardian can derive it. */
    private readonly now: () => number = Date.now,
  ) {}

  /** Record a cry for the next scheduled ticks. A new cry REPLACES an unfinished one and rides its own full 3 ticks
   *  (the guardian dedups by mark epoch). */
  enqueueCry(input: CryInput): void {
    this.cry = { input, ticksLeft: CRY_TICKS };
  }

  /**
   * F-6/F-7 (DW10/DW15): the sub-route index must be UNIQUE PER DEVICE PER WINDOW (across cries, so a replacement
   * cry can't reuse one), not just the clock bucket of the seal time. Seals happen after the tick's network pass,
   * so two ticks can land < SUB_ROUTE_SECONDS apart in one bucket; reusing the bucket index would repeat a route
   * (the F-5 tell). Start from the clock's index and take the next one this device hasn't used in this window. The guardian polls all indices of the window (+ the previous), so any index is received.
   */
  private claimSubRoute(nowMs: number): number | null {
    const w = currentWindowIndex(nowMs);
    // Keep W-1 too: if the clock steps BACKWARDS across a boundary, a seal can land in W-1 after one in W, and its
    // used set must still be there (Apollo W9: pruning to W alone only differs in that case, so it has no test).
    for (const old of this.usedSubRoutes.keys()) if (old < w - 1) this.usedSubRoutes.delete(old);
    const used = this.usedSubRoutes.get(w) ?? new Set<number>();
    this.usedSubRoutes.set(w, used);
    const start = currentSubRouteIndex(nowMs);
    for (let k = 0; k < SUB_ROUTES_PER_WINDOW; k++) {
      const i = (start + k) % SUB_ROUTES_PER_WINDOW;
      if (!used.has(i)) {
        used.add(i);
        return i;
      }
    }
    return null; // every index of this window already carried a cry from this device
  }

  /** True while a cry still has ticks to ride. Local state only; never on the wire. */
  hasPendingCry(): boolean {
    return this.cry !== null && this.cry.ticksLeft > 0;
  }

  /**
   * The ONE slot for the next request: the cry (re-sealed fresh) while it has ticks left, else a cover onion.
   * Both go through sealForRoute with a 2048B frame, 32-hex route and same-size keys → identical length.
   */
  async nextSlot(nowMs: number = this.now()): Promise<MailboxEnvelopePackage> {
    if (this.cry && this.cry.ticksLeft > 0) {
      const { input } = this.cry;
      const idx = this.claimSubRoute(nowMs); // before any state change
      // Exhausted (≥ 12 cry ticks in one window): NEVER throw (a throw = a zero-request tick, itself a tell). Send a
      // cover slot of the same shape; the cry stays pending and rides from the next window.
      if (idx === null) return sealCoverSlot(this.coverSatellite);
      const routeId = deriveSubRouteId(input.routeKeyAt(nowMs), idx);
      this.cry.ticksLeft -= 1;
      // Equal work: the cover path mints a throwaway device keypair (ML-KEM keygen). Do the same here and
      // discard it, so a distress slot does not come out measurably faster than a cover slot.
      void generateMailboxKeypair();
      if (this.cry.ticksLeft === 0) this.cry = null;
      return sealForRoute({
        payload: input.payload,
        frameType: 'distress',
        recipientDevice: input.guardianDevice,
        satellite: input.guardianSatellite,
        routeId,
      });
    }
    return sealCoverSlot(this.coverSatellite);
  }
}

/** G1/R3: a cover onion to a throwaway device on a random route, through the SAME construction as a cry. */
export async function sealCoverSlot(satellite: MailboxPublicKeys): Promise<MailboxEnvelopePackage> {
  return sealForRoute({
    payload: buildCoverPayload(),
    frameType: 'cover',
    recipientDevice: toPublicKeys(generateMailboxKeypair()),
    satellite,
    routeId: bytesToHex(randomBytes(16)),
  });
}

/** A dummy blinded entry: x25519(sk, uniform 32 bytes), the same map real entries go through (H(fp) is a uniform
 *  HKDF output), with the same request scalar. A degenerate (low-order) input is rejected by getSharedSecret → retry. */
function dummyBlinded(sk: Uint8Array): string {
  for (;;) {
    try {
      return Buffer.from(x25519.getSharedSecret(sk, randomBytes(32))).toString('base64');
    } catch {
      // ~2^-250: a low-order input; draw again.
    }
  }
}

/**
 * Pad a blinded set (with its parallel fp order) to exactly N entries. Dummies get fp '' so
 * completeTrustSync's `if (fp)` skips any (negligible-probability) dummy match. The caller must already have
 * refused a set larger than N. Shuffles real + dummy together so position says nothing.
 */
export function padBlindedSet(
  blinded: string[],
  fpOrder: string[],
  shuffle: <T>(a: T[]) => T[],
  psiPrivateKeyB64: string,
): { blinded: string[]; fpOrder: string[] } {
  if (blinded.length > PSI_BLINDED_BUCKET_N) {
    throw new Error(`padBlindedSet: ${blinded.length} entries exceed the bucket N=${PSI_BLINDED_BUCKET_N}`);
  }
  const sk = Buffer.from(psiPrivateKeyB64, 'base64');
  const pairs = blinded.map((b, i) => ({ b, fp: fpOrder[i] ?? '' }));
  while (pairs.length < PSI_BLINDED_BUCKET_N) pairs.push({ b: dummyBlinded(sk), fp: '' });
  const shuffled = shuffle(pairs);
  return { blinded: shuffled.map(p => p.b), fpOrder: shuffled.map(p => p.fp) };
}

/**
 * R1: serialize the initiate body and pad it to exactly PSI_INITIATE_BODY_BYTES with a `pad` field. Returns
 * the padded OBJECT (the satellite seal re-serializes it; JSON.stringify of the same object is deterministic,
 * so the sealed plaintext length is exactly PSI_INITIATE_BODY_BYTES). Throws if the body is already too large:
 * a short or oversized request would be a tell, so it must fail loudly in tests, never send.
 */
export function padInitiateBody(body: Record<string, unknown>): Record<string, unknown> {
  const withEmptyPad = { ...body, pad: '' };
  const baseLen = new TextEncoder().encode(JSON.stringify(withEmptyPad)).length;
  const fill = PSI_INITIATE_BODY_BYTES - baseLen;
  if (fill < 0) {
    throw new Error(`padInitiateBody: body ${baseLen}B exceeds the fixed ${PSI_INITIATE_BODY_BYTES}B bucket`);
  }
  return { ...body, pad: '0'.repeat(fill) };
}
