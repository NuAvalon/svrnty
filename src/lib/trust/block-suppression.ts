// src/lib/trust/block-suppression.ts
/**
 * Piece-2 mutual-block — block → durable SUPPRESSION-record POPULATE (task #579; Archie do-no-harm gate
 * #159479/#159668; spec KB#92246; grounding KB#92281).
 *
 * WHAT IT IS: the write-path that makes the per-person BLOCK action populate F's durable, rotation-stable
 * owner-local suppression RECORD (suppression.ts) — the SOLE load-bearing emit-side source of "whom I've
 * gone private to". The per-contact `blocked` flag (piece-1) stays as defense-in-depth (it is UNIONed at the
 * emit callsite — suppression.ts §F3), but the durable_id-keyed RECORD is what survives key-rotation /
 * mailbox-rebuild / relay-transfer: it is F's vault data, keyed by the peer's CANONICAL fingerprint
 * (hex(SHA256(sign‖enc‖kem‖sig)) — fingerprint.ts, rotation-stable), not by any rotating UUID / mailbox_fp /
 * route_id. Block writes the person-entry; unblock removes the person-entry it wrote.
 *
 * ★ §F3 FAIL-CLOSED — NEVER REDUCE SUPPRESSION ON DOUBT: if getSuppressionRecord returns null (session
 * locked / decrypt-fail / malformed / absent) we do NOT write. Overwriting an UNREADABLE record with a fresh
 * {this-person} set would REDUCE a corrupt record's suppress-all (isPartySuppressed(null) ⇒ true at the emit
 * callsite) down to suppress-ONE = a survivor RE-EXPOSE. Meanwhile the block is still enforced by that
 * fail-closed null⇒suppress-all AND the synchronously-set `blocked` flag (defense-in-depth). The durable
 * person-entry is (re)written on a later block once the record reads cleanly — the emit-path unlock/genesis
 * init writes an EXPLICIT empty record so this null window closes (KB#92281).
 *
 * DELIVERY-agnostic + DARK: this only writes an owner-local record that the (not-yet-wired) emit path reads;
 * with emit dark it is a no-live-effect populate. §C firewall: the record NEVER rides the wire.
 *
 * The store seam is INJECTED (defaults to the real client-store) so this is unit-testable IndexedDB-free —
 * mirrors know-layer-sync.ts's KnowOverlayStore pattern.
 */
import { updateSuppressionRecord } from '@/lib/identity/client-store';
import { suppressPerson, unsuppressPerson, type SuppressionRecord } from '@/lib/trust/suppression';
import type { Decision, SealedRead, Update } from '@/lib/trust/suppression-restore';

/**
 * The one client-store call this helper needs, injected for tests (no IndexedDB): the ATOMIC update of the owner's suppression record. A Block or Unblock decided on a record read before a
 * restore merged its persons must not put the record back without them, so the change is never read-then-replace: the store commits only if the record is still what was read.
 */
export interface SuppressionStoreSeam {
  updateSuppression: (ownerFingerprint: string) => Update<SuppressionRecord>;
}

const defaultStore: SuppressionStoreSeam = { updateSuppression: updateSuppressionRecord };

export type BlockSuppressionOutcome =
  | 'added' // block → person durable_id added to the record (written)
  | 'removed' // unblock → person durable_id removed from the record (written)
  | 'already' // idempotent no-op: block an already-suppressed / unblock a non-suppressed person
  | 'no-durable-id' // keyless/gray contact (no canonical fingerprint) — nothing durable to suppress
  | 'skipped-fail-closed' // record unreadable (null) — do NOT reduce suppression on doubt (block still holds)
  | 'skipped-error'; // a write failed (e.g. session locked mid-op) — swallowed; block still holds, later retry

export interface BlockSuppressionResult {
  wrote: boolean;
  outcome: BlockSuppressionOutcome;
}

/**
 * Apply a block/unblock to F's durable suppression record.
 *
 * @param ownerFingerprint F's own fingerprint (the record owner / AAD binding).
 * @param peerDurableId    the peer's CANONICAL fingerprint (TrustEdge.peer_fingerprint /
 *                         ContactRecord.fingerprint = hex(SHA256(sign‖enc‖kem‖sig)); rotation-stable).
 * @param blocked          true = block (add person-entry); false = unblock (remove person-entry).
 * @param store            injectable store seam (defaults to the real client-store).
 *
 * Idempotent. Fail-closed (never reduces suppression on an unreadable record). Never throws — a write
 * failure is swallowed (the block still holds via the fail-closed record + the `blocked` flag), so callers
 * may `void` it alongside the existing reconcileAllowedOnConsentChange fire-and-forget.
 */
/**
 * The decision, on the record as the store read it. PURE: the atomic update can run it more than once (it decides again on a newer record when another write landed first). A record that is
 * unreadable or absent is never written (§F3).
 */
export function decideBlock(held: SealedRead<SuppressionRecord>, id: string, blocked: boolean): Decision<SuppressionRecord, BlockSuppressionOutcome> {
  if (held.state !== 'ok') return { result: 'skipped-fail-closed' };
  const rec = held.value;
  if (blocked) {
    const next = suppressPerson(rec, id); // returns the SAME ref if already present (idempotent)
    return next === rec ? { result: 'already' } : { write: next, result: 'added' };
  }
  // unblock: remove the person-entry. unsuppressPerson always returns a NEW object, so compare persons.length (it only ever removes) to skip a redundant write.
  const next = unsuppressPerson(rec, id);
  return next.persons.length === rec.persons.length ? { result: 'already' } : { write: next, result: 'removed' };
}

export async function applyBlockSuppression(
  ownerFingerprint: string,
  peerDurableId: string | undefined | null,
  blocked: boolean,
  store: SuppressionStoreSeam = defaultStore,
): Promise<BlockSuppressionResult> {
  const id = (peerDurableId ?? '').trim();
  if (!id) return { wrote: false, outcome: 'no-durable-id' };

  try {
    const outcome = await store.updateSuppression(ownerFingerprint)<BlockSuppressionOutcome>((held) => decideBlock(held, id, blocked));
    return { wrote: outcome === 'added' || outcome === 'removed', outcome };
  } catch {
    // A write failure (e.g. the session locked between read and write, or a record that keeps changing) never surfaces: the block is still enforced by the fail-closed record state + the
    // `blocked` flag, and a later block retries the write.
    return { wrote: false, outcome: 'skipped-error' };
  }
}
