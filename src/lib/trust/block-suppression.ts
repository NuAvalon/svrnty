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
import { getSuppressionRecord, setSuppressionRecord } from '@/lib/identity/client-store';
import { suppressPerson, unsuppressPerson, type SuppressionRecord } from '@/lib/trust/suppression';

/** The two client-store calls this helper needs — injected for tests (no IndexedDB). */
export interface SuppressionStoreSeam {
  getSuppressionRecord: (ownerFingerprint: string) => Promise<SuppressionRecord | null>;
  setSuppressionRecord: (ownerFingerprint: string, rec: SuppressionRecord) => Promise<void>;
}

const defaultStore: SuppressionStoreSeam = { getSuppressionRecord, setSuppressionRecord };

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
export async function applyBlockSuppression(
  ownerFingerprint: string,
  peerDurableId: string | undefined | null,
  blocked: boolean,
  store: SuppressionStoreSeam = defaultStore,
): Promise<BlockSuppressionResult> {
  const id = (peerDurableId ?? '').trim();
  if (!id) return { wrote: false, outcome: 'no-durable-id' };

  const rec = await store.getSuppressionRecord(ownerFingerprint);
  if (rec === null) {
    // §F3: unreadable/absent ⇒ already fail-closed to suppress-all + the `blocked` flag covers it. Writing
    // here would risk reducing a corrupt record's suppress-all to suppress-one → never write on doubt.
    return { wrote: false, outcome: 'skipped-fail-closed' };
  }

  try {
    if (blocked) {
      const next = suppressPerson(rec, id); // returns the SAME ref if already present (idempotent)
      if (next === rec) return { wrote: false, outcome: 'already' };
      await store.setSuppressionRecord(ownerFingerprint, next);
      return { wrote: true, outcome: 'added' };
    }
    // unblock: remove the person-entry. unsuppressPerson always returns a NEW object, so compare
    // persons.length (it only ever removes) to skip a redundant write when the entry wasn't present.
    const next = unsuppressPerson(rec, id);
    if (next.persons.length === rec.persons.length) return { wrote: false, outcome: 'already' };
    await store.setSuppressionRecord(ownerFingerprint, next);
    return { wrote: true, outcome: 'removed' };
  } catch {
    // A write failure (e.g. the session locked between read and write) never surfaces: the block is still
    // enforced by the fail-closed record state + the `blocked` flag, and a later block retries the write.
    return { wrote: false, outcome: 'skipped-error' };
  }
}
