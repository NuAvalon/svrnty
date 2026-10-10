// src/lib/trust/piece2-genesis.ts
/**
 * Piece-2 mutual-block — the GENESIS-INIT spine hook (task #579, Flint #159801 / Apollo #159806 ruling).
 *
 * WHAT IT DOES: registers a run-once-at-mint hook that writes an EXPLICIT empty suppression record for a
 * freshly-minted identity. This is the positive "never-suppressed" baseline the emit path needs: an absent
 * suppression record reads as null ⇒ SUPPRESS-ALL (§F3 fail-closed, suppression.ts / client-store), so a new
 * user with no record would emit visible-affirms to NO ONE at flip (fully dark forever) until they manually
 * touched a suppression control. The genesis event writes the empty record so a new user is correctly
 * default-discoverable the moment the feature is live, while a survivor who later blocks/goes-private gets a
 * populated record that the block chokepoints maintain (block-suppression.ts).
 *
 * ★ WHY A GENESIS EVENT, NOT AN UNLOCK FLAG-READ (Flint #159801). The signal MUST be the mint EVENT, fired
 * synchronously inside generateIdentity (identity-genesis-hooks.runGenesisHooks @ browser-identity.ts). A
 * durable "is this a new identity?" FLAG read at unlock would re-inherit the absent-vs-unreadable regress: a
 * decrypt-fail of the flag is indistinguishable from "truly new" ⇒ false-genesis ⇒ overwrite a populated
 * record with empty ⇒ RE-EXPOSE a survivor's blocks. At mint the code KNOWS it is genesis by construction, and
 * no suppression record can pre-exist a brand-new fingerprint ⇒ writing empty is unambiguous and safe HERE and
 * ONLY here. This hook is NEVER wired to the unlock path.
 *
 * ★ FAIL-CLOSED CONTRACT (idempotent + degrades-to-more-suppression). runGenesisHooks swallows a throwing hook
 * (best-effort — identity creation must never fail on a hook). That is SAFE because the consumer fails closed:
 * if this write is swallowed (e.g. a transient store error), the new user simply has NO record ⇒ getSuppression
 * Record returns null ⇒ suppress-all ⇒ the new user is DARK until a record lands — under-reveal, never a
 * re-expose. Idempotent: writing `emptySuppression()` for a fresh fp is a fixed point (a genesis fp cannot have
 * a populated record to clobber). We therefore write UNCONDITIONALLY at genesis (do NOT read-first: at a real
 * genesis `getSuppressionRecord` would return null anyway, and null is ambiguous absent-vs-unreadable OUTSIDE
 * genesis — but this hook only ever fires at genesis, where null means absent-and-safe-to-init).
 *
 * ★ INTEGRATION SEAM (DEFERRED / §8). Registration is NOT a module-load side effect — the app bootstrap calls
 * registerPiece2GenesisInit() once during init (the ship-time wiring). Importing this module registers nothing;
 * on `main`-without-the-call, runGenesisHooks is a no-op. Keeps the mechanism drivable + reviewable while DARK.
 */
import { registerGenesisHook, type GenesisHook } from '@/lib/identity/identity-genesis-hooks';
import { setSuppressionRecord as realSetSuppressionRecord } from '@/lib/identity/client-store';
import { emptySuppression, type SuppressionRecord } from '@/lib/trust/suppression';

/**
 * Factory: build the genesis hook over an injected suppression-record writer (DI for IndexedDB-free unit
 * testing). The hook writes an explicit empty suppression record for the freshly-minted `fingerprint`.
 * Idempotent; relies on runGenesisHooks' swallow + the consumer's null-⇒-suppress-all for fail-closed. A no-op
 * on an empty/garbage fingerprint (defensive; genesis always supplies one).
 */
export function makePiece2GenesisInit(
  setSuppressionRecord: (fp: string, rec: SuppressionRecord) => Promise<void>,
): GenesisHook {
  return async (fingerprint: string): Promise<void> => {
    const fp = (fingerprint || '').trim();
    if (!fp) return; // defensive — genesis always supplies a real fp; never write under an empty key
    // Unconditional at genesis: a brand-new fp has no record, so this cannot clobber a populated one. If it
    // throws (e.g. locked/store error) runGenesisHooks swallows it and the consumer fails closed (null⇒dark).
    await setSuppressionRecord(fp, emptySuppression());
  };
}

/** The default genesis hook, wired to the real IndexedDB suppression store (exported for direct testing). */
export const piece2GenesisInit: GenesisHook = makePiece2GenesisInit(realSetSuppressionRecord);

/**
 * Register the piece-2 genesis-init hook into the identity mint flow. Call ONCE from the app bootstrap (the
 * deferred §8 integration). Safe to call behind the flag or unconditionally — the hook only writes an
 * owner-local suppression record that nothing READS until isPiece2MutualBlockLive() flips, so wiring it before
 * flip just pre-populates the correct default. Idempotent registration is the caller's concern (call once).
 */
export function registerPiece2GenesisInit(): void {
  registerGenesisHook(piece2GenesisInit);
}
