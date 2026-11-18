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
 * ★ ABSENT-ONLY, THROUGH THE ATOMIC UPDATE. The hook writes the empty record ONLY when the stored record is ABSENT, as one compare-and-swap (the same update Block and Unblock use). An existing record,
 * readable or not, is never replaced by empty: not one a restore just wrote, not a populated one, and a record that exists but cannot be read is left alone (it is not "absent"). The old
 * argument against reading first was that a null read cannot tell "absent" from "unreadable"; the sealed three-state read tells them apart, so a read-first decision is now safe, and it
 * closes the gap that a restore which wrote a record before a mint hook ran could have been overwritten with empty.
 *
 * ★ FAIL-CLOSED CONTRACT. runGenesisHooks swallows a throwing hook (best-effort: identity creation must never fail on a hook). That is SAFE because the consumer fails closed: if the write
 * is swallowed (a locked session, a store error, a lost comparison that keeps losing), the new user simply has NO record, so the reader returns null and suppresses everyone: dark, an
 * under-reveal and never a re-expose. Idempotent: a second run finds the record present and writes nothing.
 *
 * ★ INTEGRATION SEAM (DEFERRED / §8). Registration is NOT a module-load side effect — the app bootstrap calls
 * registerPiece2GenesisInit() once during init (the ship-time wiring). Importing this module registers nothing;
 * on `main`-without-the-call, runGenesisHooks is a no-op. Keeps the mechanism drivable + reviewable while DARK.
 */
import { registerGenesisHook, type GenesisHook } from '@/lib/identity/identity-genesis-hooks';
import { updateSuppressionRecord as realUpdateSuppressionRecord } from '@/lib/identity/client-store';
import { emptySuppression, type SuppressionRecord } from '@/lib/trust/suppression';
import type { Decision, SealedRead, Update } from '@/lib/trust/suppression-restore';

/** What the hook did: wrote the empty record, or left an existing one alone (readable, or present but unreadable). */
export type GenesisInitOutcome = 'written' | 'kept-existing' | 'kept-unreadable';

/**
 * The decision, pure: write the explicit empty record ONLY when none is stored. A record that exists is kept whatever it holds, and one that exists but cannot be read is kept too (it is not absent).
 */
export function decideGenesisInit(held: SealedRead<SuppressionRecord>): Decision<SuppressionRecord, GenesisInitOutcome> {
  if (held.state === 'absent') return { write: emptySuppression(), result: 'written' };
  return { result: held.state === 'ok' ? 'kept-existing' : 'kept-unreadable' };
}

/**
 * Factory: build the genesis hook over an injected atomic update (DI for IndexedDB-free unit testing). The hook writes an explicit empty suppression record for the freshly-minted `fingerprint`
 * if, and only if, none is stored. Idempotent; relies on runGenesisHooks' swallow and the consumer's null-means-suppress-all for fail-closed. A no-op on an empty or garbage fingerprint
 * (defensive; genesis always supplies one).
 */
export function makePiece2GenesisInit(updateSuppression: (fp: string) => Update<SuppressionRecord>): GenesisHook {
  return async (fingerprint: string): Promise<void> => {
    const fp = (fingerprint || '').trim();
    if (!fp) return; // defensive: genesis always supplies a real fp; never write under an empty key
    await updateSuppression(fp)<GenesisInitOutcome>(decideGenesisInit);
  };
}

/** The default genesis hook, wired to the real IndexedDB suppression store (exported for direct testing). */
export const piece2GenesisInit: GenesisHook = makePiece2GenesisInit(realUpdateSuppressionRecord);

/**
 * Register the piece-2 genesis-init hook into the identity mint flow. Call ONCE from the app bootstrap (the
 * deferred §8 integration). Safe to call behind the flag or unconditionally — the hook only writes an
 * owner-local suppression record that nothing READS until isPiece2MutualBlockLive() flips, so wiring it before
 * flip just pre-populates the correct default. Idempotent registration is the caller's concern (call once).
 */
export function registerPiece2GenesisInit(): void {
  registerGenesisHook(piece2GenesisInit);
}
