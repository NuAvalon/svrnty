// src/lib/identity/identity-genesis-hooks.ts
/**
 * Identity GENESIS hook registry — a dependency-free pub/sub so a feature module can hang
 * run-once-at-mint initialization off the identity-creation EVENT, WITHOUT browser-identity
 * importing that feature (no module cycle, no cross-branch coupling).
 *
 * WHY A REGISTRY (not a direct call). piece-2 mutual-block needs an empty suppression record written
 * exactly ONCE at genesis (Apollo's spine lane). Flint #159801 / Apollo #159806 ruled that signal must
 * be a POSITIVE genesis EVENT fired synchronously inside the generateIdentity flow — NOT a durable flag
 * READ at unlock (a flag-read re-inherits the absent-vs-unreadable regress: a decrypt-fail of the flag
 * storage is indistinguishable from "truly new" → false-genesis → overwrite-empty → re-expose). At mint
 * time the code KNOWS it is genesis by construction. This registry lets the spine REGISTER its init INTO
 * the mint flow; generateIdentity (main) stays blind to the spine — it just runs whatever is registered.
 *
 * FAIL-CLOSED CONTRACT (load-bearing). runGenesisHooks is best-effort: a throwing hook is logged and
 * swallowed so identity creation never fails on a hook. This is SAFE because every genesis-hook consumer
 * MUST itself fail closed on the absence of its init — e.g. a missing suppression record reads as null ⇒
 * suppress-all (over-dark), never as "nothing to suppress" (re-expose). A swallowed hook therefore
 * degrades toward MORE suppression, never less. Hooks MUST also be idempotent (a future re-mint / retry
 * must not double-apply). The signal is the mint EVENT; the safety is in the consumer's null-handling.
 */

/** A genesis hook. Receives the freshly-minted identity fingerprint. MUST be idempotent + fail-closed. */
export type GenesisHook = (fingerprint: string) => void | Promise<void>;

const genesisHooks: GenesisHook[] = [];

/**
 * Register a run-once-at-genesis hook. Called at module-load by a feature that needs to initialize
 * per-identity state at the mint event (e.g. the spine's empty-suppression-record init). On `main`
 * nothing registers → runGenesisHooks is a no-op.
 */
export function registerGenesisHook(fn: GenesisHook): void {
  genesisHooks.push(fn);
}

/**
 * Fire every registered genesis hook SYNCHRONOUSLY IN THE MINT FLOW (awaited, in registration order).
 * Best-effort per the fail-closed contract above: a throwing hook is logged + swallowed so identity
 * creation cannot be broken by a hook. Called exactly once per genesis by browser-identity.generateIdentity.
 */
export async function runGenesisHooks(fingerprint: string): Promise<void> {
  for (const fn of genesisHooks) {
    try {
      await fn(fingerprint);
    } catch (e) {
      // Swallow: the consumer fails closed on the absent init (null ⇒ suppress-all), so a failed hook
      // degrades toward more suppression, never a re-expose. Surface for diagnosis only.
      console.warn('[genesis-hook] a genesis hook threw (swallowed; consumer must fail closed)', e);
    }
  }
}

/** Test-only: clear registered hooks so a test can register in isolation. NOT for production use. */
export function __clearGenesisHooksForTest(): void {
  genesisHooks.length = 0;
}
