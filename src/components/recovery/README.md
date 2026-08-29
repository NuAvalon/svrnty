# Recovery UI (L8) — Cursor build notes

**Component owner (UI):** Cursor · **Crypto owner:** team (do not modify `src/lib/crypto/recovery.ts` or `src/lib/sync/vault.ts`)  
**Brief:** `CURSOR.md` L8 · Aesthetic: Solar Ember · **Trigger:** PR #61 v4 dual-envelope landed → wire UI

## What we built
| File | Role |
|------|------|
| `EntropyMeter.tsx` | Live strength meter for unlock passphrase / future soul-seed word entry |
| `SoulSeedReveal.tsx` | One-time reveal of the recovery phrase after forge (2nd-factor copy) |
| `seedVaultRestore.ts` | Thin UI adapter: `extractRecoveryVault` → `recoverFromSeedPhrase` → IndexedDB |
| `IdentitySeal.tsx` | Deterministic fingerprint → SVG seal (I-6; no decorative randomness) |
| `solar-ember.ts` | Shared palette tokens from CURSOR.md |

Wired into `SoverentityFrontend.tsx`: forge passphrase meter, recovery-reveal screen, restore-verify with **v4 seed-only path**.

## v4 passphrase-free restore (this PR — after Flint #61)

Fleet seam (call only, never reimplement):

```ts
const kv = extractRecoveryVault(data);           // no passphrase
const bundle = await recoverFromSeedPhrase(kv, phrase);
```

| Backup | UI |
|--------|-----|
| **v4** `.svrnty` | Daily passphrase unlock **plus** "Lost your passphrase? Recover with your recovery phrase" → seed path |
| **v3** `.svrnty` | Passphrase only; honest migration nudge (re-export to enable seed recovery) — **no false promise** |
| v4 with no recovery configured | `extractRecoveryVault` fails honestly ("no recovery vault") |

**Claim-honesty:**
- Seed path restores **identity keys** (classical PGP + KeyVault). Name/email/fingerprint come from the recovered PGP key userIDs.
- Contacts / trust graph / settings live in the **passphrase-encrypted BODY** and are **not** restored on the seed path. Copy says so.
- Wrong phrase → `"That recovery phrase doesn't match this backup."` (no lockout).

## Files touched (this task)
- `src/components/recovery/seedVaultRestore.ts` (new adapter)
- `src/components/SoverentityFrontend.tsx` (restore UI + handler)
- `src/components/recovery/README.md` (this note)
- `CURSOR_QUEUE.md` (v4 seed path unblocked)

## Assumptions
1. Today's forge phrase from `createKeyVault` is still **hex groups** (8×8), not BIP39-12 — label says "recovery phrase"; placeholder mentions hex groups.
2. Identity reconstruction from classical private key via openpgp (`readPrivateKey` → userIDs + fingerprint) is UI-layer, not crypto invention.
3. `recoverFromShards` is **not** wired yet (CUR-9 collect-back / survivor-safety).

## Questions for the team (in PR description — need your call)

1. **Flint — PQ after seed restore:** `PrivateKeyBundle` returns PQ *secrets* only; `storePQKeys` needs a serialized bundle with *public* halves. Do not invent derivation in UI. Prefer: (a) fleet helper `bundleToStoredPQ(bundle)`, (b) include public keys in `PrivateKeyBundle`, or (c) leave PQ regeneratable via existing pq-migrate screen?
2. **Hypatia — contacts honesty:** Seed path copy says contacts stay locked under the passphrase. OK as shipped, or do you want a stronger post-success interstitial?
3. **Flint / Archie — guardian shards on this screen:** `recoverFromShards(kv, shards)` is the same extract seam. Wire a "I have guardian shards" tertiary path now, or wait for CUR-9?
4. **Athena — overlap with #60:** PR #60 (Case A/B 2FA copy on JSON restore) is still open. This PR targets binary `.svrnty` v4. Merge order preference?

## Invariants honored
- No crypto / vault format reimplementation
- I-6: seal still recomputed from fingerprint at render
- Claim-honesty: seed path only offered when `version === 4`; v3 gets re-export nudge only
