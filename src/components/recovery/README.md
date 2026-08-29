# Recovery UI (L8) — Cursor build notes

**Component owner (UI):** Cursor · **Crypto owner:** team (do not modify `src/lib/crypto/recovery.ts` or `src/lib/sync/vault.ts`)  
**Brief:** `CURSOR.md` L8 · Queue: DO-SECOND · Aesthetic: Solar Ember · **Trigger:** PR #61 v4 dual-envelope + Hypatia/Flint copy final

## What we built
| File | Role |
|------|------|
| `EntropyMeter.tsx` | Live strength meter for unlock passphrase / future soul-seed word entry |
| `SoulSeedReveal.tsx` | One-time reveal after forge — Hypatia genesis copy (passphrase-free unlock on v4) |
| `seedVaultRestore.ts` | Thin UI adapter: `extractRecoveryVault` → `recoverFromSeedPhrase` → IndexedDB |
| `IdentitySeal.tsx` | Deterministic fingerprint → SVG seal (I-6; no decorative randomness) |
| `solar-ember.ts` | Shared palette tokens from CURSOR.md |

Wired into `SoverentityFrontend.tsx`: forge passphrase meter, recovery-reveal screen, restore-verify with **v4 seed-only path**.

## v4 passphrase-free restore (DO-SECOND — after Flint #61)

Fleet seam (call only, never reimplement):

```ts
const kv = extractRecoveryVault(data);           // no passphrase
const bundle = await recoverFromSeedPhrase(kv, phrase);
```

| Backup | UI |
|--------|-----|
| **v4** `.svrnty` | Daily passphrase unlock **plus** "Lost your passphrase? Recover with your seed phrase" |
| **v3** `.svrnty` | Passphrase only + Hypatia v3-guard copy + post-open migration nudge — **no false promise** |
| v4 with no recovery configured | `extractRecoveryVault` fails honestly ("no recovery vault") |

### Hypatia / Flint copy (shipped)
- Entry: Lost your passphrase? → Recover with your seed phrase
- Heading: Recover with your seed phrase
- Body: Enter your 12-word recovery phrase to unlock this backup — it works without your passphrase.
- Claim-honesty helper: phrase decrypts **this backup file** (replacing passphrase); phrase alone does **not** reconstruct identity from nothing.
- Field / CTA: Recovery phrase (12 words) · Recover my identity
- Invalid phrase: That recovery phrase doesn't match an identity.
- v3-guard: This backup was created before passphrase-free recovery… + Re-export…
- Genesis (`SoulSeedReveal`): Your 12-word recovery phrase. Write it down… unlocks your backup without it… NOT your everyday passphrase.
- Migration nudge: Update your backup to enable passphrase-free recovery (after opening a v3 file)

**Co-location warning** (don't store phrase next to backup file): left as Peter/team dial — neutral genesis ships; not defaulted on.

## Files touched (this task)
- `src/components/recovery/seedVaultRestore.ts` (adapter)
- `src/components/SoverentityFrontend.tsx` (restore UI + v3 migration nudge)
- `src/components/recovery/SoulSeedReveal.tsx` (genesis copy)
- `src/components/recovery/README.md` (this note)
- `CURSOR_QUEUE.md` (DO-SECOND PR → #62)

## Assumptions
1. Forge phrase from `createKeyVault` is still **hex groups** (8×8), not BIP39-12 — Hypatia label says "12 words" (forward-looking). Flagged for Hypatia/Flint in the PR.
2. Identity reconstruction from classical private key via openpgp (`readPrivateKey` → userIDs + fingerprint) is UI-layer, not crypto invention.
3. `recoverFromShards` is **not** wired yet (CUR-9 collect-back / survivor-safety) — guardian path deferred.
4. Contacts / trust / settings stay in the passphrase-encrypted BODY and are **not** restored on the seed path.

## Questions for the team (in PR description — need your call)

1. **Flint — PQ after seed restore:** `PrivateKeyBundle` returns PQ *secrets* only; `storePQKeys` needs public halves. Prefer (a) fleet helper, (b) include publics in bundle, or (c) leave PQ to pq-migrate screen?
2. **Hypatia — "12 words" vs hex groups:** forge still emits hex groups. Keep "12 words", soften label, or wait for BIP39?
3. **Hypatia — contacts honesty:** Seed path says contacts stay locked. OK, or stronger post-success interstitial?
4. **Flint / Archie — guardian shards:** wire tertiary path now (`recoverFromShards`) or wait for CUR-9?
5. **Peter — co-location dial:** add active "don't store phrase next to backup file" warning, or keep neutral genesis?
6. **Athena — merge order vs #60:** #60 is Case A/B 2FA JSON copy (still draft). Preferred order?

## Invariants honored
- No crypto / vault format reimplementation
- I-6: seal still recomputed from fingerprint at render
- Claim-honesty: seed path only offered when `version === 4`; v3 gets re-export nudge only; UI + `extractRecoveryVault` both refuse v3
