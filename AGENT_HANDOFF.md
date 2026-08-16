# AGENT HANDOFF — 2026-08-16

**From:** Cursor cloud agent (security punchlist pass on `cursor/security-punchlist-bb68`)  
**Context:** Peter asked to knock the review punchlist and leave a note for the five Opus agents (Athena/Flint/Archie et al.) who built svrnty.

---

## What this agent did (this PR)

Security / integrity punchlist from the Aug 16 review — **not** full Tier 0 product work.

| Fix | Where |
|---|---|
| `POST/PUT /api/identity/verify` → **410** (no more server OTP + `SoverentityIdentity` / `~/.soverentity`) | `app/api/identity/verify/route.ts` |
| Pre-deploy audit catches **imports** of `SoverentityIdentity` / `identity/core` in API routes | `scripts/pre-deploy-audit.sh` |
| Signal signing binds **`from`**; freshness window 7d; hybrid rejects legacy unbound encoding | `src/lib/trust/signals.ts` |
| Unlock gate: encrypted keys → lock screen → `initSessionKey` (no more `key.passphrase === userPhrase`) | `app/page.tsx` |
| `hasEncryptedKeys()` helper | `src/lib/identity/client-store.ts` |
| Create identity: **unlock passphrase required**; one-time **seed phrase reveal** gate | `src/components/SoverentityFrontend.tsx` |
| “Set passphrase” **re-wraps IndexedDB** via session key — does **not** overwrite PGP passphrase | same |
| Slug register sends `public_key` + `fingerprint` (was empty `publicKey`) | same |
| `updateContact` fail-closed fingerprint↔key binding | `client-store.ts` |
| `@noble/curves` declared; mutual-trust / PSI imports fixed for hashes/curves **v2** | `package.json`, `mutual-trust.ts`, `mutual-trust-sync.ts` |

**Deliberately not done here:** Tier 0.11–0.15 (two-sided book, vCard/CSV/dedup), 0.4 contact.update protocol, 0.6 messaging, 0.1 canonical envelope freeze, turning TS/ESLint back on for the whole tree, deleting `components.bak` / fs `core.ts`.

---

## What it’ll take to knock the *full* punchlist

Two queues. Do not mix them.

### Queue A — Security / substrate integrity (days of agent work, not weeks)

Done or nearly done after this PR. Remaining crumbs:

1. Joiner ceremony: verify **signed** card payload (not only fp↔key binding)
2. Dual backup KDFs: migrate vault packing to Argon2id only (`sync/backup.ts` still PBKDF2)
3. Turn `ignoreBuildErrors` / `ignoreDuringBuilds` **off** and fix compile breaks (esp. `contacts/types.ts` junk)
4. Delete or quarantine Node `fs` identity/contact managers if unused by CLI

### Queue B — Tier 0 product (9/10 ceremony pull) — **split across 5 Opus agents**

| Agent | Own these rows | Do not touch |
|---|---|---|
| **Athena-1 (UX law)** | **0.14** two-sided book (gray / living / DIM) + ignition bloom; shrink **0.8** lattice to that bloom | Planetarium expansion |
| **Athena-2 (contacts)** | **0.11** ordinary CRUD (phones, photo, multi-email) + **0.12** vCard UI (wire `vcard.ts`) + Contact Picker | Google OAuth |
| **Archie (merge)** | **0.13** dedup (E.164, fold email, living-wins) + format fields for **0.1/0.2** envelope + epoch/lineage **fields only** | Features for Tier 2 |
| **Flint (protocol)** | **0.1** canonical sign envelope (finish what signals started) + **0.4** contact.update/routing.update/ACK + **0.9** I-1/I-7 tests | Burn/summon (2.1) |
| **Flint/Athena (vault)** | Finish **0.10** PWA offline story; Argon2id single path; help copy vs seed phrase | Cloud sync OAuth |

**0.3 / 0.7** ceremony + tear: already strong — only polish / live auto-advance later.  
**0.5 / 0.6**: cuttable / court call — don’t start unless Peter says so.  
**0.15** demo script: blocked on 0.12+0.14+0.4.

### Standing rules for agents

1. **Pull test:** if it doesn’t serve 9/10 ceremony or first pilot invoice → paper.
2. **Formats cheap, features dear:** epoch/lineage fields can land without rotation UX.
3. **Do not reopen** `/api/identity` or `/api/identity/verify` server keygen/OTP.
4. **Do not** overwrite OpenPGP key passphrases with the user unlock passphrase.
5. Branch naming if using Cursor cloud: `cursor/<name>-bb68`. Prefer one concern per PR.
6. Read this file + the Aug 16 review before expanding TrustMap chrome.

---

## Suggested merge order

1. This security PR  
2. Archie 0.1/0.2 format fields  
3. Athena contacts import + two-sided book (can parallel after formats land)  
4. Flint 0.4 updates + 0.9 invariants  
5. Demo dry-run against 0.15 script  

---

## How to verify this PR quickly

```bash
bash scripts/pre-deploy-audit.sh
# Create identity with passphrase → must see seed phrase screen
# Refresh → must hit unlock gate (not auto-open)
# “Set passphrase” on legacy identity → signing still works (PGP passphrase unchanged)
```

*— handoff ends —*
