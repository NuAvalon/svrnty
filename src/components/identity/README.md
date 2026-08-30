# Identity components — Cursor UI notes

**Brief:** `CURSOR.md` I-6 / L1 · Aesthetic: Solar Ember  
**Hard boundary:** recompute seals from fingerprint; never touch per-peer encrypt / mailbox deposit.

## Production default: `phi` (Crystal)
- Fold (3–10) + formula sacred figure from the flat pool
- Soft **φ pond droplets** + **ogham notches**
- Crystal dendrites + facets + N-gon habit frames

## Lab A/B (frozen — do not overwrite)
See **[`archive/`](./archive/)** for screenshots, SVGs, and JSON fixtures.

- **`growth`** — original from Metatron demotion (`21d858c`): seed-fold, recursive spine forks + ogham, faint `{n/k}` only
- **`organic`** — recent Crystal clone with recursive Growth forks

When iterating: **add a new variant** instead of mutating these. Full commit history also lives on the PR branch.

## Demoted (lab-only)
`seed` / `flower` / `metatron` in `SACRED_DEMOTED` — not in `SACRED_FLAT`.

## Seal files
- `IdentitySeal.tsx` — `composePhiSeal`, `composeGrowthSeal`, `composeOrganicSeal`
- `sacred-geometry.ts` — catalog + `SACRED_DEMOTED`
- `archive/` — frozen reference looks
- `method-history.ts` / `MethodHistoryPanel.tsx` — **CUR-2** local revision log + restore-previous chrome (signing = Flint)

## CUR-1 — Living contact-method SEND

### What shipped (UI glass)
- **Revise** on `SovereignIdentityCard` opens `ContactMethodReviseDialog`
- Dialog: edit method value + **shared-with / notify** multi-select (from local book) + **Save locally** + **Send update**
- Trust Map contact sheet **Send update** opens the same dialog with the focused peer preselected
- `sendContactMethodUpdate` stub validates inputs and returns an honest “wire not live” result

### Files
- `ContactMethodReviseDialog.tsx` — revise + audience + send UI
- `contact-method-send.ts` — fleet hook interface + stub
- `local-methods.ts` — local-only Signal/Site drafts (`localStorage`)
- `SovereignIdentityCard.tsx` — revise entry
- Wired from `SoverentityFrontend.tsx` + `app/page.tsx` (Trust Map)

### ⛔ Flint seam (do not implement in UI)
Replace the stub body in `sendContactMethodUpdate` with:
- map kind → allowlisted delta (`emails` today; `phones` already on wire; signal/urls need grow)
- per-peer encrypt (`encryptContactUpdateTo`)
- sign `ContactUpdateEnvelope`
- mailbox / relay deposit

### Assumptions / honesty
- Audience list = “who I choose to notify **this** send,” not a constitutional “who holds my card” ledger (none exists yet)
- **Email** persists via `storeIdentity` on `identity.email`
- **Signal / Site** persist in `local-methods` bag only — **not** in `CONTACT_UPDATE_ALLOWED_FIELDS` yet
- Copy never claims live peer delivery while stub is active

### Questions for fleet
- Confirm default audience = trusted + pubkey (vs all contacts)
- When signal/urls join the allowlist, drop local-only bag

## CUR-2 notes
- Restore = append **new** local revision with prior value; never decrease wire version
- `requestRestorePrevious` returns honest `signing-not-live` until Flint wires sign+deposit
- Demo seed via `seedDemoMethodHistory` on Trust Map sample load (local-only, labeled)
- CUR-1 send should call `appendMethodRevision` when queueing (follow-on wire)
