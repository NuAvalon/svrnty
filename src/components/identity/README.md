# Identity surfaces — Cursor UI notes

## IdentitySeal
**I-6:** seal geometry is derived only from the fingerprint string (hex nibbles + FNV). Same fingerprint ⇒ same seal. No `Math.random`.

**Default (`variant="phi"`) — crystalline habit:** fold ∈ **{4, 5, 6, 8}** from a **base-10 digit** of FNV(fingerprint) (weighted toward hex). Not literal 10-gons — those look busy. φ still sets `R · φ⁻ⁿ` + dendrite lengths; fingerprint also gates branches/facets.

**Why not “N = digit faces”?** A 7-gon or 10-gon reads as noise next to the lattice. Curating habits keeps snowflake / crystal elegance while seals still *change shape* across identities.

**Lab variants** at **`/dev/seals`:** `phi` (crystal) · `sigil` (old 5-fold) · `rosette` · `lattice` · `ring` · `none`.

## SovereignIdentityCard (Archie mockup → home)
Solar Ember **sovereign identity card** matching Archie's first theme redesign mockup:
- Header: `SOVEREIGN IDENTITY · YOUR CARD`
- Seal + name + `@handle` + grouped fingerprint (`key · aaaa·bbbb·…`)
- Method rows: EMAIL / SIGNAL / SITE with **revise**
- Your circle (egocentric copy + fingerprint-derived mini lattice)
- Badges: local-first · Ed25519 (+ ML-DSA when PQ present)
- Footer: "The card is yours…"

### Files
- `SovereignIdentityCard.tsx` — card UI
- `IdentitySeal.tsx` — deterministic seal
- Wired from `SoverentityFrontend` identity view + `app/page.tsx` (identity default tab, Solar Ember shell / lock)

### Assumptions
- Email comes from `identity.identity.email`.
- Signal / site are optional props; site falls back to claimed slug host when present.
- **Revise** is an L1 living-methods **UI stub** — does not invent broadcast/crypto. Flag for team: wire to living contact-method SEND + versioning when ready.

### Questions (boundary)
- Where should Signal / site live on the self identity record long-term (handles map vs separate fields)? UI will render whatever the team stores; today Signal may be empty until L1 ships.
- Should revise open an inline editor that only mutates local IndexedDB display fields, or must it go through a signed method-update envelope immediately?
