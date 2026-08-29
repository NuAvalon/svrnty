# IdentitySeal — Cursor UI notes

**Brief:** `CURSOR.md` I-6 · Aesthetic: Solar Ember  
**Invariant:** fingerprint → deterministic geometry. No decorative randomness.

## Production default: `growth`
- Fold (3–10) + φ radial skeleton
- Recursive **spine-guided branches** (gen-1 / gen-2) from fingerprint bits
- **Ogham-ish notches** on spines (1–3 bars, occasional double)
- **Gated arcs** — broken φ-ring segments, outer vesica bulges, gen-1 tip bridges
- **Orbs** — stroke-only tip / fork / core punctuation (not orb fields)
- Optional faint `{n/k}` star accent only — **no named sacred fills**

## Demoted (lab-only)
`seed` / `flower` / `metatron` live in `SACRED_DEMOTED` — path generators remain, but they are **not** in the production flat pool (`SACRED_FLAT`). Named glyphs were overpowering identity.

## Other variants
- `phi` — crystal + formula figures (stars, hexagram, vesica, …) without demoted set
- `lattice` / `ring` / `sigil` / `rosette` — lab A/B

## Lab
`/dev/seals` — compare all variants, ±1 digit sensitivity, growth gallery.

## Files
- `IdentitySeal.tsx` — `composeGrowthSeal`, default `variant='growth'`
- `sacred-geometry.ts` — catalog + `SACRED_DEMOTED`
