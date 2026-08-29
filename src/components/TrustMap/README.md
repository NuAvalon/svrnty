# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout/crypto:** `src/lib/trust/trust-map-layout.ts` — **do not modify** (team-owned invariants + tests).

## What we changed
- Retinted SVG tokens to Solar Ember (warm ember field, gold edges, sacral orange lit nodes).
- Left layout/provenance logic untouched (egocentric, no peer↔peer inference, I-6).

## Still open (UI)
- Particle-lattice canvas (drifting nodes, accent lines when dist &lt; ~130) — next pass; current SVG layout already egocentric and mobile-safe.
- Click-node → richer glyph via `IdentitySeal` + contact sheet.
- Reach-settings / “awaken the circle” toggles — need team visibility contracts before UI.

## Questions
1. OK to evolve toward canvas particle-lattice *using the same* `computeTrustLayout` positions (render-only), or keep SVG?
2. Where should per-edge reach settings live in the data model before we draw toggles?
