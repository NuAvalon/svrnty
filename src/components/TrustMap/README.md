# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout/crypto:** `src/lib/trust/trust-map-layout.ts` — **do not modify** (team-owned invariants + tests). Clustering / group chords are render-only in this component.

## What we changed
- Retinted SVG tokens to Solar Ember (CSS vars → light/dark).
- Click node → seal + **alive contact sheet** (edit, TRUST/remove **behind confirm**, accept pending intro, introduce stub, send-update stub, version-history WIP note, multi-select → group).
- **CUR-5:** trust / break / remove / block open `TrustActionConfirmDialog` (Solar Ember). Blocked contacts are filtered off the lattice (local owner flag).
- Sample circle (`sample-circle.ts`): mutual trust self↔Ada/Grace/Margaret; owner-authored tags (`core`, `builders`, `radio`, …) → **cluster chords + centroid pull**; Frank = pending intro from Grace (pending ≠ trust).
- Known vs trusted visuals sharpened (hollow dashed known · lit fill + halo trusted · double-glow mutual · pulsing dashed pending).
- Intro UI creates a local pending contact for demo; dual-accept protocol is team-owned.

## Still open (UI)
- Particle-lattice canvas (dist &lt; ~130 accent lines) — next pass.
- Reach-settings / “awaken the circle” — need team visibility contracts.
- Version history surface (L1) — placeholder only.
- Real introduce wire (pending both sides until accept) — stubbed locally.

## Questions
1. OK to keep group chords as owner-authored tag edges (current), or should tribes live in a separate store before we draw them?
2. Should pending intros sit outside the known ring until accepted, or stay on the rim (current)?
