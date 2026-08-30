# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout:** `src/lib/trust/trust-map-layout.ts` — organic egocentric lattice (not concentric trust rings). Trust is a visual overlay (filament glow). Camera in `graph-camera.ts`.

## What we changed
- Lattice seed: tag-sector + phyllotaxis, then spacing/cluster gravity. **No inner/outer trust rings.**
- Zoom/pan/pinch via SVG **viewBox camera** (wheel toward cursor, pinch toward midpoint, Fit). CSS-scale zoom is gone.
- Particle wash behind the graph (`TrustMapLatticeField`) — motes are atmosphere, not contacts.
- Browse: organic hulls, trust overlay on nodes, no member-count badges (I-3).
- Click node → seal + **alive contact sheet** (edit, TRUST/remove **behind confirm**, accept pending intro, introduce stub, **Send update → CUR-1 revise dialog**, **CUR-2 version history panel**, multi-select → group).
- **CUR-3:** focus-sheet email / phone / url / handle via I-10a `ContactMethodLink`.
- **CUR-5:** trust / break / remove / block open `TrustActionConfirmDialog`. Blocked contacts filtered off the lattice.
- Sample circle: owner-authored tags → lattice chords (k-NN within tag, not complete graph). Frank = pending intro from Grace.
- Legend: “Every visible line consented — none inferred.”

## Still open (UI)
- Reach-settings / “awaken the circle” — need team visibility contracts.
- Real introduce wire — stubbed locally.
- Wire broadcast for Send update — Flint.

## ⛔ Flint seam (CUR-2)
- Restore/retract = sign next **higher** `ContactUpdateEnvelope.version`.
- Local `svrnty.method-history.v1:*` is UI glass only.

## Questions
1. OK to keep group filaments as owner-authored tag k-NN (current), or should tribes live in a separate store?
2. Should recipient sheet show **peer** revision history or **owner** outbound only (current)?
