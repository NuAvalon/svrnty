# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout:** `src/lib/trust/trust-map-layout.ts` — particle lattice + mutual-bond springs (not concentric trust rings). Camera: `graph-camera.ts` / `use-graph-viewport.ts` (wheel, pinch, pan, fullscreen). Pull-to-refresh consumes the living mailbox then re-reads the book.

## What we changed
- Retinted SVG tokens to Solar Ember (CSS vars → light/dark).
- Click node → seal + **alive contact sheet** (edit, TRUST/remove **behind confirm**, accept pending intro, introduce stub, **Send update → CUR-1 revise dialog**, **CUR-2 version history panel**, multi-select → group).
- **CUR-3:** focus-sheet email / phone / url / handle are tap-to-open via I-10a allowlisted `ContactMethodLink` (see `src/components/contacts/README.md`).
- **CUR-5:** trust / break / remove / block open `TrustActionConfirmDialog` (Solar Ember). Blocked contacts are filtered off the lattice (local owner flag).
- Sample circle (`sample-circle.ts`): mutual trust self↔Ada/Grace/Margaret; owner-authored tags (`core`, `builders`, `radio`, …) → **cluster chords + centroid pull**; Frank = pending intro from Grace (pending ≠ trust).
- Known vs trusted visuals sharpened (hollow dashed known · lit fill + halo trusted · double-glow mutual · pulsing dashed pending).
- Intro UI creates a local pending contact for demo; dual-accept protocol is team-owned.
- **CUR-2:** `MethodHistoryPanel` — local method-revision log + one-tap **Restore previous** (appends a new local draft; signing stubbed).

## Still open (UI)
- Reach-settings / “awaken the circle” — need team visibility contracts.
- Real introduce wire (pending both sides until accept) — stubbed locally.
- Wire broadcast for Send update — Flint (`identity/contact-method-send.ts` stub).

## ⛔ Flint seam (CUR-2)
- Restore/retract = sign next **higher** `ContactUpdateEnvelope.version` with prior field values + per-peer encrypt + deposit.
- Never roll wire version backward (receivers reject `stale-version`).
- Local `svrnty.method-history.v1:*` is UI glass only — not the wire ledger.

## Questions
1. OK to keep group chords as owner-authored tag edges (current), or should tribes live in a separate store before we draw them?
2. Should pending intros sit outside the known ring until accepted, or stay on the rim (current)?
3. Should recipient sheet show **peer** revision history (applied deltas) or **owner** outbound correct/retract only (current)?
