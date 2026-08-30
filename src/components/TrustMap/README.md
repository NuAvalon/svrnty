# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout:** egocentric particle **galaxy** (canvas). Trust is glow. Camera is viewBox-space pan/zoom.

## How 2,000 friends display (Cathedral-inspired, not Facebook lists)

Everyone on the lattice is already in **your** book — presence here is not inferred.

1. **Zoomed out** — points of light. Labels only when close, searched, or lamped.
2. **Lamp a person** (click) — volumetric beams to their **constellation**:
   - **Groups you named** (owner tags) — dashed gold
   - **Circle they showed you** (`disclosed_circle` / exchange `mutual_contacts`) — fleet `visible()` ∩ book
   - **Open-visibility peer trust** (`they_trust` / `peer_mutual`) — Peter's spec below
3. **Trust overlay** — ember fill on people *you* trusted; known stay hollow. The “20 you trust of those 85” is the glow on the lamped set, not a score.
4. **Search** finds a person in a dense book.

### Open-visibility peer trust (Peter's spec)

If you trust Sally and Joe, they trust you, and **all three** have open visibility for trusted contacts, you see that they trust each other — and they see that you trust them. That is **consented PSI disclosure**, not an inferred bond.

The glass draws those ember filaments only when:

- both contacts are **trusted + reciprocal** with you
- you opened visibility toward **both** (per-peer `open_visibility` — there is no book-global flag)
- each already lists the other in fleet `they_trust` / `peer_mutual` (or the demo stand-in)

Fail closed if any piece is missing. **Owner tags never create a peer chord.** The fleet owns PSI / `visible()`; we only render what landed on the edge.

We did **not** port Three.js. The Cathedral 3D universe is a global knowledge graph; svrnty’s graph is **egocentric + your book**. 2D canvas + camera is the particle-lattice CURSOR.md asks for. Tilt/3D is a later aesthetic pass if Peter wants it — not a new data model.

### Labels at density (LOD)
- Screen-space names (fixed ~12px), not world-scaled stickers.
- Far zoom: force-only (lamp / hover / search). Mid: trusted + collision-capped. Near: denser neighborhood labels.
- Corner **nameplate** always shows who you’re hovering or lamped.
- Search → Enter/Go flies the camera and pulses the match.

### What we will not draw
- Peer↔peer bonds from co-membership, “we both know them,” or friends-of-friends.
- Mutual-friend **counts** on identity (I-3).
- Why a line is absent (deniability).

## Classical vCard
Add-a-field editor on classical contacts (phone, email, link, address, org, title, nickname, birthday, handle, custom). Export omits trust dumps so a round-trip `.vcf` stays a phone book.

## Boundary
No crypto / `visible()` / relay. `disclosed_circle` and `they_trust` are read-only fleet fields.
