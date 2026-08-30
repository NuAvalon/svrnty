# TrustMap (L2) — Cursor UI notes

**Brief:** `CURSOR.md` L2 · Aesthetic: Solar Ember  
**Layout:** egocentric particle **galaxy** (canvas). Trust is glow. Camera is viewBox-space pan/zoom.

## How 2,000 friends display (Cathedral-inspired, not Facebook lists)

Everyone on the lattice is already in **your** book — presence here is not inferred.

1. **Zoomed out** — points of light. Labels only when close, searched, or lamped.
2. **Lamp a person** (click) — volumetric beams to their **constellation**:
   - **Groups you named** (owner tags)
   - **Circle they showed you** (`disclosed_circle` / exchange `mutual_contacts`) — fleet `visible()` ∩ book
   - **They trust too** (`they_trust` / `peer_mutual`) — fleet PSI, not transitive invention
3. **Trust overlay** — ember fill on people *you* trusted; known stay hollow. The “20 you trust of those 85” is the glow on the lamped set, not a score.
4. **Search** finds a person in a dense book.

We did **not** port Three.js. The Cathedral 3D universe is a global knowledge graph; svrnty’s graph is **egocentric + your book**. 2D canvas + camera is the particle-lattice CURSOR.md asks for. Tilt/3D is a later aesthetic pass if Peter wants it — not a new data model.

### What we will not draw
- Peer↔peer bonds that nobody disclosed (the “your trusted friend also trusts 10” **only** lights when PSI/`they_trust` is present).
- Mutual-friend **counts** on identity (I-3).
- Why a line is absent (deniability).

## Classical vCard
Add-a-field editor on classical contacts (phone, email, link, address, org, title, nickname, birthday, handle, custom). Export omits trust dumps so a round-trip `.vcf` stays a phone book.

## Boundary
No crypto / `visible()` / relay. `disclosed_circle` and `they_trust` are read-only fleet fields.
