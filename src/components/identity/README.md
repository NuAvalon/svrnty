## IdentitySeal
**I-6:** seal geometry is derived only from the fingerprint string. Same fingerprint ⇒ same seal. No `Math.random`.

**Flat sacred pool** (equal odds — no preference weights)
- Every `(fold, figure)` catalog entry is equally likely via `pickSacredEntry`.
- Fold ∈ {3…10} comes with the figure.
- Crystal spines / φ cascade / dendrites follow the chosen fold.

**Catalog — formula figures, not hand-drawn glyphs**
- `{n/k}` star polygons (pentagram, heptagram, nonagram, decagram…) — continuous stroke when `gcd(n,k)=1`
- Compound figures when `gcd>1` (hexagram ★ = `{6/2}`, `{8/2}`, `{9/3}`, `{10/4}`…)
- Flower of life, Metatron’s cube, seed of life — light accents
- Circle / φ-nested circles, vesica, triquetra, diamond
- **No Crowley unicursal** — dropped; fold-6 still has a star via compound hexagram ★. Spines/branches already vary line count and angles from the fingerprint.

**Orientation:** spine / vertex 0 is always at the top (canonical). There is no free whole-seal
rotation axis — two fingerprints cannot be the same crystal merely spun (including `360°/fold`
symmetry twins). Catalog “rotated …” figures are intentional π-flips of the sacred overlay, not
spins of the whole seal.

φ measures the crystal cascade `R · φ⁻ⁿ` and dendrites. Lab: `/dev/seals`.

Peers see a seal only after a contact is added — geometry is regenerated from their
fingerprint locally (I-6). No image export; the seal is not a transport or QR substitute.

**Render:** stroke-only wire (no opaque fills) so the seal sits cleanly on light or dark
backgrounds — lines over whatever is behind it.
