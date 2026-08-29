## IdentitySeal
**I-6:** seal geometry is derived only from the fingerprint string. Same fingerprint ⇒ same seal. No `Math.random`.

**Two seed axes** (uniform — no preference weights)
1. **Fold** ∈ {3…9} via `FNV(fp) % 7` over `{3,4,5,6,7,8,9}` equally
2. **Sacred figure** via `seed % catalog.length` — one of each option per fold (hexagram ★, unicursal, `{n/k}` stars, triquetra, vesica…)

φ still measures the crystal cascade `R · φ⁻ⁿ` and dendrites. Lab: `/dev/seals`.
