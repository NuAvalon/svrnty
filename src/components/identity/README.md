## IdentitySeal
**I-6:** seal geometry is derived only from the fingerprint string. Same fingerprint ⇒ same seal. No `Math.random`.

**Two seed axes** (uniform — no preference weights)
1. **Fold** ∈ {3…10} via `FNV(fp) % 8` over `{3,4,5,6,7,8,9,10}` equally
2. **Sacred figure** via `seed % catalog.length` — one of each option per fold (hexagram ★, unicursal, `{n/k}` stars incl. decagram `{10/3}`, **circle / φ circles**, seed of life on 6, triquetra, vesica…)

φ still measures the crystal cascade `R · φ⁻ⁿ` and dendrites. Lab: `/dev/seals`.
