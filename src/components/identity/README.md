# IdentitySeal — Cursor UI notes

**I-6:** seal geometry is derived only from the fingerprint string (hex nibbles + FNV). Same fingerprint ⇒ same seal. No `Math.random`.

Used on soul-seed reveal; safe to reuse on TrustMap node click / contact detail.
