# Frozen formula source

Plain-text snapshots of the compose grammars at freeze time (`ff1dfed`).

| File | Variant |
|------|---------|
| `composePhiSeal.ts.txt` | Crystal (`phi`) |
| `composeGrowthSeal.ts.txt` | Growth (post-Metatron) |
| `composeOrganicSeal.ts.txt` | Organic (Crystal clone + forks) |
| `sacred-geometry.ts.txt` | Catalog + figure path builders |

**Do not edit these to change live seals.** Edit `IdentitySeal.tsx` / `sacred-geometry.ts` instead. If you intentionally replace a frozen look, add `archive/v2/` rather than mutating these files.

Regenerate snapshots:
```bash
node --import tsx src/components/identity/archive/freeze-source.ts
```
