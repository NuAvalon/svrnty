# IdentitySeal archive — frozen A/B looks

**Do not overwrite.** When experimenting, add a *new* `SealVariant` + new archive files. These three stay as reference.

| Variant | Compose | Meaning |
|---------|---------|---------|
| **Crystal** (`phi`) | `composePhiSeal` | Production default · sacred figure + φ droplets + ogham |
| **Growth** | `composeGrowthSeal` | Post-Metatron original (`21d858c`) · seed-fold, spine forks + ogham, no named glyphs |
| **Organic** | `composeOrganicSeal` | Recent Crystal clone with recursive Growth forks (`4103523`) |

## Contents
- `screenshots/` — `/dev/seals` A/B captures (5 / 7 / 10-fold)
- `svg/` — deterministic SVG renders for the same sample fingerprints
- `fixtures/*.json` — fold / figure / counts for regression
- `manifest.json` — index of frozen samples
- `freeze-seals.ts` — regenerate SVG + fixtures (`node --import tsx …/freeze-seals.ts`)

## Regenerate
```bash
node --import tsx src/components/identity/archive/freeze-seals.ts
```
Only re-run when intentionally updating the freeze (and say so in the commit). Prefer adding `archive/v2/` over mutating these files in place.
