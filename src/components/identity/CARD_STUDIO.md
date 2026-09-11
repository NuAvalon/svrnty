# Card studio + lenses (queue #1)

**Render-glass only.** No crypto, no `visible()`, no signed-card schema, no `routing.update` implementation.

## What shipped
- **Custom typed fields** on the owner card (text / link / date / phone / email) — additive on the local `OwnerCardBag`, riding ContactRecord’s open index-sig when a received card is annotated. Soft cap 16 KB; `data:` / `javascript:` values refused (avatars referenced, not inlined).
- **Card studio preview** — name + selected lens methods + per-method relay host. Recognition aid only; seal is recomputed from fingerprint.
- **Receiver-local annotations** — alias + notes in top-level `owner_local` on the stored contact. Survive `applyVerifiedContactUpdate` (allowlist does not touch that field). Tags stay `metadata.tags`.
- **Per-method relay field** + **Use this relay** control — saves a host on this device; calls `registerTeamMethodRelayMove` when the fleet wires `routing.update`. Unwired: honest “saved on this device; delivery still uses the current relay.”
- **Default-lens picker at Grow** — choose the face you mean to hand them. Does **not** change the signed invite (identity-card-sign is CODEOWNERS). Extra methods stay local until the living card schema carries them.

## Files
| File | Role |
|------|------|
| `src/components/identity/owner-card.ts` | Bag + persist + cap + default lens |
| `src/components/identity/OwnerCardStudio.tsx` | Compose UI |
| `src/components/identity/OwnerCardPreview.tsx` | Preview |
| `src/components/GrowSheet.tsx` | Grow lens picker |
| `src/lib/contacts/method-relay.ts` | Host normalize + team seam |
| `src/lib/contacts/owner-local-annotations.ts` | Alias/notes + export strip |
| `src/components/contacts/ContactDetailDialog.tsx` | Receiver annotation glass |

## Boundary
- Did **not** touch CODEOWNERS paths (`src/lib/crypto`, `src/lib/identity`, `src/lib/sync/vault.ts`, `src/lib/trust`).
- `owner_local` rides Athena’s enc-b blob via existing `updateContact` (open bag).
- Lens is consent-by-inclusion *intent*. The signed Grow payload is still the fleet identity card.

## Ask the fleet
1. Wire `registerTeamMethodRelayMove` to `routing.update` when that object type lands — the glass control is ready.
2. Add `owner_local` to `stripOwnerLocalForPublish` (glass already strips it; fleet strip does not know the key yet).
3. Living-card schema: extra methods / lens projection on the signed invite (today they stay on-device; copy says so).

## Verify
```bash
npx tsx --test src/components/identity/owner-card.test.ts
npx tsx --test src/lib/contacts/method-relay.test.ts
npx tsx --test src/lib/contacts/owner-local-annotations.test.ts
```
