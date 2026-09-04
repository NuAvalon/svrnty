# Own-identity vCard export

**Render-glass only.** No crypto, no gate, no relay.

| File | Role |
|------|------|
| `own-vcard.ts` | `toOwnVCard` / `downloadOwnVCard` — owner's name + methods → `.vcf` |
| `own-vcard.test.ts` | Shape tests + **negative** strip of tags/blocked/keys |
| `SovereignIdentityCard.tsx` | **Save contact card (.vcf)** button |

Book multi-contact export (`vcard.ts`) is unchanged here — #82 already strips tags / fingerprint / trust from the phone-book path.

## Invariants
- Device-local tags / blocked / group-labels never appear on this export (Apollo §2 / KB#87571)
- Own `.vcf` carries user-authored methods only — fingerprint as UID/NOTE recognition aid, not a verification claim
- Site URLs are http(s) only (no `javascript:` / `data:`)

## Verify
```bash
npx tsx --test src/lib/contacts/own-vcard.test.ts
```
