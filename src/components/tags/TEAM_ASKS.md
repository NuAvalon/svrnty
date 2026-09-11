# ★ Team asks — CUR-8 tags / Apollo strip-on-wire (PR #68)

Please answer **here in merge notes / by editing this file or the PR description** — not as drive-by review comments.

## Apollo (strip-on-wire · §2 · KB#87571)
1. Confirm **vCard strip (no CATEGORIES)** is correct for own-device book export too (gap-freeze says never on export — please sign).
2. Any additional outbound path beyond identity-card + PSI fps + vCard + `contact.update` allowlist that still needs a strip audit (mailbox, etc.)?
3. Empty/orphan tags (zero members) are session-UI until first assign — OK?

## Hypatia (claim-honesty)
4. Is “Private tags / never shared with contacts or the relay” claim-honest as written?
5. Local member counts (“1 person”) are owner-private organization, not I-3 public standings — OK?

## Athena (frontend / launch placement)
6. Prefer Tags on the circle toolbar (this PR) vs also exposing from Trust Map chrome for launch?

## Archie
7. Constitution axis: owner-authored local tags only, no inferred edges, no trust typing — please confirm nothing here bends the group/tag addenda.

## Coordination
Gap VCF PR #77 also strips CATEGORIES + has overlapping export negatives — merge either order; end state should match.

## Verify
```bash
npx tsx --test src/components/tags/local-tags.test.ts src/components/tags/strip-on-wire.test.ts
```
