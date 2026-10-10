# Two-sided book chrome — Trust/Known alignment

**When:** 2026-08-30 gap cron · **Boundary:** presentational only (no gate / crypto / wire)

## What changed
After CUR-5 (#67), the confirm button says **Trust** / **Untrust**, but the living address book still said **Vouch**. That mismatch sends users hunting for a button that isn't there.

| Surface | Before | After |
|---------|--------|--------|
| Living subtitle / empty CTA | Vouch… | **Trust** someone… |
| `CONTACT_STATE_META` hints | “not yet vouched” / “Vouched and…” | **Trusted** / Known language |
| Identity card circle blurb | “who they vouch for” | “who they trust” |
| Bloom glow | always timed | skipped under `prefers-reduced-motion: reduce` |

Protocol / signal type remains fleet `vouch` — untouched. This is UI vocabulary only.

## Verify
```bash
npx tsx --test src/lib/trust/contact-state.test.ts
```

## Team asks (answer in the PR body — not review comments)
See the PR description: Hypatia claim-honesty on Trusted vs Vouch chrome, plus the standing gap-unblock table for green drafts #68–#79.
