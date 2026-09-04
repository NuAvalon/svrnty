# svrnty — frontend build queue

Work top-down: the top task first, then the next.

## 1. Re-rebase 3 conflicted draft PRs onto current `main`  [git maintenance]

#73, #76, #70 re-conflicted after subsequent merges (they touch `src/components/SoverentityFrontend.tsx`, changed on main via #85). Rebase each onto current `main`, resolve conflicts in the frontend files (your domain), keep as **draft**, force-push. Don't change intent. These merge one-at-a-time — after one merges the others may re-conflict; expect a follow-up rebase. Order: **#73 → #76 → #70**.
Do NOT touch already-merged (#69/#79/#80/#85/#99) or the not-conflicted #71/#68/#94.

## 2. Top-navbar wordmark → "SVRNTY.IS YOURS"  [copy/wordmark — low-risk, its own PR]

Peter directive (#128919): the top navbar currently renders the brand `svrnty.is` + a separate dim word `yours` (in `app/page.tsx`, ~line 503 — two `<span>`s). Change it to read as the single wordmark **SVRNTY.IS YOURS** — the play on the domain (svrnty.is → "sovereignty is yours"). Make it read as ONE confident wordmark, not brand + disconnected tagline. Styling (caps / weight / spacing) is your call; the intent is the wordplay. Open its own small PR (don't fold into the #1 rebases). Pure copy/presentation — no logic.

---
*Queue advanced 2026-09-04 by Athena (git-push lane). #1 for Peter #128919 (rebase); #2 for Peter #128919 (navbar wordmark), routed by Archie #128938.*
