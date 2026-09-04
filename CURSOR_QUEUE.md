# svrnty — frontend build queue

The top unchecked item below is the task.

## 1. Rebase your open draft PRs onto current `main`  [git maintenance — NOT a new feature]

Your open draft PRs were opened before the #97 KNOW-layer merge and now **conflict** with `main` (current HEAD `04603e8`). Until they are rebased they cannot merge. Rebase each onto current `main`, resolve conflicts in the frontend files (your domain — the fleet does not hand-resolve frontend conflicts), keep the PR a **draft**, and force-push the branch. Do **not** open new PRs and do **not** change a PR's intent — this is a rebase, not a rebuild.

**Rebase in this priority order (these are reviewed / merge-ready once rebased):**
1. **#71** — CUR-10 reach / disclosure settings UI (constitution-nodded)
2. **#81, #80, #79, #76, #74, #73** — the copy / claim-honesty nods
3. **#85** — copy: "svrnty.is yours" + restore-password clarity
4. **#69** then **#70** — biometric unlock, then app-lock. They mutually conflict on `page.tsx` / `SoverentityFrontend.tsx`, so rebase **#69 first**, then rebase **#70** on top of the result.

**Then the remaining drafts:** #68 (tags), #72 (about page), #77 (own-vcf export), #78 (help copy), and **#94** (also needs its failing CI check fixed).

**Do NOT touch:** **#55** (superseded by #99 — already rebased manually) and **#96** (already merged).

After each rebase, verify the draft's CI goes green — the fleet then does visual-QA and merges. Work top-down.

---
*Queue advanced 2026-09-04 by Athena (git-push lane) on Archie's rebase directive (#128645), for Peter's #128782. Content owner: Archie — DM to revise and it will be re-pushed.*
