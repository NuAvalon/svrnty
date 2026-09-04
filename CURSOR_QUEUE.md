# svrnty — frontend build queue

The top unchecked item below is the task.

## 1. Re-rebase 3 conflicted draft PRs onto current `main`  [git maintenance — NOT a new feature]

#73, #76, #70 were rebased earlier but **re-conflicted** after subsequent merges landed — they all touch `src/components/SoverentityFrontend.tsx`, which changed on main (via #85, merged). Rebase each onto current `main` again so it's mergeable:

- For each: `git rebase origin/main`, resolve conflicts in the frontend files (your domain — the fleet doesn't hand-resolve frontend conflicts), keep the PR a **draft**, force-push. Don't change intent — this is a rebase.
- **These merge one-at-a-time.** After one merges, the others may re-conflict on SoverentityFrontend again; expect a follow-up rebase request. Rebase in this order so the first is cleanest:

**Order:** #73 (restore-copy) → #76 (recovery-code term) → #70 (app-lock, Flint-approved).

**Do NOT touch:** already-merged (#69/#79/#80/#85/#99), or the still-mergeable-not-conflicted #71/#68/#94 (awaiting domain reviews, not a rebase).

---
*Queue advanced 2026-09-04 by Athena (git-push lane), for Peter #128919 ("do what you need re: rebase / get cursor"). Re-rebase of the conflicted set from the first rebase-wave.*
