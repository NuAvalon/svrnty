# svrnty Merge Gate — Delegated Merge under Jurisdiction Review

**Git-infra memo §1 (Peter/Fable, 2026-08-17). Merge-mechanic: Athena 🦉 (time-boxed
through 9/10, reviewed each Saturday court — scoped, revocable, logged).**

This is the org layer running on GitHub primitives — we dogfood the governance model on
our own repo before shipping it to anyone. Delegated merge under jurisdiction review =
scoped grants; merge-mechanic = a time-boxed mandate; recorded cross-reviews =
attestations; **deploy = the sovereign's one gate.**

## The two gates

| Gate | Who | Rule |
|------|-----|------|
| **DEPLOY** | **Peter — absolute, unchanged, no exceptions** | Merging to `main` is NOT deploying. Deploy to svrnty.is stays Peter's separate hard gate. |
| **MERGE-TO-MAIN** | Delegated to the merge-mechanic, conditional | A PR may merge WITHOUT Peter when ALL of the three conditions below hold. |

## Merge-to-main: the three conditions (ALL required)

1. **Green.** Existing tests + `next build` pass (the I-suite when it lands supersedes this).
   The merge-mechanic verifies green before merging (CI automates it — see §CI below).
2. **A recorded non-author review** from the governing jurisdiction (see the map). The
   reviewer must not be the author. Recorded via MCP `request_review()` / `complete_review()`.
3. **No protected path touched** (see below). A protected-path PR still needs **Peter-ack**.

If any condition fails → the PR does not merge. Protected-path PRs are flagged to Peter.

## Jurisdiction map (who reviews what)

| Domain | Reviewer | Paths (see CODEOWNERS for the precise globs) |
|--------|----------|----------------------------------------------|
| crypto · envelope · key material | **Flint** | `/src/lib/crypto/**`, `**/sign-envelope*`, `**/*envelope*`, identity/verify |
| formats · protocol objects · frozen rows | **Archie** | `/src/lib/format/**`, `/src/lib/trust/types.ts` |
| UX · ceremony · onboarding · contacts | **Athena** | `/src/lib/ceremony/**`, `/src/lib/contacts/**`, `/src/components/**` |
| docs · canon | **Hypatia** | `*.md`, `/docs/**`, `README.md` |

**If Athena (the merge-mechanic) is the AUTHOR of a UX/contacts PR, the non-author review
comes from Flint or Archie** — the mechanic never reviews their own work. Self-merge of
one's own unreviewed PR is never permitted.

## Protected paths (Peter-ack still required — the gate cannot self-weaken)

- `/src/lib/crypto/**` and any crypto/key-material (Flint's review + Peter-ack = double-gated).
- Any **format-frozen** file (`/src/lib/format/**`, `/src/lib/trust/types.ts`).
- **Relay custody logic** (`/src/lib/sync/relay.ts`).
- **CI / branch-protection config itself** (`/.github/**`, `/CODEOWNERS`, this file).
- Anything **beyond Tier-0** (memo §8): recovery ceremony/Shamir, grants/delegation, orgs,
  PSI discovery, DHT, `did:svrnty:` syntax, self-hosted slugs, native shell, duress path,
  one-shot at-rest re-encrypt.

## Promoting / demoting a protected path (Peter, #115873, 2026-08-17)

Protection is a **one-way ratchet by default**:

- **Promote (add a path) — any agent, no ack.** Any agent may add a file to the protected list by
  flagging it here (or in `CODEOWNERS`) with **one sentence of reasoning**. Tightening the gate is
  always safe, so it needs no Peter-ack — the reasoning simply lands in this file's history (the record).
- **Demote (remove a path) — Peter-ack required.** Removing a path — loosening the gate — is the only
  direction that can weaken it, so it needs Peter's explicit ack. The gate cannot self-weaken from inside.

Every protected entry carries its one-sentence reasoning inline, so the record shows *why* each path is gated.

## Enforcement — how it actually works right now

⚠️ **GitHub-native branch protection is NOT yet in place.** The push credential
(palberts22) has `push`+`triage` but **NOT `admin`** on `NuAvalon/svrnty`, so an agent
cannot configure branch protection — only the org owner can. Until then:

- **Review gate** = MCP `request_review()` + merge-mechanic discipline (NOT GitHub, because
  all agents push under one identity — GitHub can't tell a non-author review from a self-review).
- **Green gate** = merge-mechanic runs build + tests before merging (CI below makes it visible).
- **Protected-path gate** = merge-mechanic flags to Peter; Peter-ack precedes merge.

**To harden to GitHub-enforced** (org owner action): grant palberts22 (or a bot) `admin`,
then set branch protection on `main` → require the `ci` status check + 1 review + no
force-push. Exact call once admin exists:
```
gh api -X PUT repos/NuAvalon/svrnty/branches/main/protection \
  -f 'required_status_checks[strict]=true' -f 'required_status_checks[checks][][context]=ci' \
  -F 'enforce_admins=false' -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'restrictions=null'
```

## Merge-mechanic daily runbook (Athena)

1. `gh pr list --repo NuAvalon/svrnty --state open` — the queue.
2. For each PR, in dependency order (stacked PRs merge base-first):
   a. **Classify**: which jurisdiction? Does it touch a protected path?
   b. **Green**: fetch the branch, run its tests (tsc→CJS) + `next build`. Red → back to author.
   c. **Review**: is there a recorded non-author review from the right jurisdiction? If not,
      `request_review()` to the jurisdiction reviewer; wait for `complete_review()`.
   d. **Protected path** → flag to Peter, wait for ack. Otherwise, and if a+b+c pass → merge.
   e. **Merge**: `gh pr merge <n> --squash` (or ff), then `git worktree remove` the stale lane.
3. Log the merge (who reviewed, green evidence, protected-path acks) — attestations, not vibes.
4. Never `--no-verify`. Never force-push. Deploy is never part of a merge.

## CI (status check)

`.github/workflows/ci.yml` runs `next build` + typecheck on every PR to `main` — the
machine-checkable half of condition 1. The cross-file **divergence-guard** (verify-allowlist
≡ apply-allowlist, the lockstep pattern) joins CI once both allowlist files land on `main`
(via the current drain). See `shared/outbox/*/lockstep_divergence_guard_pattern.md`.

---
*Merge-mechanic mandate accepted by Athena 2026-08-17. Reviewed at Saturday court.
Deploy stays Peter's. This gate is Tier-0-adjacent infrastructure, not scope expansion.*
