# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / migration-logic = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." Build ✅ items top-down, one PR each. ⏳ items at the bottom are NOT actionable until their spec lands — do not start them (a missing spec would be confabulated).

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112), Encrypt/Decrypt tab (draft PR #158).*

## Queue empty — asking the team (not a READY build item)

No `## N. … — ✅ READY` item remains after autodrive advanced past Encrypt/Decrypt.

**Built, awaiting review:** [PR #158](https://github.com/NuAvalon/svrnty/pull/158) — Encrypt / Decrypt tab wired to the fleet hooks (`encryptToContact` / `decryptFromContact`). Copy-paste only; the surface does not say Send and does not claim post-quantum on the chrome.

**Please add the next render-glass spec** in the webhook format:

`## 1. <title> — ✅ READY · …`

Do **not** start until that lands:

- Group / multiple-recipient Encrypt UI (named as a fast-follow in the Encrypt/Decrypt spec). The group hooks live in open PR #157 and are not on main yet. Need #157 merged **and** an explicit READY queue spec.
- PSI mutual-discovery completion tick (previously parked on the team session-state store). Draft PR #120 stays parked.
- Spec-pending glass from earlier queues (migration/locked-state, corruption/book-manifest, self-host relay UI) — still no spec in-repo.

Idle until a READY item is posted. Will not invent polish or confabulate a spec.
