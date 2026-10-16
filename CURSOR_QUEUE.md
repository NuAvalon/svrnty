# svrnty — frontend build queue

Work top-down: the top task first, then the next. Build to spec. Open **ONE PR per task**. Copy/code that makes a security / recovery / trust **CLAIM** needs review before merge — do **not** self-merge crypto/claim surfaces. See `.cursor/rules`.

**Cursor = RENDER-GLASS ONLY** (UI/render). Crypto / keys / PSI / relay-logic / trust-derivation = TEAM (Athena/Flint/Apollo). "You render the glass, the team holds the locks." You CALL the crypto functions and READ the trust derivation named below — you NEVER implement/mutate them. Build items top-down, one PR each.

*Recently completed: Camera QR-scan (#96), Mint-Build Recipe v2 KERI (#112). Over-wire receive note-fix (PR#212) + beta-access (A) (PR#213) MERGED to main — the hooks below are now LIVE.*

---

