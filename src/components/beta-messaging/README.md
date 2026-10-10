# Beta-messaging copy (gate-ON redeem)

Render-glass for CURSOR_QUEUE item 1: **Beta-messaging UI copy**. BETA surface only — the public README is unchanged.

## What this is
- **Unlock/redeem** mounts **only** when `isBetaIssuerProvisioned()` is true (`NEXT_PUBLIC_SVRNTY_BETA_GATE=1` or `true`). Unset = dogfood gap = no redeem chrome.
- Redeem **calls** fleet `signMailboxClaimRequest` + `deriveMailboxId`, then `POST /api/relay/claim`. Token verify / claim-registry stay in `src/lib/relay/` (untouched).
- After a 200 `{ status: "claimed" }`, a **device-local** flag is stored (`localStorage`, keyed by fingerprint). It is not a publish / PSI / export field.
- Post-redeem chrome is the queue what-it-is / sending / receiving copy. This PR does **not** rebuild the over-wire inbox (draft PR #217).

## Copy (queue-verbatim)
Unlock: **Turn on beta messaging** / Redeem key / “one key per book.”
What it is: **Encrypted messages, with the people you trust** (queue paragraph, including “end-to-end encrypted”).
Sending: **Sent** is the floor; Delivered is named only as coming.
Receiving: saved / there when you open — never “appears live.”

## Files
- `beta-messaging-copy.ts` — fixed strings
- `is-beta-gate-on.ts` — public gate flag
- `beta-redeem.ts` — thin claim wrapper
- `BetaMessagingTab.tsx` — Solar Ember glass
- `beta-claimed-local.ts` — device-local claimed bit

## Not touched
CODEOWNERS paths (`src/lib/crypto`, `identity`, `trust`, `sync`, `relay` internals, `messaging`, vault). Claim-gates. CI workflows. README.md. Restore-gate control flow.

## Ask
1. Hypatia — the queue paragraph says “end-to-end encrypted” and “the relay … never learns who you talk to.” Substrate is classical OpenPGP seal + dumb-mailbox blob (`isPQEncapLive()` / `isPQSignLive()` still false). Copied verbatim; please confirm or substitute.
2. Athena — pair `NEXT_PUBLIC_SVRNTY_BETA_GATE=1` with the server issuer pin. Glass cannot read `SVRNTY_BETA_ISSUER_*` (those must stay server-only).
3. Compose with draft **PR #217** (send/inbox): when both merge, redeem should front the inbox while gate-ON and this book is unclaimed.
