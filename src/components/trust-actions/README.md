# Trust actions (CUR-5 / L3) — Cursor UI notes

**Queue:** `CURSOR_QUEUE.md` CUR-5 · **Aesthetic:** Solar Ember  
**Seam owners:** Flint / Athena (relay-auth · vouch/break/block wire) · Hypatia (claim-honesty on confirm copy)

## What we built
Confirm flows for **trust / break (untrust) / remove / block / unblock** — no more one-click destructive toggles on Trust Map or Contacts detail.

| File | Role |
|------|------|
| `trust-actions.ts` | Copy + local patch builder + `applyTrustAction` (wire = `stub-not-live`) |
| `TrustActionConfirmDialog.tsx` | Solar Ember modal glass |
| `trust-actions.test.ts` | Copy + apply unit tests |

## Behavior
- **Trust** — local `trusted: true` after confirm. Binary only (no score/rank in copy).
- **Break** — local drop to known; optional **local-only** reason (not auto-shared).
- **Remove** — local `removeContact` after confirm.
- **Block** — local `blocked` flag (+ clears vouch). Hidden from Trust Map; listed under Contacts → Blocked. **Relay stays blind** — not a server ban.
- **Unblock** — clears local flag; returns as known.

## Hard boundary
- Does **not** call `createSignal` / `vouchSignal` / `breakSignal` or invent block mute on the relay.
- Does **not** touch `visible()` / PSI / crypto.
- Blind `/api/trust/commit|revoke` from Contacts detail left as-is (pre-existing); Trust Map path uses the same local update as before, now behind confirm.

## Assumptions
1. `blocked` is an **owner-local** flag (like tags) — strip on any publish/sync wire (Apollo).
2. Block implies break on this device (no trusted+blocked half-state).
3. Confirm copy is draft-honest until Hypatia signs.

## Questions for the team (answer in PR / merge notes)
1. **@Flint — wire notify:** After local trust/break, should UI call fleet `createSignal(vouch|break)` + mailbox deposit, or keep confirm local-only until a dedicated send seam exists?
2. **@Flint / @Athena — block mute:** Is local hide enough for launch, or do we need a relay-auth “drop envelopes from fp” that stays blind to graph shape?
3. **@Apollo — strip-on-wire:** Confirm `blocked` (and break reason) never leave the device on publish/sync — same law as tags?
4. **@Hypatia — claim-honesty:** Review confirm bodies (esp. “not sent from this confirm yet” / “relay stays blind”). Too hedged or correct?
5. **@Peter — block vs remove:** Should Block be available from Trust Map sheet (current) and Contacts, or Contacts-only?

## Verify
- Unit: `npx tsx --test src/components/trust-actions/trust-actions.test.ts`
- Manual: Trust Map → node → TRUST / Remove trust / Block / Remove → confirm → cancel works; confirm applies.
- Manual: Contacts → detail → same confirms; Blocked tab → Unblock.
