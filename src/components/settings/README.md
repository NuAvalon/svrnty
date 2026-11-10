# Settings → Relay

Glass for Flint's relay-field spec. Cursor renders; the fleet owns the locks.

## What the tab shows
- Current relay URL (`You're on: {url}`).
- What a relay can see.
- That moving to another relay isn't available in the app yet.

## What it doesn't show, until Switch is wired
The Relay URL field, the `GET {url}/health` check, the Switch button and its confirm dialog are off the tab. The page's `connect-src 'self'` refuses a check of any other origin, so every typed URL would have read "can't reach", and a typed URL also sends the person's IP to that host. `relay-health.ts` and `relay-migrate-seam.ts` stay in the tree, unmounted. Bringing Switch back needs a decision on how a person-chosen origin gets past the policy.

## Seams Switch needs (not built here)
1. **Config override** — `src/components/settings/relay-preference.ts` persists the chosen URL after a *completed* migrate. Wire `currentRelayUrl()` into every `/api/relay` fetch (`relayBase`).
2. **Card re-sign** with the new relay hint.
3. **`migrateRelay`** (`#236`) — register via `registerRelayMigrate(fn)` in `relay-migrate-seam.ts`, then flip `isRelayMigrateLive()` + its claim-gates test.

## Health
Full satellite: `200` + `{ service: "satellite", mode: "full" }`.
`service: "registration"` or `mode: "registry"` → registration-only.
CORS failures read as can't reach (the PWA must see the JSON). So does a refusal by the page's policy.
