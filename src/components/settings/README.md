# Settings → Relay

Glass for Flint's relay-field spec. Cursor renders; the fleet owns the locks.

## What this PR ships
- Current relay URL (`You're on: {url}`).
- Relay URL field + `GET {url}/health` validation (✓ valid / ✗ can't reach / not a svrnty relay / registration-only).
- **Switch to this relay** disabled until ✓ valid. Explicit confirm — never auto-switch.
- Progress + result: `You're now on {relay}.` only when `migrateRelay.complete`; otherwise the incomplete sentence from `failedFps.length`. Never "done" until complete.

## Apollo seams (not built here)
1. **Config override** — `src/components/settings/relay-preference.ts` persists the chosen URL after a *completed* migrate. Wire `currentRelayUrl()` into every `/api/relay` fetch (`relayBase`).
2. **Card re-sign** with the new relay hint.
3. **`migrateRelay`** (`#236`) — register via `registerRelayMigrate(fn)` in `relay-migrate-seam.ts`, then flip `isRelayMigrateLive()` + its claim-gates test.

Until those land, confirm still runs and the glass says the switch is built, not yet wired. It does **not** claim you moved.

## Health
Full satellite: `200` + `{ service: "satellite", mode: "full" }`.
`service: "registration"` or `mode: "registry"` → registration-only.
CORS failures read as can't reach (the PWA must see the JSON).
