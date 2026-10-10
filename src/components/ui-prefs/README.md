# UI prefs

**Appearance (light / dark)** — Solar Ember stays the brand; light is a daylight parchment
variant of the same gold/orange system, not a separate theme.

## Files
- `AppearanceProvider.tsx` — reads/writes `localStorage` key `svrnty.ui`
- `AppearanceToggle.tsx` — header control
- Tokens: `src/components/recovery/solar-ember.ts` (CSS vars) + `app/globals.css`

## Storage shape
```json
{ "appearance": "dark" | "light" }
```
Extensible later (accent, density, motion) without a new key — grow `UiPrefs`.

## Assumptions
- Default remains **dark** (CURSOR.md Solar Ember).
- Components that still hardcode hex colors will lag until migrated to `solarEmber` / CSS vars.
- No `next-themes` dependency — FOUC avoided with a tiny inline boot script in `layout.tsx`.
