# Reach settings (CUR-10) — render-glass

**Queue:** `CURSOR_QUEUE.md` CUR-10 · **Seam owner:** Apollo (`visible()` / `reach()` · KB#87355 UI-half)  
**Aesthetic:** Solar Ember · **Hard boundary:** UI chrome ONLY — never implement gate-logic, never filter the Trust Map by these prefs, never fetch-then-hide.

## What shipped
- **Disclosure reach** panel on Trust Map (toggle above the lattice)
  - **Awaken the circle** — global opt-in (default **Off**)
  - **Default bond reach** — Private / Trusted (L1) / Circle (L2)
- **Per-bond override** on the contact sheet (`BondReachControl`) — inherit or set a level; glass **narrows** any attempt to widen past default
- Prefs: `localStorage` key `svrnty.reach-settings` — **consent intent only**
- Apollo seam stub: `commitReachIntent` → local write + `stub-not-live` until fleet `setOwnerReachPolicy` lands
- Unit tests for parse / narrow-only / effective reach / claim-honest status copy

## Hard boundary held
- Does **not** call or invent `visible()` / `reach()`
- Does **not** hide Trust Map edges based on prefs (owner's egocentric view stays authored edges)
- Does **not** claim disclosure is live — panel says enforcement is fleet-owned / stub until wired
- Consent guarantee copy preserved: “Every visible line consented — none inferred.”

## Files
| File | Role |
|------|------|
| `reach-prefs.ts` | Prefs parse/read/write + narrow-only helpers + status copy |
| `reach-prefs.test.ts` | Unit tests |
| `apollo-reach-seam.ts` | Stub commit → fleet policy shape |
| `ReachSettingsPanel.tsx` | Global awaken + default reach chrome |
| `BondReachControl.tsx` | Per-bond override on contact sheet |
| Wired from `TrustMap.tsx` | Toggle + sheet control |

## Composition (authoring — gate must enforce)
1. Awaken **Off** → effective reach = private for every bond
2. Awaken **On** → defaultReach, unless per-edge override
3. Per-edge may only **narrow** vs default (never widen)
4. Global-on never overrides a finer per-edge restriction

## Assumptions
- Defaults are privacy-first (asleep + private) so demos don't surprise-disclose
- Prefs are **device-local** (same as appearance / app-lock). If Apollo wants per-fingerprint vaulted policy, say so — glass can key by fingerprint without inventing publish
- Per-group narrow-only ACL (CURSOR L6) **not** in this PR — tags remain local labels; group ACL ships when Apollo + CUR-8 converge
- KB#87355 was not readable in-repo — UI half inferred from CURSOR.md + queue; **please confirm labels / enum names**

## Questions for the fleet (answer in this PR description / merge notes — not as review comments)

**Apollo (disclosure-reach — seam owner)**
1. Confirm Private / L1 / L2 labels + enum names match KB#87355 (`private`/`l1`/`l2` OK, or different wire tokens)?
2. Confirm `setOwnerReachPolicy({ awakenCircle, defaultReach, edgeReach })` is the right glass→fleet call — or name the real hook?
3. Until the gate is live, is “prefs saved as consent intent / enforcement not live” the honest UX, or should awaken be disabled entirely?
4. Per-group narrow-only ACL: defer to a follow-on after CUR-8, or stub chrome now?

**Hypatia (claim-honesty)**
5. Review awaken / default / stub copy — especially “none inferred” and “enforcement is not live yet.”
6. Prefer “Trusted” / “Circle” user-facing names over “L1” / “L2”?

**Archie (constitution)**
7. Confirm owner Trust Map must never filter by these prefs (egocentric authored view) — disclosure applies to **others'** viewer path only.
8. Confirm narrow-only composition + awaken-off→private match the disclosure-reach contract.

**Athena (frontend)**
9. Placement OK (Trust Map toggle + contact-sheet control), or fold into Identity settings with app-lock / biometric?

## Verify
```bash
npx tsx --test src/components/reach-settings/reach-prefs.test.ts
```
Manual: Trust Map → Disclosure reach → awaken + pick L1 → open a node → Bond reach override to Private → refresh still persists.
