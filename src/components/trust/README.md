# Trust-phase visual map

Render-glass for CURSOR_QUEUE item 1: pending (one-way) trust must be unmistakable from mutual.

## What this is
`trustPhaseVisual()` is the **one** phase→paint map. Galaxy nodes, address-book chips, and the contact badge all read it. Trust phase is **read** from `livingEdgeStatus(edge).trust` (fleet, shipped). This folder does not recompute trust, does not touch `src/lib/trust/`, and does not change the seal.

## Map
| `livingEdgeStatus.trust` | bond-state | paint | label |
|---|---|---|---|
| `none` | `known` | dim outline, no fill | Known |
| `outbound` | `trust-sent` | dashed hollow, muted, **never white** | Awaiting mutual |
| `inbound` | `trust-received` | gold, actionable, not white | Trusts you · trust back? |
| `mutual` | `mutual` | solid fill + **white core** (the only lit bond) | Mutual |
| blocked | `blocked` | muted / struck | Blocked |

Verify (`ownerHasVerified`) is an ember **on** the bond — orthogonal, never a promotion to mutual/white.

Intro `connection === 'pending'` is a separate axis (`Pending intro`, gold short-dash). It does not reuse `trust-sent`.

## Files
- `trust-phase-visual.ts` — the map
- `trust-phase-visual.test.ts` — white IFF mutual, multi-channel pending≠mutual, verify overlay, intro≠trust-sent, consumer-import lock

Wired consumers: `TrustMap.tsx` (live SVG Galaxy), `TrustMapGalaxy.tsx` (canvas, same map), `MasterAddressBookList.tsx`, `ContactManagement.tsx` (badge / icon). `recordToContact` now forwards `trusted` / `mutual` / `verification` so the book can see reciprocity the way Galaxy already could.

## Not touched
`livingEdgeStatus`, `trust-recipe`, layout radii, seal generator, CODEOWNERS paths.

## Ask
1. Peter-sees-it gate: Alan (sample, trusted not reciprocal) must read **Awaiting mutual** at a glance; Ada must read **Mutual** + white light.
2. Fleet: optional CI step `tsx --test src/components/trust/trust-phase-visual.test.ts` (workflows are CODEOWNERS — not edited here).
