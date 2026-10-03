# One-step Connect-UX (render-glass)

CURSOR_QUEUE #3 — paste a grow-link → Gate (pending) → one tap Known.

**This folder is glass only.** Crypto / grow-link resolve / Gate persist live behind `src/lib/connect/add-logic.ts`, a typed stub. Apollo wires that post-flip. Flip `isConnectAddLogicLive()` in `claim-gates.ts` WITH the real implementation — until then the live `/c/{code}` path stays `JoinerCeremony`.

## Files
| File | Role |
|------|------|
| `src/lib/connect/parse-connect-link.ts` | Parse full invite, `/c/{code}` without key, or bare code. INV-4 for keyed URLs. Never logs the fragment. |
| `src/lib/connect/add-logic.ts` | `resolveConnectLink` / `landInGate` / `promoteGateToKnown` — stub, fail-closed, never Known on land, never Trust on promote |
| `src/lib/connect/copy.ts` | Claim-honest strings. Entity type = **attested**, not verified. UNKNOWN = not yet attested. |
| `ConnectOneStep.tsx` | Paste → Gate chrome → Add to Known (disabled while stubbed) |
| `ConnectArrivalCard.tsx` | Card chrome. Seal recomputed from fingerprint (I-6). Mailbox via scheme-allowlist (I-10a). |

## Invariants (must hold)
1. Gate-not-Known on arrival — land never returns Known; Add to Known is a separate tap.
2. Add is local + one-sided — copy says so; no mutual assertion from the link.
3. Mutual-known/trust requires both sides — the link does not fabricate a mutual edge.
4. Invitation, not capture / not a bearer grant.
5. Promote choice is Known only — Trust is not offered here.

## Honest limits
- Persist is **not live**. Copy says so. The Add to Known button stays disabled until Apollo flips the gate.
- `/c/{code}` still mounts JoinerCeremony while `isConnectAddLogicLive() === false` so today's grow/scan e2e and live joins keep working.
- No-account: CTA to create identity on home, then return to the same link. Mint is not inlined (it lives in `SoverentityFrontend`; extracting it would touch restore-gate-adjacent UI).
- Hypatia: microcopy is operational pending her claim-ledger pass.

## Assumptions
- Grow is identity-gated today, so the paste field on Grow always has an owner. No-account is the `/c/` branch after the flip.
- Bare codes and keyless `/c/{code}` are accepted by the parser; resolve still no-ops until Apollo.

## Questions
1. **Apollo:** please implement `resolveConnectLink` / `landInGate` / `promoteGateToKnown` and flip `isConnectAddLogicLive()`. The UI is wired to those three calls only.
2. **Apollo:** when the gate flips, should `/c/{code}` drop JoinerCeremony for cards (keep it for shard links)?
3. **Hypatia:** please replace CONNECT_COPY with claim-ledger strings. Entity badge is `attested: …` / `not yet attested` (KB#90007/90008).
4. **Athena:** is inlining mint on `/c/` (existing genesis UI, PWA stays open) a follow-on, or should this shell keep the home-screen CTA?

## Verify
```bash
npx tsx --test src/lib/connect/parse-connect-link.test.ts src/lib/connect/add-logic.test.ts src/lib/connect/copy.test.ts src/lib/claim-gates.test.ts
npx playwright test e2e/connect-one-step.spec.ts
```
