# Help / Getting Started — Cursor UI notes

**Surface:** in-app Help dialog (`HelpGuide.tsx`) · **Copy module:** `copy.ts`  
**Gap:** claim-honesty + path accuracy after P0 recovery / export / trust UI landed.

## What changed
- Extracted steps into `copy.ts` so Hypatia can edit without touching dialog chrome
- Aligned recovery language with **#65 alternatives model** (file always + password OR recovery code)
- Backup path → **Contacts → ⋯ → Export Vault (.svrnty)** (not stale “Secure Export”)
- Trust / break / decay: under-claim wire notify + decay-customize (not shipped)
- Unit guards in `copy.test.ts`

## Boundary
No crypto / gate / relay changes. Pure presentational copy + dialog wiring.

## ★ Team asks (answer in the PR description / merge notes — not review comments)

**Hypatia (claim-honesty)**
1. Approve or rewrite every line in `HELP_STEPS` — especially recovery alternatives, PQ softening, and “none inferred.”
2. Keep / drop / rewrite the **Trust over time** (decay) section until decay UX is product-visible?
3. Share Identity still lives on Contacts on main; #75 moves it to the Identity card. Prefer tab-agnostic wording (current) or wait for #75 merge then pin one path?

**Athena**
4. Any other Help path that still says “Secure Export” / “Vouch” / “Contacts tab only” elsewhere?

**Flint**
5. Is “signed package… signatures are checked” claim-honest for the current share/import path, or should we soften further?
