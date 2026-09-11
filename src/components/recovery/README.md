# Recovery glass

UI over fleet recovery primitives. Call existing hooks; do not reimplement crypto.

## Distress — Coming gate (P0 life-safety)

Sender Distress is **not live**. Recovery → **Distress — coming** opens copy that says so, plus a hard-disabled control labelled **Coming**. There is no `sendDistress` path from this sheet.

Do not add EMERGENCY / auto-dial / alarm-banner chrome, and do not restore a recipient-picker that looks like composing a cry. When Fleet wires the envelope, that is an explicit un-gate — not a silent re-enable.

Copy lives in `distress-coming.ts` (Peter/Hypatia-approved body). Tests: `distress-coming.test.ts`, `e2e/distress-coming.spec.ts`.
