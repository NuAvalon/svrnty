# Galaxy peer-mesh legend (queue #4)

Render-glass only. Appends the anti-surveillance clause to the TrustMap legend so the glass says lines are disclosures, not observations, and that svrnty does not infer who knows whom.

## Files
- `peer-mesh-copy.ts` — the clause (verbatim from the queue spec)
- `TrustMap.tsx` — interpolates it next to the existing consented-legend sentence
- `peer-mesh-copy.test.ts` — clause shape + TrustMap still says "consented" (do not drop that guarantee)

## What this does not touch
`src/lib/trust/*` (CODEOWNERS). Draft PR #170 moves hover titles / `peerMeshLegend` into the recipe; this PR is the tiny follow-up that paints the clause on the glass. Fold the sentence into `peerMeshLegend` later if the recipe owner wants a single source.

## Honest limit
The peer mesh is still go-live-gated. This is legend copy on the Galaxy, not a claim that the mesh is live.
