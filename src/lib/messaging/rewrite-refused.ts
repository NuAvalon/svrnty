// src/lib/messaging/rewrite-refused.ts
// FIRST WRITE WINS (Archie #2653, Flint #2650): a count of inbound notes refused because they reused a stored note_id with different content.
// A number only: no id, no sender, no text. In memory, for this session; the surface that shows it is a later decision.

let refused = 0;

/** Called once per refusal. */
export function noteRewriteRefused(): void {
  refused++;
  console.warn('[notes] refused a rewrite of an already-stored message (count only)');
}

export function rewriteRefusedCount(): number {
  return refused;
}

/** Test seam. */
export function resetRewriteRefusedCount(): void {
  refused = 0;
}
