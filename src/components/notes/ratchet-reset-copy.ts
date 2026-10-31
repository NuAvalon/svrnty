// src/components/notes/ratchet-reset-copy.ts
// The one line the reset dialog shows when resetMessageSession throws. Hypatia, #720 copy v0.11 (svrnty_720_receive_copy_v0_11.md, sha256 16020dae), BY VALUE.
// Why this wording: the reset is three non-atomic steps (delete the session, mark held frames, set the flag); a throw at step 2 or 3 leaves the
// session already reset, so "couldn't reset" would be false there. "Didn't finish" is true at any step, and "Try again" is true advice because
// each step is idempotent (session-reset.ts header). No cause, no count, no safety claim.
export const RESET_FAILED_LINE = "The reset didn't finish. Try again.";
