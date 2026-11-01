// src/components/notes/ratchet-reset-copy.ts
// The one line the reset dialog shows when resetMessageSession throws. Hypatia, #720 copy v0.11 (svrnty_720_receive_copy_v0_11.md, sha256 16020dae), BY VALUE.
// Why this wording: the reset is three non-atomic steps (delete the session, mark held frames, set the flag); a throw at step 2 or 3 leaves the
// session already reset, so "couldn't reset" would be false there. "Didn't finish" is true at any step, and "Try again" is true advice because
// each step is idempotent (session-reset.ts header). No cause, no count, no safety claim.
export const RESET_FAILED_LINE = "The reset didn't finish. Try again.";

// #720 copy v0.12 (svrnty_720_receive_copy_v0_12.md, sha256 f9a7d5d2), BY VALUE. Shown INSTEAD of the two desync hints that point at the Reset button
// when the button is not offered for this contact (a headless peer without the adopt fix: a reset there causes the break instead of fixing it).
// No "ask them to send it again": a resend rides the same out-of-step session. The lines above the hints are unchanged.
export const RESET_UNAVAILABLE_HINT_HELD = "Resetting the message session isn't available for this contact yet.";
export const RESET_UNAVAILABLE_HINT_RECORDED = "This app couldn't keep the message itself, only a note that it arrived. Resetting the message session isn't available for this contact yet.";
