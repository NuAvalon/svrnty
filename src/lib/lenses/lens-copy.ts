// src/lib/lenses/lens-copy.ts
// Lenses v1.3 — the user-facing strings the contract (athena-lenses-v1.3, sha256
// b03b9f45b6b66b75…) pins EXACTLY. R6: a revised or removed lens cannot take back what was
// already delivered, and a recipient can repeat what they were given but cannot prove you gave
// it to them — no copy may say or imply otherwise. These are the sanctioned strings; changing
// them is a claim-honesty change, not a wording tweak.
//
// {name} = the recipient's display name; {method} = the method label (e.g. "Signal", "Email").

/** R6a — before WIDENING a recipient's lens, per recipient (and per newly exposed method). */
export function lensWideningWarning(name: string, method: string): string {
  return `This gives ${name} your ${method}. Once it's sent, you can't take it back.`;
}

/** R6b — on NARROWING a recipient's lens or removing a method from it. */
export function lensNarrowingNote(name: string): string {
  return `${name} won't get updates to this any more. They keep what they already have.`;
}

/** R6c — anywhere the feature is explained. */
export const LENS_EXPLAINER = 'Anyone you give a card to can pass it on.';

/** R6d — the pre-feature line. TRUE only while the flag is off; gate it on isLensDeliveryLive()
 *  (do not delete it, do not leave it standing once lens delivery ships). */
export const EXTRA_METHODS_LOCAL_LINE =
  'Extra methods stay on this device until the living card schema carries them.';

/** R6d's live-arm: what the same spot says once lens delivery ships — honest, no over-claim. */
export const EXTRA_METHODS_LENS_LINE =
  'Extra methods reach only the people whose lens includes them.';
