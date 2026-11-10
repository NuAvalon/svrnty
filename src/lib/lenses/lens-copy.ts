// src/lib/lenses/lens-copy.ts
// Lenses v1.3 — the user-facing strings the lenses v1.3 contract pins EXACTLY. R6: a revised or
// removed lens cannot take back what was already delivered, and a recipient can repeat what they
// were given but cannot prove you gave it to them — no copy may say or imply otherwise. These are
// the sanctioned strings; changing them is a claim-honesty change, not a wording tweak.
//
// {name} = the person's display name (the RECIPIENT on the send side, the SENDER on the receive
// side); {method} = the method label (e.g. "Signal", "Email").

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

/** R6d's live-arm: what the same spot says once lens delivery ships — honest, no over-claim, and
 *  not an absolute about where the information can END UP (anyone can pass a card on). */
export const EXTRA_METHODS_LENS_LINE =
  'Extra methods go only to the people whose lens includes them.';

/** Sender-side, when a lens's methods cannot fit the single uniform cell: nothing went out. */
export const LENS_TOO_LARGE_LINE =
  'This lens has too much in it to send. Nothing went out. Take something off it and try again.';

/** Receive side — a lens value in the contact view, shown as given (never as the contact's own). */
export function lensGivenLine(name: string): string {
  return `${name} gave you this.`;
}

/** Receive side — a lens value that DIFFERS from the one the signed path delivered. "Not through
 *  the new one" stays: ringing the new number to check whether the new number is real is how this
 *  scam works. */
export function lensChangedLine(name: string, method: string): string {
  return `${name}'s ${method} changed. Before you rely on the new one, check with them some other way, not through the new one.`;
}

/** Receive side — the held value stays visible beside the changed warning. */
export function lensChangedWasLine(oldValue: string): string {
  return `Was: ${oldValue}`;
}
