// src/lib/lenses/lens-copy.ts
// Lenses v1.7 — the user-facing strings the lenses contract pins EXACTLY. R6: a revised or
// removed lens cannot take back what was already delivered, and a recipient can repeat what they
// were given but cannot prove you gave it to them — no copy may say or imply otherwise. These are
// the sanctioned strings; changing them is a claim-honesty change, not a wording tweak.
//
// {name} = the person's display name (the RECIPIENT on the send side, the SENDER on the receive
// side); {method} = the method label (e.g. "Signal", "Email").
// (Contract-side rule names below use the R6-copy sub-items; the contract's R6a/R6b review rules
// live in the apply/display logic, not here — the labels were relabelled so they no longer clash.)

/** contract R6 (send side) — before WIDENING a recipient's lens, per recipient (and per newly
 *  exposed method). */
export function lensWideningWarning(name: string, method: string): string {
  return `This gives ${name} your ${method}. Once it's sent, you can't take it back.`;
}

/** contract R6 (send side) — on NARROWING a recipient's lens or removing a method from it. */
export function lensNarrowingNote(name: string): string {
  return `${name} won't get updates to this any more. They keep what they already have.`;
}

/** contract R6 (send side) — anywhere the feature is explained. */
export const LENS_EXPLAINER = 'Anyone you give a card to can pass it on.';

/** contract R6 (send side) — the pre-feature line. TRUE only while the flag is off; gate it on
 *  isLensDeliveryLive() (do not delete it, do not leave it standing once lens delivery ships). */
export const EXTRA_METHODS_LOCAL_LINE =
  'Extra methods stay on this device until the living card schema carries them.';

/** The same spot once lens delivery ships — honest, no over-claim, and not an absolute about
 *  where the information can END UP (anyone can pass a card on). */
export const EXTRA_METHODS_LENS_LINE =
  'Extra methods go only to the people whose lens includes them.';

/** Sender-side, when a lens's methods cannot fit the single uniform cell — v1.7 item D2: the
 *  too-large check runs PER RECIPIENT, so the line names them and never claims nothing went to
 *  anyone ("Nothing went out" can be false while another recipient's payload went). */
export function lensTooLargeLine(name: string): string {
  return `This lens has too much in it to send to ${name}. Nothing went to them.`;
}

/** R8a composer ask — a lens carrying two methods in one slot (same kind AND label) is held until
 *  the owner labels them; the noun adapts to the kind ("email addresses" for email). */
export function lensSharedSlotLine(kind: string): string {
  const noun = kind === 'phone' ? 'phone numbers' : kind === 'email' ? 'email addresses' : `${kind} entries`;
  return `Two ${noun} in this lens have the same label. Give each one its own label before you send it.`;
}

/** Receive side — a lens value in the contact view, shown as given (never as the contact's own). */
export function lensGivenLine(name: string): string {
  return `${name} gave you this.`;
}

/** Receive side — a lens value that DIFFERS from the one held before. "Not through the new one"
 *  stays: ringing the new number to check whether the new number is real is how this scam works.
 *  v1.7 item D1: with no name to put to it, the line is the no-name form — "Their {method}
 *  changed." (the old "They's {method}" render is gone). */
export function lensChangedLine(name: string, method: string): string {
  const who = name.trim() ? `${name.trim()}'s` : 'Their';
  return `${who} ${method} changed. Before you rely on the new one, check with them some other way, not through the new one.`;
}

/** Receive side — the held value stays visible beside the changed warning. */
export function lensChangedWasLine(oldValue: string): string {
  return `Was: ${oldValue}`;
}

/** R8a (v1.7) — the VISIBLE state when a contact's payload is refused for the method cap: without
 *  it the contact's updates simply stop, which reads like a Freeze or a Remove nobody made. */
export function lensStoppedLine(name: string): string {
  return `Updates from ${name} can't be shown here any more. Ask them for their current card.`;
}
