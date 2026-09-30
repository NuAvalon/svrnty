/**
 * Sender Distress — Coming gate (life-safety).
 *
 * Fleet owns the envelope (`sendDistress` in src/lib/trust — do not call it from glass
 * until send is real). This file is copy + the disabled-control contract only.
 *
 * ⛔ Do not add present-tense "it sent" / "calling for help" / EMERGENCY / auto-dial chrome.
 */

export const DISTRESS_COMING_COPY = {
  menuLabel: 'Distress — coming',
  heading: 'Distress signal — coming',
  body:
    "This will let you quietly reach the people you trust to come to you — in person, offline — when you can't safely say why. It isn't live yet, so we've turned it off rather than let it fail silently. Pressing it now would do nothing, and we won't pretend otherwise.",
  controlLabel: 'Coming',
} as const;
