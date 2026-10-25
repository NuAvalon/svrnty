// src/lib/compose/compose-pin-copy.ts
// The words of the compose-key PIN ceremony. VERBATIM from Hypatia's portal_compose_copy_v0.md §7 (sha1 b1d3aa51; Flint K1-K5, lane:portal #1035).
// Do not reword: pin/rotation wording is where phishing happens ("key changed, continue?" trains click-through). The words are "pinned", never
// "trusted", "verified", "secure"; the pin narrows WHO can put a sign card in front of Peter, it does not make a request safe (K4).
//
// NEVER here: "trust this portal", "verified portal", "secure connection", "continue anyway", and no auto-pin after the first (K3).
// The one place "safe" appears is the K4 line, in a negation, on purpose.

export const PIN_COPY = {
  firstTitle: "Pin the noosphere portal's compose key",
  firstBody:
    'Sign requests will only be shown from this key. Compare these 16 characters with the noosphere page AND with what you were told separately:',
  match: 'They match, pin it',
  noMatch: "They don't match",
  mismatch: "Not pinned. Don't sign anything from the portal until the characters match, and tell the fleet they didn't.",
  pinned: "Pinned. Sign requests from this key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
  changed: "The portal's compose key changed. Requests from it are blocked until you compare the new key.",
  oldLabel: 'Old: ',
  newLabel: 'New: ',
  compareNew: 'Compare the new key',
  keepBlocked: 'Keep it blocked',
  unpinnedLog: "A sign request arrived from a key you haven't pinned. It wasn't shown.",
} as const;

export type PinCopyKey = keyof typeof PIN_COPY;

/** Default keyboard focus per screen. On the K3 rotation screen it is the SAFE choice, so Enter/Space never accepts a new key by reflex. */
export const PIN_DEFAULT_FOCUS = {
  'first-pin': 'noMatch',
  'key-changed': 'keepBlocked',
  'compare-new': 'noMatch',
} as const;
