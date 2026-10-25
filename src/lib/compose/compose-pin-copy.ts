// src/lib/compose/compose-pin-copy.ts
// The words of the compose-key PIN ceremony. VERBATIM from Hypatia's portal_compose_copy_v0.md §7 (sha1 64c94d76; Flint K1-K5 lane:portal #1035,
// P1/P2 #1176). Do not reword: pin/rotation wording is where phishing happens. The words are "pinned", never "trusted", "verified", "secure"; the pin
// narrows WHO can put a sign card in front of Peter, it does not make a request safe (K4).
//
// WHERE these appear (Flint P1): every pin, replace and re-pin screen opens ONLY from Settings › Compose key. An arriving note never opens one.
// NEVER here: "trust this portal", "verified portal", "secure connection", "continue anyway", and no auto-pin after the first (K3).
// The only place "safe" appears is the K4 line (in `pinned` and `replaced`), in a negation, on purpose.

export const PIN_COPY = {
  // Settings › Compose key: state line (the "Pinned: " prefix is followed by the 16 hex) and the actions
  stateNotPinned: 'Not pinned',
  statePinnedPrefix: 'Pinned: ',
  // Hypatia doc sha1 d1dacc91 (lane:portal #1513): the old line claimed the portal's key changed; the app only knows a different key sent a request.
  stateBlockedChanged: 'Blocked: a different key sent a request',
  stateBlockedUnreadable: "Blocked: your pin couldn't be read",
  actionPin: 'Pin the key',
  actionCompareNew: 'Compare the new key',
  actionKeepBlocked: 'Keep it blocked',
  actionRePin: 'Re-pin the key',
  // first pin
  firstTitle: "Pin the noosphere portal's compose key",
  firstBody:
    'Sign requests will only be shown from this key. Compare these 16 characters with the noosphere page AND with what you were told separately:',
  // re-pin (the stored pin could not be read: damaged is NOT absent, Flint P2)
  rePinTitle: "Re-pin the noosphere portal's compose key",
  rePinBody:
    "Your old pin couldn't be read, so there's nothing to compare it with. Compare these 16 characters with the noosphere page AND with what you were told separately:",
  // buttons for first pin and re-pin
  match: 'They match, pin it',
  noMatch: "They don't match",
  mismatch: "Not pinned. Don't sign anything from the portal until the characters match, and tell the fleet they didn't.",
  pinned: "Pinned. Sign requests from this key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
  // replace (K3: "Compare the new key" opens this; it SAYS it replaces and keeps the old key in view)
  replaceTitle: 'Replace the pinned compose key?',
  replaceBody:
    'The old key stops working once you pin this one. Compare these 16 characters with the noosphere page AND with what you were told separately:',
  oldLabel: 'Old: ',
  replaceMatch: 'They match, replace it',
  notReplaced: "Not replaced. The old key stays pinned and the new one stays blocked. Tell the fleet the characters didn't match.",
  replaced: "Replaced. Sign requests from the new key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
  // PASSIVE notices (no buttons, no key shown): an arriving note can only ever produce these, never a ceremony
  // Hypatia doc sha1 9a7d704e (lane:portal #1493): the app only knows a DIFFERENT key sent a request, not that the portal's key changed, so it does not say so.
  // Fixed text: nothing from the sender, shown at most once per sender per 24 h (compose-memory.ts, Flint #1489 C3).
  changedNotice: "A sign request arrived from a key that isn't your pinned compose key. It was blocked. If the portal told you its key changed, compare it in Settings › Compose key.",
  // Header over the capped list of recently seen keys in Settings: never pre-selected, none of them checked.
  candidatesHeader: 'Recently seen keys. None of these is checked: compare the characters with the noosphere page AND with what you were told separately before pinning one.',
  unreadableNotice: "Your compose pin couldn't be read, so sign requests are blocked. Re-pin it in Settings › Compose key.",
  unpinnedLog: "A sign request arrived from a key you haven't pinned. It wasn't shown.",
} as const;

export type PinCopyKey = keyof typeof PIN_COPY;

/** Default keyboard focus. Always the SAFE choice, so Enter/Space never accepts a key by reflex. */
export const PIN_DEFAULT_FOCUS = {
  'first-pin': 'noMatch',
  're-pin': 'noMatch',
  replace: 'noMatch',
  /** the Settings row shown when a different key has arrived (Hypatia §7: focus on Keep it blocked) */
  'settings-changed': 'actionKeepBlocked',
} as const;
