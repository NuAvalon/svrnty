// src/components/settings/trust-map-copy.ts
// The words of the "Show up in trust maps" setting (copy ledger rows 323 and 326). Reviewed copy: do not reword it here; a change needs the copy owner's new row and new hash. Plain ASCII, straight apostrophes.
//   - While nobody is sent anything yet (isPiece2MutualBlockLive() is false) every line says what is SAVED and that it is not live. Nothing here claims that anyone is currently hidden or shown, and nothing
//     mentions blocked people or a delay: those come back with the switch that makes the setting live, re-verified then.
//   - Turning "show up" ON asks first; turning it OFF does not.
// Run: npx tsx --test src/components/settings/trust-map-setting.test.ts   (the hashes and lengths of these strings are pinned there)

/** Row 323a (21 chars, sha256 prefix 6f0d114e6f1f20eb): the switch's label. */
export const TRUST_MAP_LABEL = 'Show up in trust maps';
/** Row 323b (103, a80fcf243966c8b8): shown in BOTH states, and under the unreadable line, while the setting is not live. */
export const TRUST_MAP_NOT_LIVE = "Showing up in other people's trust maps isn't live yet. Your choice is saved and will apply when it is.";
/** Row 323c (74, 77ab3f0098270dc9): the stored choice is "show up". */
export const TRUST_MAP_STATE_ON = "You're set to show up in the trust maps of the people you're connected to.";
/** Row 323c (52, cbfac985da6a671e): the stored choice is "stay out". */
export const TRUST_MAP_STATE_OFF = "You're set to stay out of other people's trust maps.";
/** Row 323d (76, f62f877112427fc0): asked before ANY write that turns "show up" on. */
export const TRUST_MAP_CONFIRM = "Set yourself to show up in the trust maps of the people you're connected to?";
/** Row 323d (7, b43e47255851dc59) and (6, 19766ed6ccb2f4a3): the two buttons. Cancel writes nothing. */
export const TRUST_MAP_CONFIRM_YES = 'Show up';
export const TRUST_MAP_CONFIRM_NO = 'Cancel';
/** Row 323f = 204c (56, 44a6df8051a158c0): the write did not finish; the switch shows the stored state, read again. */
export const TRUST_MAP_WRITE_FAILED = "That didn't save. Your trust-map setting hasn't changed.";
/** Row 326a (72, 93757b238368db05): no record is saved on this device (never made, or lost: they cannot be told apart, so this never says "not set up yet"). No switch; nothing is written. */
export const TRUST_MAP_ABSENT = "This device has no trust-map setting saved, so it can't be changed here.";
/** Row 326b (84, d82c4d582595ebe2): a record is saved but cannot be read. No switch; nothing is written. (Row 325a, which said this to people for whom nothing had failed, is void.) */
export const TRUST_MAP_UNREADABLE = "Your trust-map setting couldn't be read on this device, so it can't be changed here.";
