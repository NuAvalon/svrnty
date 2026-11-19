// src/components/contacts/removed-before-copy.ts
// The words on the owner's private contact card for a person the owner removed and later let back in (copy ledger rows 311a, 311b and 314a). Reviewed copy: do not reword it here; a
// change needs the copy owner's new row and new hash. Plain ASCII, straight apostrophes.
//   - It says the person is back in the contacts, that they were not told, and that the owner's backups still record the removal. It never says blocked, unblocked or restricted.
//   - There is no default button and no "Leave it": closing the card changes nothing and the notice shows again.
// Run: npx tsx --test src/components/contacts/removed-before-copy.test.ts

/** Row 311a (157 chars, sha256 prefix 89947ff34c4b995d): the notice body. */
export const REMOVED_BEFORE_NOTICE = "You removed this person before. They're back in your contacts now, and they weren't told you'd removed them. Your backups still record that you removed them.";
/** Row 314a (60 chars, bb4f6aa12f9e9976): the line under the two buttons. */
export const REMOVED_BEFORE_KEEP_HELPER = "Keep them, and backups you make from now on won't record it.";
/** Row 314a: the two buttons. Keep = take them off the removed list (the drop's one caller); Remove them again = the normal Remove. */
export const REMOVED_BEFORE_KEEP = 'Keep them';
export const REMOVED_BEFORE_REMOVE_AGAIN = 'Remove them again';
/** Row 314b = 311b (102 chars, 17bec0c1bbd54de7): shown when taking them off the removed list did not finish. */
export const REMOVED_BEFORE_DROP_FAILED = "Taking them off your removed list didn't finish. Your backups will still record that you removed them.";
/** Row 314b: the two buttons on the failure line. Try again retries only the drop; Not now goes back to the notice. */
export const REMOVED_BEFORE_TRY_AGAIN = 'Try again';
export const REMOVED_BEFORE_NOT_NOW = 'Not now';
