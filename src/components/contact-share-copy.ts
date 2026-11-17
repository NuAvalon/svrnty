// src/components/contact-share-copy.ts
// The two sentences the "share your card" dialog shows when a share does not finish (copy ledger row 232a), kept apart from the dialog so tests can pin their bytes and scan the dialog.
//   - SHARE_NFC_FAILED: writing the card to an NFC tag did not finish.
//   - SHARE_LINK_FAILED: the share link could not be created (it is built through the relay).
// The dialog used to show whatever error text came back (the browser's own wording for an NFC failure, the relay server's for a link failure). It now shows these and logs the real error by class and code only.
// A leaf on purpose (no imports).
// Run: npx tsx --test src/components/contact-share-copy.test.ts
export const SHARE_NFC_FAILED = "Writing to the tag didn't finish. Try again.";
export const SHARE_LINK_FAILED = "The link couldn't be created. Check your connection and try again.";
