// src/components/contact-share-copy.ts
// The two sentences the "share your card" dialog shows when a share does not finish (copy ledger row 232a), kept apart from the dialog so tests can pin their bytes and scan the dialog.
//   - SHARE_NFC_FAILED: writing the card to an NFC tag did not finish.
//   - SHARE_LINK_FAILED: the share link could not be created (it is built through the relay).
//   - SHARE_NFC_DENIED (copy ledger row 253): the browser refused the NFC write. Chosen by isNfcNotAllowed, which keys on the error's NAME (a DOMException named NotAllowedError) and never reads its message;
//     the sentence says what to check and does not claim the cause (Web NFC also rejects NotAllowedError for reasons other than a denied permission).
// The dialog used to show whatever error text came back (the browser's own wording for an NFC failure, the relay server's for a link failure). It now shows these and logs the real error by class and code only.
// A leaf on purpose (no imports).
// Run: npx tsx --test src/components/contact-share-copy.test.ts
export const SHARE_NFC_FAILED = "Writing to the tag didn't finish. Try again.";
export const SHARE_LINK_FAILED = "The link couldn't be created. Check your connection and try again.";
export const SHARE_NFC_DENIED = "This browser didn't allow writing to the tag. Check that NFC is allowed for this site in your browser settings, then try again.";

/** True when the browser refused the NFC write: an error whose NAME is NotAllowedError. The name only; the message is never read. */
export function isNfcNotAllowed(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { name?: unknown }).name === 'NotAllowedError';
}
