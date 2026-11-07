// src/lib/identity/passphrase-loss-notice.ts
// A static notice for people whose contacts or backup went missing after they changed their passphrase or restored a backup (the cause is being fixed).
// Its job is to stop "hidden" from becoming "lost": the stored rows still open with the previous passphrase, and clearing the browser's data would destroy them.
// Wording rules (the claims ledger): "may", never "are"; no "not lost" / "safe"; no date; a secondary line, so a new user is not alarmed.
// ONE place for the words, so a change of wording is a change to this file only.

/** Under "No contacts yet" on the Contacts screen. */
export const PASSPHRASE_LOSS_NOTICE_CONTACTS =
  "If your contacts disappeared after you changed your passphrase or restored a backup, don't clear this browser's data. They may still be stored on this device, and we're working on a way to bring them back. Keep your previous passphrase.";

/** In the backup (vault export) dialog. */
export const PASSPHRASE_LOSS_NOTICE_BACKUP =
  "If no backup file appears after you changed your passphrase or restored a backup, part of your data can't be read with your current passphrase. Don't clear this browser's data, and keep your previous passphrase. We're working on a fix.";
