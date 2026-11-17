// src/components/shard-give-copy.ts
// Two sentences the "give a recovery piece" dialog shows (copy ledger rows 226a and 237), kept apart from the component so tests can pin their bytes and scan the component for the
// old phrases. A leaf on purpose (no imports).
//   - SHARD_LINK_NOTE sits above the link and the QR code. The key is IN the link (the relay URL carries it after the #), and the QR encodes the same URL, so the sentence says so:
//     anyone who holds the link or the QR code can open the piece. The line this replaced told people the server could not see the piece, which hid that.
//   - shardAllGivenLine replaces a line that promised a restore from any N keepers. Collecting pieces back is not in the app yet, so it says what is true: that many
//     keepers together hold enough to rebuild the recovery key, and that collecting them back is not built.
//   - SHARD_READ_FAILED and SHARD_LINK_FAILED are the two failure sentences (reading the pieces on this device; creating the recovery link). The dialog shows these and never an error's own text
//     (the real error is logged by class and code only).
//   - shardReadyLine is the line above the "tear off a piece" button. It said that giving a piece lets any N of your keepers restore you. It now says the same true thing as the all-given
//     line, in one form for a single piece and one for several, and drops the contact's name (it comes from the contact's card).
//   - SHARD_COUNT_UNUSABLE (copy ledger row 258a) is the ONE sentence both lines show when the stored pieces record does not hold a usable count: a threshold that is not an integer
//     with 2 <= threshold <= total, or a total that is not an integer. A record like that can already be on a device (it was imported before the import checked its shape, or it was
//     written some other way), and the two lines above would print its numbers and a "no single piece can" claim that the record does not support. This sentence has no numbers and no such
//     claim. The guard lives in the two line functions, so every caller gets it.
// Run: npx tsx --test src/components/shard-give-copy.test.ts
export const SHARD_LINK_NOTE = "The piece is encrypted in your browser. The server only holds the encrypted copy; the key is in the link itself, so anyone with this link or QR code can open the piece. Send it only through a channel you trust.";

export const SHARD_COUNT_UNUSABLE = "This set of recovery pieces doesn't record a usable count, so this device can't tell how many keepers it takes to rebuild your recovery key. Collecting the pieces back isn't in the app yet.";

// The arguments are typed as numbers, but they are read from a stored record, so at run time they can be anything (a string, NaN, undefined). Number.isInteger is false for all of those.
export function shardCountUsable(total: number, threshold: number): boolean {
  return Number.isInteger(total) && Number.isInteger(threshold) && threshold >= 2 && threshold <= total;
}

export function shardAllGivenLine(total: number, threshold: number): string {
  if (!shardCountUsable(total, threshold)) return SHARD_COUNT_UNUSABLE;
  return `You've given out all ${total} of your pieces. Any ${threshold} of your keepers together hold enough to rebuild your recovery key. Collecting the pieces back isn't in the app yet.`;
}

export function shardReadyLine(remaining: number, total: number, threshold: number): string {
  if (!shardCountUsable(total, threshold)) return SHARD_COUNT_UNUSABLE;
  return `You hold ${remaining} un-given ${remaining === 1 ? 'piece' : 'pieces'} of ${total}. Any ${threshold} of your keepers together hold enough to rebuild your recovery key; no single piece can, not even theirs. Collecting the pieces back isn't in the app yet.`;
}

export const SHARD_READ_FAILED = "Your recovery pieces could not be read on this device.";
export const SHARD_LINK_FAILED = "The recovery link could not be created. Try again.";
