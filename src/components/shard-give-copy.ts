// src/components/shard-give-copy.ts
// Two sentences the "give a recovery piece" dialog shows (copy ledger rows 226a and 237), kept apart from the component so tests can pin their bytes and scan the component for the
// old phrases. A leaf on purpose (no imports).
//   - SHARD_LINK_NOTE sits above the link and the QR code. The key is IN the link (the relay URL carries it after the #), and the QR encodes the same URL, so the sentence says so:
//     anyone who holds the link or the QR code can open the piece. The line this replaced told people the server could not see the piece, which hid that.
//   - shardAllGivenLine replaces a line that promised a restore from any N keepers. Collecting pieces back is not in the app yet, so it says what is true: that many
//     keepers together hold enough to rebuild the recovery key, and that collecting them back is not built.
// Run: npx tsx --test src/components/shard-give-copy.test.ts
export const SHARD_LINK_NOTE = "The piece is encrypted in your browser. The server only holds the encrypted copy; the key is in the link itself, so anyone with this link or QR code can open the piece. Send it only through a channel you trust.";

export function shardAllGivenLine(total: number, threshold: number): string {
  return `You've given out all ${total} of your pieces. Any ${threshold} of your keepers together hold enough to rebuild your recovery key. Collecting the pieces back isn't in the app yet.`;
}
