# Notes inbox (over-wire SEND / INBOX)

Render-glass for CURSOR_QUEUE item 1 (Over-wire SEND / INBOX). Compose calls fleet `sendNoteToPeer`. The inbox **reads** `listThreads()` / `listNotesForThread()`. Receive persist is already in the app-shell live-book poll (`acceptInboundNote`) — this tab does not reimplement consume.

The glass is the **Thread Field**: a people rail (recomputed seals in hex chips + last-note preview, no unread counts) and an ember conversation (outbound glow / inbound dim). Galaxy stars hop here via **Note** on the star sheet (`onOpenNote` → `focusFingerprint`).

## Files
- `NotesInbox.tsx` — Thread Field + honest send status
- `notes-field.ts` — people-rail merge + clocks (no presence)
- `notes-copy.ts` — queue copy (status floor **Sent · unconfirmed.**)
- `notes-contacts.ts` — sendable = SVRN card with a public key, not blocked
- `notes-keys.ts` — load unlocked identity args; thread PQ pubs for canonical senders
- `notes-send.ts` — thin `sendNoteToPeer` call
- `notes-status.ts` — deposited → Sent · unconfirmed; failed deposit → Not sent
- `note-events.ts` — same-page / cross-tab inbox-repaint bus

## Wiring (must stay true)
- Crypto is **call-only**: `sendNoteToPeer` / `listThreads` / `listNotesForThread` / `initNotesStore`.
- Senders must be **canonical** (64-hex fp + PQ pubs). Classical 40-hex cannot send; the relay rejects them.
- Outbound status is **Sent · unconfirmed.** Never Delivered / Read / Expired. Never poll `/api/relay/msg/status`.
- A failed deposit is **Not sent. Saved on this device.** — not a fake Sent.
- Dropped inbound (non-contact / unsigned / forged) stays silent. No admit-status oracle.
- Did not flip `isPQEncapLive()` / `isPQSignLive()`. Did not build the beta redeem screen (queue item 2).

## Live-repaint seam (ask)
`consume-mailbox.ts` already has `emitNote`. `buildConsumeDeps` in `src/lib/sync/live-book-poll.ts` does **not** pass it (CODEOWNERS — not touched). This tab re-reads the notes store while open and subscribes to `subscribeNoteArrivals`. Please wire:

```ts
emitNote: (e) => emitNoteArrival(e),
```

in `buildConsumeDeps` (import `emitNoteArrival` from this folder). Until then, arrivals persist (PR #212) and appear on the next store re-read / when the inbox is opened.

## Copy
Queue LIVE-STATUS said to use the beta-surface strings for this glass. Unlock/redeem stays **off** this PR (gate-ON only, next item). Hypatia: the "end-to-end encrypted" / "never learns who you talk to" paragraph is copied from the queue spec (classical OpenPGP seal + dumb mailbox, not PQ).
