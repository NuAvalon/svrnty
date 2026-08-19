// src/lib/contacts/contact-events.ts
// Live-beat reactivity primitive (svrnty demo-spine beat-4 — Apollo).
//
// Publishes contact-change events to same-page subscribers AND across tabs/contexts via BroadcastChannel.
// The book (ContactManagement) subscribes → re-project the changed edge(s); the return-channel consume→apply
// caller emits reason:'live-apply' so the render layer resets the last_interaction indicator on the incoming update.
//
// HONESTY GATE (Archie #116323 + Hypatia #116326, converged #116278): `source` distinguishes a TRUE live-push
// ('broadcast' = arrived from ANOTHER tab/context via BroadcastChannel — same page instance, NO reload) from a
// 'local' write in this page. Beat-4 asserts LIVE only on a 'broadcast'-sourced repaint, so the demo can never
// claim "Alice self-updated live" when it actually pulled-to-refresh. BroadcastChannel does NOT echo to its own
// sender, so a context only ever sees OTHER contexts' events as 'broadcast' — the live signal can't be faked locally.
//
// SEAM (gated on Athena's caller + testid): (1) call emitContactChange() at the contacts-store write points in
// @/lib/identity/client-store (addContact/updateContact/removeContact) so every writer — UI, import, and her
// caller — drives reactivity; (2) ContactManagement subscribes and re-reads/re-projects; (3) the caller emits
// reason:'live-apply' after its foldLivingWins apply. Athena owns the beat-4 live-signal testid keyed off `source`.

export type ContactChangeReason = 'ui-edit' | 'import' | 'live-apply' | 'delete';

export interface ContactChangeEvent {
  /** Contact-record ids that changed — subscribers re-project exactly these. Empty = coarse "re-read all" (the pull-to-refresh fallback, not the live beat). */
  ids: string[];
  /** Why it changed. 'live-apply' (incoming via the return-channel caller) is the path that resets last_interaction. */
  reason: ContactChangeReason;
  /**
   * 'local'     — emitted by THIS page's own write (immediate optimistic repaint).
   * 'broadcast' — arrived from another tab/context via BroadcastChannel = the true live-push (beat-4's honest signal).
   * Set by the transport, never by the caller.
   */
  source: 'local' | 'broadcast';
}

type Listener = (evt: ContactChangeEvent) => void;

const CHANNEL_NAME = 'svrnty:contacts';
const listeners = new Set<Listener>();
let channel: BroadcastChannel | null = null;

function ensureChannel(): BroadcastChannel | null {
  if (channel) return channel;
  if (typeof BroadcastChannel === 'undefined') return null; // SSR / unsupported → same-page fan-out only, never throws
  channel = new BroadcastChannel(CHANNEL_NAME);
  channel.onmessage = (e: MessageEvent) => {
    const incoming = e.data as Omit<ContactChangeEvent, 'source'>;
    // Arrived from ANOTHER context → the true live-push. Stamp 'broadcast' and fan out to this page's subscribers.
    fanout({ ids: incoming.ids ?? [], reason: incoming.reason, source: 'broadcast' });
  };
  // Node/SSR: don't let the channel handle keep the process alive (no-op in the browser, which has no unref).
  (channel as unknown as { unref?: () => void }).unref?.();
  return channel;
}

function fanout(evt: ContactChangeEvent): void {
  // Snapshot first: a listener may unsubscribe mid-dispatch; a throwing listener must not break the fan-out.
  for (const l of [...listeners]) {
    try { l(evt); } catch { /* isolate subscriber errors */ }
  }
}

/**
 * Emit a contact-change. Fans out to THIS page's subscribers immediately (source:'local') and posts to other
 * tabs/contexts via BroadcastChannel, where it arrives as source:'broadcast'. Pass the changed record ids;
 * an empty array signals a coarse "re-read everything" (the pull-to-refresh fallback, not the live beat).
 */
export function emitContactChange(evt: { ids: string[]; reason: ContactChangeReason }): void {
  fanout({ ids: evt.ids, reason: evt.reason, source: 'local' });
  const ch = ensureChannel();
  if (ch) ch.postMessage({ ids: evt.ids, reason: evt.reason }); // peers receive it as source:'broadcast'
}

/** Subscribe to contact-change events (local writes + cross-context live-pushes). Returns an unsubscribe fn. */
export function subscribeContactChanges(listener: Listener): () => void {
  ensureChannel(); // open the channel eagerly so cross-tab pushes are received even before this page's first write
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Test/teardown helper: clears subscribers and closes the channel. Not for app use. */
export function __resetContactEventsForTest(): void {
  listeners.clear();
  if (channel) { channel.close(); channel = null; }
}
