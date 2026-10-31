// src/lib/notes/mail-notifications.ts
// Phase 1 mail notifications (opt-in, client only). Spec: Athena svrnty_mail_notifications_spec_v1 (fe94d085), Flint review 06e74339
// (N1-N4), copy Hypatia svrnty_notifications_copy_v1 (9e1aef8d), strings verbatim.
//
// While svrnty is open or in a background tab, a NEW, verified, admitted inbound note can raise a system notification. Nothing here runs
// when svrnty is closed, and nothing leaves the device: the prefs are local, and the notification is shown by this device's own service worker.
//
// The decision is a PURE function (decideMailNotification) so every rule is a test row:
// - only kind === 'note' (emitted after a signed + admitted persist; never a receipt, never our own send, never a drop)  (N2, receipts)
// - only for the ACTIVE identity (to_fingerprint must match)                                                                (N4)
// - only when the page is hidden, the user opted in, and the browser granted permission
// - the text is the constant "New note" unless the nested "Show who it's from" is on AND the app is unlocked AND the sender
//   has a LOCAL contact name (never the envelope's)                                                                         (N1, N3)
// - never the note text, never a fingerprint, never a count.

import type { NoteArrivalEvent } from './note-events';

// ── copy (Hypatia 9e1aef8d, verbatim) ──────────────────────────────────────────────────────────────────────────────────────
export const COPY = {
  toggle: 'Notify me about new notes on this device',
  toggleHelper: "Works only while svrnty is open or in a background tab. When svrnty is closed, it can't notify you.",
  beforePrompt: 'Your browser will ask whether svrnty may show notifications.',
  notification: 'New note',
  nameToggle: "Show who it's from",
  nameToggleHelper: 'Names appear on your lock screen, where anyone holding your phone can see them.',
  denied: 'Notifications are blocked for svrnty in your browser settings.',
} as const;

/** One tag for every mail notification: a burst collapses into one, and a later one replaces it quietly. */
export const NOTIFICATION_TAG = 'svrnty-mail';

// ── device-local prefs ─────────────────────────────────────────────────────────────────────────────────────────────────────
export type MailNotifyPrefs = { enabled: boolean; showSender: boolean };
export const DEFAULT_PREFS: MailNotifyPrefs = { enabled: false, showSender: false };
const PREFS_KEY = 'svrnty:mail-notify:v1';

export function loadMailNotifyPrefs(storage: Pick<Storage, 'getItem'> | null = safeLocalStorage()): MailNotifyPrefs {
  try {
    const raw = storage?.getItem(PREFS_KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    const p = JSON.parse(raw) as Partial<MailNotifyPrefs>;
    const enabled = p.enabled === true;
    // The name toggle is nested: it can only be on while the main toggle is on.
    return { enabled, showSender: enabled && p.showSender === true };
  } catch {
    return { ...DEFAULT_PREFS };
  }
}

export function saveMailNotifyPrefs(prefs: MailNotifyPrefs, storage: Pick<Storage, 'setItem'> | null = safeLocalStorage()): void {
  try {
    storage?.setItem(PREFS_KEY, JSON.stringify({ enabled: prefs.enabled, showSender: prefs.enabled && prefs.showSender }));
  } catch {
    /* private mode / blocked storage: the toggle simply doesn't persist */
  }
}

function safeLocalStorage(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

// ── the decision ──────────────────────────────────────────────────────────────────────────────────────────────────────────
export type DecideInput = {
  event: NoteArrivalEvent;
  /** The identity this tab has loaded and unlocked; null when locked or no identity. */
  activeFingerprint: string | null;
  unlocked: boolean;
  pageHidden: boolean;
  permission: NotificationPermission | 'unsupported';
  prefs: MailNotifyPrefs;
  /** The LOCAL contact book's name for event.from_fingerprint under the active identity, or null. Never taken from the envelope. */
  localContactName: string | null;
};
export type MailNotification = { title: string; body?: string; tag: string };

export function decideMailNotification(i: DecideInput): MailNotification | null {
  if (!i.prefs.enabled) return null;
  if (i.permission !== 'granted') return null;
  if (!i.pageHidden) return null; // the open page already shows it (Notes tab dot / inbox repaint)
  if (i.event.kind !== 'note') return null; // receipts, our own sends and anything unlabelled never notify (fail closed)
  if (!i.activeFingerprint || !i.event.to_fingerprint) return null;
  if (i.event.to_fingerprint.toLowerCase() !== i.activeFingerprint.toLowerCase()) return null; // N4: another identity's mail (e.g. another tab)
  const base: MailNotification = { title: COPY.notification, tag: NOTIFICATION_TAG };
  const name = i.localContactName?.trim();
  if (i.prefs.showSender && i.unlocked && name) {
    return { ...base, body: senderLine(name) };
  }
  return base;
}

/**
 * The sender line shown under "New note" when the nested toggle is on. Hypatia's copy v1 (9e1aef8d) doesn't define this string yet
 * (asked 🦉12735). Until she does, it is OFF: senderLine returns the name ONLY through this single constant, so the copy change is one line + its pin.
 */
export const SENDER_LINE_PENDING_COPY = true;
export function senderLine(name: string): string | undefined {
  if (SENDER_LINE_PENDING_COPY) return undefined;
  return name;
}

// ── showing it ────────────────────────────────────────────────────────────────────────────────────────────────────────────
type Registration = { showNotification: (title: string, options?: NotificationOptions) => Promise<void> };

/** Shows through the service worker registration (Android Chrome throws on `new Notification()`). Never throws. */
export async function showMailNotification(n: MailNotification, getRegistration: () => Promise<Registration | null>): Promise<boolean> {
  try {
    const reg = await getRegistration();
    if (!reg) return false;
    const opts: NotificationOptions & { renotify?: boolean } = { tag: n.tag, renotify: false, icon: '/icon-192.svg', data: { url: '/' } };
    if (n.body) opts.body = n.body;
    await reg.showNotification(n.title, opts);
    return true;
  } catch {
    return false;
  }
}

export function notificationPermission(): NotificationPermission | 'unsupported' {
  try {
    return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
  } catch {
    return 'unsupported';
  }
}
