// Thread Field helpers — people rail + clocks. No unread counts (I-3), no presence (I-6).

import type { NoteThread } from '@/lib/messaging';
import { readLastActivity } from '@/lib/messaging/thread-activity';
import { NOTES_BOUNDS } from './notes-copy';
import { boundDisplayText, formatFingerprintShort } from './notes-text';

export type FieldPerson = {
  fingerprint: string;
  name: string;
  threadId: string | null;
  preview: string;
  lastAt: string | null;
  sendable: boolean;
};

export type FieldName = {
  fingerprint: string;
  name: string;
};

export function threadPeerFp(thread: NoteThread, ownerFp: string): string {
  const peer = thread.participants.find((p) => p.fingerprint !== ownerFp);
  return peer?.fingerprint || thread.participants[0]?.fingerprint || '';
}

export function displayNameFor(fp: string, names: FieldName[], fallback?: string): string {
  const named = names.find((n) => n.fingerprint === fp);
  if (named?.name) return named.name;
  return boundDisplayText(fallback) || formatFingerprintShort(fp);
}

export function previewLine(body: string, max = 72): string {
  return boundDisplayText(body, max);
}

export function formatNoteClock(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

export function formatNoteDay(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

const FIVE_MIN_MS = 5 * 60 * 1000;
const MS_PER_DAY = 86_400_000;

/** Local calendar day as a UTC-ms key so DST does not split a day. */
function localDayUtcMs(d: Date): number {
  return Date.UTC(d.getFullYear(), d.getMonth(), d.getDate());
}

/**
 * Contact-list timestamp: same local day → clock; yesterday → relative "yesterday";
 * 2–6 local days ago → weekday; older → month+day (year if different).
 * A lastAt up to 5 minutes in the future (clock skew) still renders as a time — never "Tomorrow".
 * In-thread day headings keep using formatNoteDay.
 */
export function formatNoteListWhen(
  iso: string | null | undefined,
  now: Date = new Date(),
): string {
  if (!iso) return '';
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return '';

  const aheadMs = then.getTime() - now.getTime();
  if (aheadMs > 0 && aheadMs <= FIVE_MIN_MS) return formatNoteClock(iso);

  const diffDays = Math.round((localDayUtcMs(now) - localDayUtcMs(then)) / MS_PER_DAY);
  if (diffDays <= 0) return formatNoteClock(iso);
  if (diffDays === 1) {
    return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(-1, 'day');
  }
  if (diffDays <= 6) {
    return then.toLocaleDateString(undefined, { weekday: 'short' });
  }
  const sameYear = then.getFullYear() === now.getFullYear();
  return then.toLocaleDateString(
    undefined,
    sameYear
      ? { month: 'short', day: 'numeric' }
      : { month: 'short', day: 'numeric', year: 'numeric' },
  );
}

export function mergeFieldPeople(args: {
  ownerFp: string;
  threads: NoteThread[];
  names: FieldName[];
  sendable: ReadonlySet<string>;
  previews: Record<string, string>;
  extraFp?: string;
  extraName?: string;
  /** The clock the list is read at (tests); defaults to now. */
  nowMs?: number;
}): FieldPerson[] {
  const seen = new Set<string>();
  const out: FieldPerson[] = [];
  const nowMs = args.nowMs ?? Date.now();

  for (const thread of args.threads) {
    if (thread.kind !== 'direct') continue;
    const fp = threadPeerFp(thread, args.ownerFp);
    if (!fp || seen.has(fp)) continue;
    seen.add(fp);
    const fromThread = thread.participants.find((p) => p.fingerprint === fp)?.display_name;
    out.push({
      fingerprint: fp,
      name: displayNameFor(fp, args.names, fromThread),
      threadId: thread.thread_id,
      preview: args.previews[thread.thread_id] || '',
      lastAt: readLastActivity(thread.last_activity_at, nowMs), // a value ahead of now + slack never shows as a far-future time
      sendable: args.sendable.has(fp),
    });
  }

  for (const row of args.names) {
    if (!row.fingerprint || seen.has(row.fingerprint)) continue;
    if (!args.sendable.has(row.fingerprint) && row.fingerprint !== args.extraFp) continue;
    seen.add(row.fingerprint);
    out.push({
      fingerprint: row.fingerprint,
      name: row.name || formatFingerprintShort(row.fingerprint),
      threadId: null,
      preview: '',
      lastAt: null,
      sendable: args.sendable.has(row.fingerprint),
    });
  }

  if (args.extraFp && !seen.has(args.extraFp)) {
    out.unshift({
      fingerprint: args.extraFp,
      name: displayNameFor(args.extraFp, args.names, args.extraName),
      threadId: null,
      preview: '',
      lastAt: null,
      sendable: args.sendable.has(args.extraFp),
    });
  }

  return out;
}

export function boundPeerName(raw: string | null | undefined): string {
  return boundDisplayText(raw, NOTES_BOUNDS.name);
}

/** Conversations first (recent activity), then unused people by name — Signal/WhatsApp list, not a flat log. */
export function sortFieldPeople(people: FieldPerson[]): FieldPerson[] {
  return [...people].sort((a, b) => {
    const aActive = a.lastAt ? 1 : 0;
    const bActive = b.lastAt ? 1 : 0;
    if (aActive !== bActive) return bActive - aActive;
    if (a.lastAt && b.lastAt && a.lastAt !== b.lastAt) {
      // As NUMBERS: an older build can have stored an offset (+05:00) or no-millisecond string, which sorts hours out of place as text.
      const am = Date.parse(a.lastAt);
      const bm = Date.parse(b.lastAt);
      if (Number.isFinite(am) && Number.isFinite(bm) && am !== bm) return bm - am;
      if (am !== bm) return Number.isFinite(bm) ? 1 : Number.isFinite(am) ? -1 : b.lastAt.localeCompare(a.lastAt);
    }
    return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
  });
}

/** Search by recipient name or fingerprint. Bound + NFC; no unread/presence. */
export function filterFieldPeople(people: FieldPerson[], query: string): FieldPerson[] {
  const q = boundDisplayText(query).toLowerCase();
  if (!q) return people;
  return people.filter((person) => {
    const name = person.name.toLowerCase();
    const fp = person.fingerprint.toLowerCase();
    return name.includes(q) || fp.includes(q);
  });
}
