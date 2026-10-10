// Thread Field helpers — people rail + clocks. No unread counts (I-3), no presence (I-6).

import type { NoteThread } from '@/lib/messaging';
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

export function mergeFieldPeople(args: {
  ownerFp: string;
  threads: NoteThread[];
  names: FieldName[];
  sendable: ReadonlySet<string>;
  previews: Record<string, string>;
  extraFp?: string;
  extraName?: string;
}): FieldPerson[] {
  const seen = new Set<string>();
  const out: FieldPerson[] = [];

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
      lastAt: thread.last_activity_at,
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
