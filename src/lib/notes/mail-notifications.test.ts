// src/lib/notes/mail-notifications.test.ts
// Phase 1 mail notifications: the decision matrix + Flint's NEGs (verify-failed / blocked / receipt / wrong fp / canary) + copy == Hypatia
// 9e1aef8d verbatim. Run: npx tsx --test src/lib/notes/mail-notifications.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  COPY, DEFAULT_PREFS, NOTIFICATION_TAG, NOTIFY_BODY_NAMED, NOTIFY_TITLE, SENDER_LINE_PENDING_COPY, decideMailNotification, senderLine, loadMailNotifyPrefs, saveMailNotifyPrefs,
  showMailNotification, type DecideInput,
} from './mail-notifications';

const ME = 'ab'.repeat(32);
const BOB = 'cd'.repeat(32);
const CANARY = 'CANARY-7f3a-secret-note-text';
const base = (over: Partial<DecideInput> = {}): DecideInput => ({
  event: { kind: 'note', note_id: 'n1', thread_id: 't1', from_fingerprint: BOB, to_fingerprint: ME },
  activeFingerprint: ME, unlocked: true, pageHidden: true, permission: 'granted',
  prefs: { enabled: true, showSender: false }, localContactName: 'Bob', ...over,
});

test('M1 the happy path: hidden + opted in + granted + a new note for the ACTIVE identity → exactly { title: "New note", tag }', () => {
  assert.deepEqual(decideMailNotification(base()), { title: 'New note', tag: NOTIFICATION_TAG });
});

test('M2 matrix: each gate alone suppresses it (off, not granted, page visible, no active identity)', () => {
  assert.equal(decideMailNotification(base({ prefs: DEFAULT_PREFS })), null, 'off by default');
  for (const permission of ['default', 'denied', 'unsupported'] as const) assert.equal(decideMailNotification(base({ permission })), null, permission);
  assert.equal(decideMailNotification(base({ pageHidden: false })), null, 'visible page: the app shows it itself');
  assert.equal(decideMailNotification(base({ activeFingerprint: null })), null, 'locked / no identity');
});

test('M3 NEG receipts and unlabelled events never notify (a delivery receipt for OUR note is not "New note"; a same-page send has no kind)', () => {
  assert.equal(decideMailNotification(base({ event: { kind: 'receipt', note_id: 'n1', to_fingerprint: ME } })), null);
  assert.equal(decideMailNotification(base({ event: { note_id: 'n1', thread_id: 't1' } })), null);
});

test('M4 NEG (N4) another identity\'s mail: to_fingerprint ≠ the active identity, or missing → nothing (other tab / switched identity)', () => {
  assert.equal(decideMailNotification(base({ event: { kind: 'note', from_fingerprint: BOB, to_fingerprint: 'ee'.repeat(32) } })), null);
  assert.equal(decideMailNotification(base({ event: { kind: 'note', from_fingerprint: BOB } })), null);
  assert.ok(decideMailNotification(base({ event: { kind: 'note', from_fingerprint: BOB, to_fingerprint: ME.toUpperCase() } })), 'case-insensitive match');
});

test('M5 (N1/N3) the sender is NEVER shown by default, nor while locked, nor without a usable LOCAL contact name', () => {
  for (const over of [
    { prefs: { enabled: true, showSender: false } },
    { prefs: { enabled: true, showSender: true }, unlocked: false },
    { prefs: { enabled: true, showSender: true }, localContactName: null },
    { prefs: { enabled: true, showSender: true }, localContactName: '   ' },
  ] as Partial<DecideInput>[]) {
    const n = decideMailNotification(base(over))!;
    assert.equal(n.title, 'New note');
    assert.equal(n.body, undefined, JSON.stringify(over));
  }
});

test('M5b (Hypatia #188943) named mode: title stays "New note", body "From {name}", from the local name only', () => {
  assert.equal(SENDER_LINE_PENDING_COPY, false);
  assert.equal(NOTIFY_TITLE, 'New note');
  assert.equal(NOTIFY_BODY_NAMED, 'From {name}');
  assert.deepEqual(decideMailNotification(base({ prefs: { enabled: true, showSender: true }, localContactName: 'Work' })), { title: 'New note', body: 'From Work', tag: NOTIFICATION_TAG });
});

test('M5c NEG the name is plain text: control, bidi overrides and every format char (zero-width, LRM/RLM, tags) are stripped; bounded; never a fingerprint', () => {
  const cf = [0x200b, 0x200e, 0x200f, 0x2060, 0xfeff, 0xe0041].map((c) => String.fromCodePoint(c)).join('');
  const rlo = String.fromCodePoint(0x202e);
  assert.equal(senderLine(`B${cf}o${rlo}b\u0007`), 'From Bob');
  assert.equal(senderLine(cf + rlo), undefined, 'nothing visible left → title only');
  assert.equal(senderLine('x'.repeat(500))!.length, 'From '.length + 64);
  for (const fpish of ['cdcdcdcd', 'CDCDCDCD…EFEFEFEF', 'cdcd cdcd cdcd', 'ab:cd:ef:01:23']) assert.equal(senderLine(fpish), undefined, fpish);
  assert.equal(senderLine('Cafe'), 'From Cafe', 'a short word that happens to be hex-ish is still a name');
  assert.equal(senderLine('Bob 1234abcd'), 'From Bob 1234abcd', 'a real name containing hex is a name');
});

test('M6 NEG canary: no field of the notification ever carries note text, a fingerprint or ids, whatever the event carries', () => {
  const ev = { kind: 'note' as const, note_id: CANARY, thread_id: CANARY, from_fingerprint: BOB, to_fingerprint: ME, body: CANARY } as unknown as DecideInput['event'];
  const n = decideMailNotification(base({ event: ev, localContactName: 'Bob', prefs: { enabled: true, showSender: true } }))!;
  const flat = JSON.stringify(n);
  for (const bad of [CANARY, BOB, ME, BOB.slice(0, 8)]) assert.equal(flat.includes(bad), false, bad);
  assert.equal(n.body, 'From Bob', 'only the local name travels');
});

test('M7 NEG (N2) verify-failed / not-in-book / blocked notes never reach the bus: emitNote runs ONLY on consume-mailbox\'s kind "note" branch', () => {
  const cm = readFileSync(join(__dirname, '../sync/consume-mailbox.ts'), 'utf8');
  const calls = cm.match(/deps\.emitNote\?\.\(/g) ?? [];
  assert.equal(calls.length, 1, 'exactly one emitNote call site');
  const at = cm.indexOf('deps.emitNote?.(');
  const branch = cm.lastIndexOf("outcome.kind === 'note'", at);
  assert.ok(branch > 0 && at - branch < 400, "the one call sits inside the outcome.kind === 'note' branch");
});

test('M8 the poller labels its events: emitNote → kind "note", emitReceipt → kind "receipt", both with the owner\'s fingerprint', () => {
  const lbp = readFileSync(join(__dirname, '../sync/live-book-poll.ts'), 'utf8');
  assert.match(lbp, /emitNote: \(e\) => emitNoteArrival\(\{ \.\.\.e, kind: 'note', to_fingerprint: owner\.fingerprint \}\)/);
  assert.match(lbp, /emitReceipt: \(e\) => emitNoteArrival\(\{ \.\.\.e, kind: 'receipt', to_fingerprint: owner\.fingerprint \}\)/);
});

test('M9 a burst of 5 arrivals shows under ONE tag with renotify off (the OS collapses them into one notification)', async () => {
  const shown: Array<{ title: string; opts: NotificationOptions & { renotify?: boolean } }> = [];
  const reg = { showNotification: async (title: string, opts?: NotificationOptions) => { shown.push({ title, opts: opts ?? {} }); } };
  for (let i = 0; i < 5; i++) await showMailNotification(decideMailNotification(base())!, async () => reg);
  assert.equal(new Set(shown.map((s) => s.opts.tag)).size, 1);
  assert.equal(shown[0].opts.tag, NOTIFICATION_TAG);
  assert.equal(shown.every((s) => s.opts.renotify === false && s.opts.body === undefined), true);
  assert.equal(await showMailNotification(decideMailNotification(base())!, async () => { throw new Error('no sw'); }), false, 'never throws');
});

test('M10 prefs: off by default, the name toggle cannot be on while the main one is off, and opting out takes effect on the next read', () => {
  const mem = new Map<string, string>();
  const st = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
  assert.deepEqual(loadMailNotifyPrefs(st), { enabled: false, showSender: false });
  saveMailNotifyPrefs({ enabled: false, showSender: true }, st);
  assert.deepEqual(loadMailNotifyPrefs(st), { enabled: false, showSender: false });
  saveMailNotifyPrefs({ enabled: true, showSender: false }, st);
  assert.ok(decideMailNotification(base({ prefs: loadMailNotifyPrefs(st) })));
  saveMailNotifyPrefs({ enabled: false, showSender: false }, st);
  assert.equal(decideMailNotification(base({ prefs: loadMailNotifyPrefs(st) })), null, 'opt-out stops it immediately');
  mem.set('svrnty:mail-notify:v1', '{not json');
  assert.deepEqual(loadMailNotifyPrefs(st), DEFAULT_PREFS, 'a torn value fails closed');
});

test('M11 copy == Hypatia svrnty_notifications_copy_v1 (9e1aef8d), verbatim, and none of her NEG phrases appear', () => {
  assert.deepEqual(COPY, {
    toggle: 'Notify me about new notes on this device',
    toggleHelper: "Works only while svrnty is open or in a background tab. When svrnty is closed, it can't notify you.",
    beforePrompt: 'Your browser will ask whether svrnty may show notifications.',
    notification: 'New note',
    nameToggle: "Show who it's from",
    nameToggleHelper: 'Names appear on your lock screen, where anyone holding your phone can see them.',
    denied: 'Notifications are blocked for svrnty in your browser settings.',
  });
  const files = ['./mail-notifications.ts', '../../components/notes/MailNotificationsSettingsPanel.tsx', '../../components/notes/useMailNotifications.ts']
    .map((f) => readFileSync(join(__dirname, f), 'utf8').toLowerCase()).join('\n');
  for (const neg of ['private notification', 'anonymous notification', 'no one can tell', 'encrypted notification', 'instant', 'real-time', 'only you can see']) {
    assert.equal(files.includes(neg), false, neg);
  }
});

test('M12 sw.js: the worker version is bumped and a notification tap goes to a FIXED same-origin URL (never the notification data)', () => {
  const sw = readFileSync(join(__dirname, '../../../public/sw.js'), 'utf8');
  assert.match(sw, /const CACHE_NAME = 'svrnty-v4';/);
  assert.match(sw, /addEventListener\('notificationclick'/);
  assert.match(sw, /new URL\('\/', self\.location\.origin\)/);
  assert.doesNotMatch(sw, /notification\.data/);
});
