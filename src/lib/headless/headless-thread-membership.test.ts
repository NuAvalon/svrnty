// src/lib/headless/headless-thread-membership.test.ts: the headless accept path (HeadlessStore.acceptInboundNote) files a note only into a thread its sender is a participant of.
// A headless agent's own thread ids are GUESSABLE (thr_<owner6>_<peer6>: hex prefixes of public fingerprints), so an admitted peer needs no leaked id to name another contact's thread. The rule,
// the alias and the bound are the browser path's (thread-alias.ts); here they live in the store's single locked write. A sender who is not in the thread they name gets a fresh local thread,
// the claimed thread is untouched, and the alias keeps one conversation in one. A missing, evicted or malformed alias costs a split, never a join. The agent runner's routing
// (routeInbound / loomNotice / openTaskChannel) reads only the sender's contact record and the note body, never a thread: what a joined note could change is what the agent sees in its own store.json.
// Run: npx tsx --test src/lib/headless/headless-thread-membership.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HeadlessStore } from './headless-store';
import { MAX_THREAD_ALIASES } from '@/lib/messaging/thread-alias';
import type { NoteRecord, NoteThread } from '@/lib/messaging/types';

const SENDER = 'cd'.repeat(32);
const OTHER = 'ab'.repeat(32);
const admit = () => true;

const note = (note_id: string, thread_id: string, over: Partial<NoteRecord> = {}): NoteRecord =>
  ({ note_id, thread_id, direction: 'inbound', from_fingerprint: SENDER, to_fingerprints: [], sent_at: '2026-10-30T12:00:00.000Z', body: `body ${note_id}`, participant_kind: 'human',
    retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over } as NoteRecord);
// The real client's threadFor builds a NEW thread under the CLAIMED id (rec.thread_id): the store must override it with the id it chose.
const threadFor = (n: NoteRecord) => (existing: NoteThread | undefined): NoteThread =>
  existing ? { ...existing, last_activity_at: n.sent_at } : { thread_id: n.thread_id, kind: 'direct', participants: [{ fingerprint: n.from_fingerprint, kind: 'human', display_name: 'x' }],
    created_at: n.sent_at, last_activity_at: n.sent_at, retention: { expires_at: null } } as NoteThread;
const accept = (s: HeadlessStore, n: NoteRecord) => s.acceptInboundNote(n, threadFor(n), admit);
const thread = (thread_id: string, fps: string[]): NoteThread =>
  ({ thread_id, kind: 'direct', participants: fps.map((fingerprint) => ({ fingerprint, kind: 'human', display_name: 'p' })), created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-01T00:00:00.000Z', retention: { expires_at: null } } as NoteThread);
const others = (s: HeadlessStore, keep: string[]) => s.listThreads().filter((t) => !keep.includes(t.thread_id));
function fileStore() {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'hl-947-'));
  const path = join(dir, 'store.json'), lockDir = join(dir, 'lock');
  mkdirSync(lockDir, { recursive: true });
  return { dir, path, lockDir, open: () => new HeadlessStore({ path, lockDir }), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('HM1 a sender who is NOT in the thread they name gets a fresh thread: the claimed thread is byte-identical, the note is stored, the fresh thread lists the sender', () => {
  const s = new HeadlessStore();
  s.putThread(thread('thr_victim', [OTHER]));
  const before = JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim'));
  assert.equal(accept(s, note('n1', 'thr_victim')), 'created');
  assert.equal(JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim')), before, 'untouched (last_activity_at did not move)');
  const stored = s.listNotes().find((n) => n.note_id === 'n1')!;
  assert.notEqual(stored.thread_id, 'thr_victim');
  const fresh = others(s, ['thr_victim']);
  assert.deepEqual(fresh.map((t) => t.thread_id), [stored.thread_id]);
  assert.deepEqual(fresh[0].participants.map((p) => p.fingerprint), [SENDER]);
});

test('HM2 CONTROL: a real participant still joins their own thread (case-insensitive) and no alias is written', () => {
  const s = new HeadlessStore();
  s.putThread(thread('thr_mine', [SENDER.toUpperCase()]));
  accept(s, note('n2', 'thr_mine'));
  assert.equal(s.listNotes().find((n) => n.note_id === 'n2')!.thread_id, 'thr_mine');
  assert.deepEqual(others(s, ['thr_mine']), []);
});

test('HM2b an UNKNOWN thread id is created under the claimed id, as before', () => {
  const s = new HeadlessStore();
  accept(s, note('n2b', 'thr_new'));
  assert.equal(s.listNotes()[0].thread_id, 'thr_new');
});

test('HM3 two notes from the same non-member under the same claimed id share ONE fresh thread; the original stays untouched', () => {
  const s = new HeadlessStore();
  s.putThread(thread('thr_victim', [OTHER]));
  const before = JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim'));
  accept(s, note('a', 'thr_victim'));
  accept(s, note('b', 'thr_victim'));
  const ids = new Set(s.listNotes().map((n) => n.thread_id));
  assert.equal(ids.size, 1);
  assert.equal(JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim')), before);
  assert.equal(others(s, ['thr_victim']).length, 1);
});

test('HM4 BOUNDED: after more claimed ids than the bound, the oldest alias is evicted; its next note makes another fresh thread and NEVER joins the original', () => {
  const s = new HeadlessStore();
  const N = MAX_THREAD_ALIASES + 2;
  for (let i = 0; i < N; i++) s.putThread(thread(`thr_v${i}`, [OTHER]));
  for (let i = 0; i < N; i++) accept(s, note(`n${i}`, `thr_v${i}`));
  const before = JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_v0'));
  const firstFresh = s.listNotes().find((n) => n.note_id === 'n0')!.thread_id;
  accept(s, note('again', 'thr_v0')); // thr_v0's alias was evicted
  const again = s.listNotes().find((n) => n.note_id === 'again')!.thread_id;
  assert.notEqual(again, 'thr_v0', 'never the original');
  assert.notEqual(again, firstFresh, 'a split, as the bound allows');
  assert.equal(JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_v0')), before);
});

test('HM5 PERSISTENCE: the alias is written with the book under the lock and a NEW instance resolves the next note to the same fresh thread', () => {
  const f = fileStore();
  try {
    const a = f.open();
    a.putThread(thread('thr_victim', [OTHER]));
    accept(a, note('p1', 'thr_victim'));
    const raw = JSON.parse(readFileSync(f.path, 'utf8'));
    assert.equal(raw.thread_aliases.length, 1);
    assert.deepEqual(Object.keys(raw.thread_aliases[0]).sort(), ['entries', 'fp']);
    const b = f.open();
    accept(b, note('p2', 'thr_victim'));
    assert.equal(new Set(b.listNotes().map((n) => n.thread_id)).size, 1, 'both notes in one fresh thread');
  } finally { f.cleanup(); }
});

test('HM6 an OLD-format file (no alias field) loads and works; a MALFORMED alias field loads as no alias: a split, never a join', () => {
  for (const alias of [undefined, 'garbage', 7, null, [], [{ fp: 'nope' }], [{ fp: SENDER, entries: 'x' }], [{ fp: SENDER, entries: [{ c: 'a' }] }], [{ fp: SENDER.toUpperCase(), entries: [] }]]) {
    const f = fileStore();
    try {
      writeFileSync(f.path, JSON.stringify({ contacts: [], notes: [], threads: [thread('thr_victim', [OTHER])], ...(alias === undefined ? {} : { thread_aliases: alias }) }));
      const s = f.open();
      assert.equal(accept(s, note('m1', 'thr_victim')), 'created', JSON.stringify(alias));
      assert.notEqual(s.listNotes().find((n) => n.note_id === 'm1')!.thread_id, 'thr_victim', 'never joins');
      assert.equal(JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim')), JSON.stringify(thread('thr_victim', [OTHER])), 'the original is untouched');
    } finally { f.cleanup(); }
  }
});

test('HM7 a REDELIVERY of a stored non-member note is idempotent even with the alias GONE: "stored", not "kept"; one thread', () => {
  const f = fileStore();
  try {
    const a = f.open();
    a.putThread(thread('thr_victim', [OTHER]));
    assert.equal(accept(a, note('r1', 'thr_victim')), 'created');
    const raw = JSON.parse(readFileSync(f.path, 'utf8'));
    delete raw.thread_aliases; // the alias is lost
    writeFileSync(f.path, JSON.stringify(raw));
    const b = f.open();
    assert.equal(accept(b, note('r1', 'thr_victim')), 'stored', 'a byte-identical redelivery, not a refused rewrite');
    assert.equal(others(b, ['thr_victim']).length, 1);
    assert.equal(b.listNotes().length, 1);
  } finally { f.cleanup(); }
});

// ---- static pin: the alias is local to the headless book; nothing else names its field ----
const CWD = process.cwd();
const codeOnly = (t: string): string => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
function sources(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== 'node_modules' && n !== '.next') sources(p, out); continue; }
    if (/\.(ts|tsx|mjs)$/.test(n) && !/\.test\.(ts|tsx)$/.test(n) && !/\.d\.ts$/.test(n)) out.push(p);
  }
  return out;
}
test('HM8 PIN: the alias field of the headless book is named by the store alone (no export, dead-letter or script reads or prints it)', () => {
  const named = ['app', 'src', 'scripts'].flatMap((r) => (existsSync(join(CWD, r)) ? sources(join(CWD, r)) : []))
    .filter((f) => /\bthread_aliases\b/.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(CWD.length + 1)).sort();
  assert.deepEqual(named, ['src/lib/headless/headless-store.ts']);
});

test('HM9 TWO SENDERS: two different non-members naming the same thread get two different fresh threads, each listing only its own sender (the alias is keyed by the sender)', () => {
  const B = 'ef'.repeat(32);
  const s = new HeadlessStore();
  s.putThread(thread('thr_victim', [OTHER]));
  const before = JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim'));
  assert.equal(accept(s, note('a1', 'thr_victim')), 'created');
  assert.equal(accept(s, note('b1', 'thr_victim', { from_fingerprint: B })), 'created');
  const tA = s.listNotes().find((n) => n.note_id === 'a1')!.thread_id;
  const tB = s.listNotes().find((n) => n.note_id === 'b1')!.thread_id;
  assert.notEqual(tA, 'thr_victim');
  assert.notEqual(tB, 'thr_victim');
  assert.notEqual(tA, tB, "B's note is not filed into A's fresh thread");
  const fps = (id: string) => s.listThreads().find((t) => t.thread_id === id)!.participants.map((p) => p.fingerprint);
  assert.deepEqual(fps(tA), [SENDER], "A's thread lists only A");
  assert.deepEqual(fps(tB), [B], "B's thread lists only B");
  // each sender's later note under the same claimed id stays in their OWN fresh thread
  assert.equal(accept(s, note('a2', 'thr_victim')), 'created');
  assert.equal(accept(s, note('b2', 'thr_victim', { from_fingerprint: B })), 'created');
  assert.equal(s.listNotes().find((n) => n.note_id === 'a2')!.thread_id, tA);
  assert.equal(s.listNotes().find((n) => n.note_id === 'b2')!.thread_id, tB);
  assert.equal(JSON.stringify(s.listThreads().find((t) => t.thread_id === 'thr_victim')), before, 'the claimed thread is still untouched');
  assert.deepEqual(others(s, ['thr_victim', tA, tB]), [], 'no other thread appeared');
});
