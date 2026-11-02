// Wiring: the REAL acceptInboundNote keeps a thread's last_activity_at monotone and clamped (chat-list order).
// The thread store has the same replace-by-thread_id semantics as the IndexedDB 'threads' store.
// Run: npx tsx --test src/lib/messaging/thread-activity-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import { ACTIVITY_FUTURE_SLACK_MS } from './thread-activity';
import { sortFieldPeople, type FieldPerson } from '../../components/notes/notes-field';
import type { NoteRecord, NoteWireV0, NoteThread } from './types';

async function mint() {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, pass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, sig: id.pq_sig_public_key };
}
type Id = Awaited<ReturnType<typeof mint>>;
const note = (s: Id, note_id: string, sent_at: string, thread_id = 'thr_b') =>
  signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id, from_fingerprint: s.fp, sent_at, body: 'hi', participant_kind: 'human' } as NoteWireV0, s.pub, s.priv, s.pass, s.kem, s.sig);

function store() {
  const rows = new Map<string, NoteRecord>();
  const threads = new Map<string, NoteThread>();
  const io = {
    putNote: (async (n: NoteRecord) => { rows.set(n.note_id, structuredClone(n)); }) as never,
    getNote: (async (id: string) => rows.get(id) ?? null) as never,
    putThread: (async (t: NoteThread) => { threads.set(t.thread_id, structuredClone(t)); }) as never,
    listThreads: (async () => [...threads.values()]) as never,
  };
  return { threads, io };
}
const accept = (wire: NoteWireV0, io: unknown) => acceptInboundNote({ wire, isAdmitted: async () => true, io: io as never } as never);

test('T1 NEG: an older backlog note processed AFTER a newer one does not move the thread back', async () => {
  const B = await mint();
  const st = store();
  assert.ok(await accept(await note(B, 'n1', '2026-10-30T12:00:00.000Z'), st.io));
  assert.ok(await accept(await note(B, 'n2', '2026-10-24T07:00:00.000Z'), st.io));
  assert.equal(st.threads.get('thr_b')!.last_activity_at, '2026-10-30T12:00:00.000Z');
});

test('T2 NEG: a 2099 sent_at is stored CLAMPED to now+slack, never raw', async () => {
  const B = await mint();
  const st = store();
  const t0 = Date.now();
  assert.ok(await accept(await note(B, 'n1', '2099-01-01T00:00:00.000Z'), st.io));
  const got = Date.parse(st.threads.get('thr_b')!.last_activity_at);
  assert.ok(got >= t0 + ACTIVITY_FUTURE_SLACK_MS - 5000 && got <= Date.now() + ACTIVITY_FUTURE_SLACK_MS + 5000, `clamped, got ${new Date(got).toISOString()}`);
});

test('T3 control: a newer note still advances the thread', async () => {
  const B = await mint();
  const st = store();
  assert.ok(await accept(await note(B, 'n1', '2026-10-24T07:00:00.000Z'), st.io));
  assert.ok(await accept(await note(B, 'n2', '2026-10-30T12:00:00.000Z'), st.io));
  assert.equal(st.threads.get('thr_b')!.last_activity_at, '2026-10-30T12:00:00.000Z');
});

test('T4 the SAME backlog delivered twice (ack never lands) => zero reorders on the second pass', async () => {
  const [A, B, C] = [await mint(), await mint(), await mint()];
  const st = store();
  const backlog = [
    await note(A, 'a1', '2026-10-30T10:00:00.000Z', 'thr_a'), await note(B, 'b1', '2026-10-30T12:00:00.000Z', 'thr_b'),
    await note(B, 'b0', '2026-10-24T07:00:00.000Z', 'thr_b'), await note(C, 'c1', '2026-10-29T09:00:00.000Z', 'thr_c'),
    await note(A, 'a0', '2026-10-25T08:00:00.000Z', 'thr_a'), await note(C, 'c2', '2026-10-31T01:00:00.000Z', 'thr_c'),
  ];
  const order = () => sortFieldPeople([...st.threads.values()].map((t): FieldPerson => ({
    fingerprint: t.thread_id, name: t.thread_id, threadId: t.thread_id, preview: '', lastAt: t.last_activity_at, sendable: true,
  }))).map((p) => p.name).join('>');
  for (const w of backlog) assert.ok(await accept(w, st.io));
  const settled = order();
  const stamps = JSON.stringify([...st.threads.values()].map((t) => [t.thread_id, t.last_activity_at]));
  for (const w of backlog) {
    assert.ok(await accept(w, st.io), 'redelivery accepted');
    assert.equal(order(), settled, `no reorder while re-processing ${w.note_id}`);
  }
  assert.equal(JSON.stringify([...st.threads.values()].map((t) => [t.thread_id, t.last_activity_at])), stamps, 'no thread activity changed');
});
