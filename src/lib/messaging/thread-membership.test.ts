// src/lib/messaging/thread-membership.test.ts: an inbound note may only join an existing thread its sender is a participant of.
// acceptInboundNote used to find the thread by the SENDER-chosen thread_id and join it whoever the sender was, so an admitted contact who learned another thread's id could
// file notes into it (and, for a held thread, make it reappear). Now: a sender who is NOT a participant of the thread they name gets a FRESH local thread, never the claimed one;
// later notes from the same sender under the same claimed id join that fresh thread (a local, bounded alias), so one real conversation is not split. A real participant always joins
// their own thread and the alias is never consulted for them. REAL TripleRatchet, REAL acceptInboundNote, REAL signed wires; only the stores are in memory (the io seam).
// Run: npx tsx --test src/lib/messaging/thread-membership.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { memIO } from './ratchet-test-io';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import { sealDirectNote, openDirectNoteStagedTyped } from './direct-session';
import { SETTINGS_ROW_PREFIXES, isAllowedSettingsRowKey } from './settings-row-keys';
import type { NoteRecord, NoteThread, NoteWireV0 } from './types';

const ident = (): RatchetIdentity => {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
};
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const ME = 'fp-me', THEM = 'fp-them';
const OTHER = 'ab'.repeat(32); // someone else's fingerprint (a participant of the thread being targeted)

type AliasPort = { resolve(sender: string, claimed: string): Promise<string | null>; remember(sender: string, claimed: string, local: string): Promise<void> };

async function world() {
  const [me, them] = [ident(), ident()];
  const sender = await mintHeadlessAgent({ throwaway: true });
  const id = sender.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  const myIO = memIO();
  const theirIO = memIO();
  const notes = new Map<string, NoteRecord>(), threads = new Map<string, NoteThread>();
  const calls = { putThread: [] as string[], aliasRemember: 0 };
  const io = {
    putNote: async (n: NoteRecord) => { notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { calls.putThread.push(t.thread_id); threads.set(t.thread_id, t); },
    listThreads: async () => [...threads.values()].filter((t) => t.held !== true),
    listThreadsIncludingHeld: async () => [...threads.values()],
    getNote: async (nid: string) => notes.get(nid) ?? null,
    countHeldFrom: async () => 0,
  };
  // The alias table in memory (the real one is a sealed row in the notes store); `forget` simulates eviction, `throwOnResolve` a locked store.
  const table = new Map<string, string>();
  const flags = { forget: false, throwOnResolve: false };
  const aliases: AliasPort = {
    resolve: async (s, c) => { if (flags.throwOnResolve) throw new Error('notes store locked'); return flags.forget ? null : (table.get(`${s.toLowerCase()}|${c}`) ?? null); },
    remember: async (s, c, l) => { calls.aliasRemember++; if (!flags.forget) table.set(`${s.toLowerCase()}|${c}`, l); },
  };
  const wireFor = (note_id: string, body: string, thread_id: string, sent_at: string = new Date().toISOString()): Promise<NoteWireV0> =>
    signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id, from_fingerprint: id.fingerprint, sent_at, body, participant_kind: 'human' },
      id.public_key, sender.secret_material.classicalPrivateKey, sender.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key);
  const frame = async (text: string) => (await sealDirectNote(ME, text, them, peerOf(me), theirIO.io))!;
  const accept = async (wire: NoteWireV0, o: { frozen?: boolean; withAliases?: boolean } = {}) => {
    const reasons: string[] = []; let created = 0, rewriteRefused = 0;
    let r: NoteRecord | null = null, threw: unknown = null;
    try {
      r = await acceptInboundNote({
        wire, isAdmitted: async () => !o.frozen, isFrozen: async () => !!o.frozen,
        io: io as never, ...(o.withAliases === false ? {} : { threadAliases: aliases }),
        onDrop: (x: string) => reasons.push(x), onCreated: () => { created++; }, onRewriteRefused: () => { rewriteRefused++; },
        openRatchet: (_f: string, body: string) => openDirectNoteStagedTyped(THEM, body, me, peerOf(them), myIO.io),
      } as never);
    } catch (e) { threw = e; }
    return { r, reasons, created, rewriteRefused, threw };
  };
  const seedThread = (thread_id: string, participantFps: string[], extra: Partial<NoteThread> = {}): NoteThread => {
    const t: NoteThread = {
      thread_id, kind: 'direct', created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-01T00:00:00.000Z', retention: { expires_at: null },
      participants: participantFps.map((fingerprint) => ({ fingerprint, kind: 'human', display_name: fingerprint.slice(0, 8) })), ...extra,
    } as NoteThread;
    threads.set(thread_id, t);
    return t;
  };
  return { id, notes, threads, calls, flags, table, wireFor, frame, accept, seedThread };
}

test('T1 a sender who is NOT a participant of the VISIBLE thread they name gets a fresh thread; the original is byte-identical', async () => {
  const w = await world();
  w.seedThread('T1', [OTHER]);
  const before = JSON.stringify(w.threads.get('T1'));
  const out = await w.accept(await w.wireFor('n1', await w.frame('hello'), 'T1'));
  assert.ok(out.r, 'the note is stored (the sender is admitted: nothing is dropped)');
  assert.notEqual(out.r!.thread_id, 'T1', 'it never joins the claimed thread');
  assert.equal(JSON.stringify(w.threads.get('T1')), before, 'the original thread row is untouched (last_activity_at did not move)');
  assert.ok(w.threads.has(out.r!.thread_id), 'a fresh thread exists for it');
  assert.deepEqual(w.threads.get(out.r!.thread_id)!.participants.map((p) => p.fingerprint), [w.id.fingerprint], 'whose participant is the sender');
  assert.deepEqual(w.calls.putThread, [out.r!.thread_id], 'the only thread write is the new one');
});

test('T2 a non-participant naming a HELD thread: new thread, the held thread stays held and unchanged (they cannot un-hold it)', async () => {
  const w = await world();
  w.seedThread('T2', [OTHER], { held: true });
  const before = JSON.stringify(w.threads.get('T2'));
  const out = await w.accept(await w.wireFor('n2', await w.frame('knock knock'), 'T2'));
  assert.ok(out.r);
  assert.notEqual(out.r!.thread_id, 'T2');
  assert.equal(JSON.stringify(w.threads.get('T2')), before, 'the held thread is byte-identical: still held, not re-surfaced');
  assert.equal(w.threads.get('T2')!.held, true);
  assert.equal(w.threads.get(out.r!.thread_id)!.held, undefined, 'the sender is admitted, so the fresh thread is an ordinary one');
});

test('T2b a FROZEN non-participant naming a visible or held thread: the fresh thread is HELD, the original untouched', async () => {
  const w = await world();
  w.seedThread('T2b', [OTHER]);
  const before = JSON.stringify(w.threads.get('T2b'));
  const out = await w.accept(await w.wireFor('n2b', await w.frame('held one'), 'T2b'), { frozen: true });
  assert.ok(out.r);
  assert.equal(out.r!.held, true);
  assert.notEqual(out.r!.thread_id, 'T2b');
  assert.equal(JSON.stringify(w.threads.get('T2b')), before);
  assert.equal(w.threads.get(out.r!.thread_id)!.held, true, 'a held note makes a held thread, as for any held note');
});

test('T3 CONTROL: a real participant still joins their own thread, case-insensitively, and the alias is never consulted for them', async () => {
  const w = await world();
  w.seedThread('T3', [w.id.fingerprint.toUpperCase()]);
  const wire = await w.wireFor('n3', await w.frame('mine'), 'T3');
  const out = await w.accept(wire);
  assert.ok(out.r);
  assert.equal(out.r!.thread_id, 'T3', 'a member joins their own thread');
  assert.deepEqual(w.calls.putThread, ['T3']);
  assert.equal(w.calls.aliasRemember, 0, 'no alias is written for a member');
});

test('T3b an UNKNOWN thread id is still created under the claimed id, as before (a stranger-free path: nothing is aliased)', async () => {
  const w = await world();
  const out = await w.accept(await w.wireFor('n3b', await w.frame('first'), 'brand-new'));
  assert.equal(out.r?.thread_id, 'brand-new');
  assert.equal(w.calls.aliasRemember, 0);
});

test('T4 the same non-participant sends TWO notes under the same claimed id: ONE new thread holds both, the original is untouched', async () => {
  const w = await world();
  w.seedThread('T4', [OTHER]);
  const before = JSON.stringify(w.threads.get('T4'));
  const a = await w.accept(await w.wireFor('n4a', await w.frame('one'), 'T4'));
  const b = await w.accept(await w.wireFor('n4b', await w.frame('two'), 'T4'));
  assert.ok(a.r && b.r);
  assert.equal(a.r!.thread_id, b.r!.thread_id, 'both notes are in the same fresh thread');
  assert.notEqual(a.r!.thread_id, 'T4');
  assert.equal(JSON.stringify(w.threads.get('T4')), before);
  assert.equal([...w.threads.keys()].filter((k) => k !== 'T4').length, 1, 'exactly one new thread exists');
});

test('T5 after the alias is EVICTED the next note makes another fresh thread, and NEVER joins the original', async () => {
  const w = await world();
  w.seedThread('T5', [OTHER]);
  const before = JSON.stringify(w.threads.get('T5'));
  w.flags.forget = true;
  const a = await w.accept(await w.wireFor('n5a', await w.frame('one'), 'T5'));
  const b = await w.accept(await w.wireFor('n5b', await w.frame('two'), 'T5'));
  assert.ok(a.r && b.r);
  assert.notEqual(a.r!.thread_id, 'T5');
  assert.notEqual(b.r!.thread_id, 'T5');
  assert.equal(JSON.stringify(w.threads.get('T5')), before, 'degraded to a split, never a join');
});

test('T6 the sender-visible result is the same for a KNOWN thread id and an UNKNOWN one (stored, created once, nothing dropped, no refused rewrite); a later reply by the owner is the stated bound', async () => {
  const known = await world(); known.seedThread('K', [OTHER]);
  const unknown = await world();
  const a = await known.accept(await known.wireFor('o1', await known.frame('x'), 'K'));
  const b = await unknown.accept(await unknown.wireFor('o1', await unknown.frame('x'), 'U'));
  const shape = (o: typeof a) => ({ stored: !!o.r, created: o.created, drops: o.reasons, rewrite: o.rewriteRefused, threw: !!o.threw, held: o.r?.held ?? false });
  assert.deepEqual(shape(a), shape(b));
});

// A real redelivery that REACHES the first-write-wins check: the same note (same id, body and signed time) arriving again as a FRESH ratchet frame (a duplicate through a second relay).
// (Delivering the very same frame twice never gets that far: its key is spent, so the stored note is returned first.)
test('T7 a REDELIVERY of the same non-participant note (a fresh frame, same id/body/time) is idempotent: one note, one thread, no refused-rewrite', async () => {
  const w = await world();
  w.seedThread('T7', [OTHER]);
  const SENT = '2026-02-02T10:00:00.000Z';
  const first = await w.accept(await w.wireFor('n7', await w.frame('once'), 'T7', SENT));
  assert.ok(first.r);
  const again = await w.accept(await w.wireFor('n7', await w.frame('once'), 'T7', SENT));
  assert.equal(again.rewriteRefused, 0, 'not mistaken for a rewrite');
  assert.equal(again.r!.thread_id, first.r!.thread_id, 'it finds the same fresh thread');
  assert.equal(w.notes.size, 1);
  assert.equal([...w.threads.keys()].filter((k) => k !== 'T7').length, 1);
});

test('T7b the same redelivery with the ALIAS LOST still finds the note\'s own fresh thread (no second thread, no refused-rewrite)', async () => {
  const w = await world();
  w.seedThread('T7b', [OTHER]);
  w.flags.forget = true; // the alias is never found (evicted, or its write failed)
  const SENT = '2026-02-02T11:00:00.000Z';
  const first = await w.accept(await w.wireFor('n7b', await w.frame('once'), 'T7b', SENT));
  assert.ok(first.r);
  const again = await w.accept(await w.wireFor('n7b', await w.frame('once'), 'T7b', SENT));
  assert.equal(again.rewriteRefused, 0);
  assert.equal(again.r!.thread_id, first.r!.thread_id);
  assert.equal([...w.threads.keys()].filter((k) => k !== 'T7b').length, 1);
});

test('T8 a locked alias store THROWS (the note waits for a retry); it never falls back to joining the original', async () => {
  const w = await world();
  w.seedThread('T8', [OTHER]);
  const before = JSON.stringify(w.threads.get('T8'));
  w.flags.throwOnResolve = true;
  const out = await w.accept(await w.wireFor('n8', await w.frame('x'), 'T8'));
  assert.ok(out.threw, 'fail closed: retryable');
  assert.equal(w.notes.size, 0);
  assert.equal(JSON.stringify(w.threads.get('T8')), before);
});

test('T9 WITHOUT an alias port (legacy callers, tests) a non-participant still never joins: each note gets its own fresh thread', async () => {
  const w = await world();
  w.seedThread('T9', [OTHER]);
  const before = JSON.stringify(w.threads.get('T9'));
  const out = await w.accept(await w.wireFor('n9', await w.frame('x'), 'T9'), { withAliases: false });
  assert.ok(out.r);
  assert.notEqual(out.r!.thread_id, 'T9');
  assert.equal(JSON.stringify(w.threads.get('T9')), before);
});

test('T10 PIN: the alias rows live under their own allowed settings prefix (a deliberate edit of the row-key pin), and the live note seam passes the real port', () => {
  assert.ok((SETTINGS_ROW_PREFIXES as readonly string[]).includes('thread_alias:'));
  assert.equal(isAllowedSettingsRowKey(`thread_alias:${'ab'.repeat(32)}`), true);
  assert.equal(isAllowedSettingsRowKey('thread_alias:'), false);
  const seam = readFileSync(new URL('../sync/live-book-poll.ts', import.meta.url), 'utf8');
  assert.match(seam, /threadAliases/, 'the live seam wires the alias port');
});

test('T11 the alias is re-checked at use: a mapped thread that exists and does NOT list the sender is never joined, and a mapping back at the CLAIMED thread is not used either; a fresh thread is made and the row is overwritten', async () => {
  for (const target of ['T11-by', 'T11']) {
    const w = await world();
    w.seedThread('T11', [OTHER]);
    w.seedThread('T11-by', [OTHER]);
    const key = `${w.id.fingerprint.toLowerCase()}|T11`;
    w.table.set(key, target); // a wrong row: a keying bug, or a tampered store
    const existing = () => JSON.stringify([w.threads.get('T11'), w.threads.get('T11-by')]);
    const before = existing();
    const a = await w.accept(await w.wireFor('n11a', await w.frame('one'), 'T11'));
    assert.ok(a.r, target);
    assert.ok(a.r!.thread_id !== 'T11' && a.r!.thread_id !== 'T11-by', `never joins ${target}`);
    assert.equal(existing(), before, 'both existing threads are untouched');
    assert.deepEqual(w.threads.get(a.r!.thread_id)!.participants.map((p) => p.fingerprint), [w.id.fingerprint]);
    assert.equal(w.table.get(key), a.r!.thread_id, 'the wrong alias is overwritten with the fresh thread');
    const b = await w.accept(await w.wireFor('n11b', await w.frame('two'), 'T11'));
    assert.equal(b.r!.thread_id, a.r!.thread_id, 'the next note joins the fresh thread');
  }
});
