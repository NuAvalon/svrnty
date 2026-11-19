// src/lib/messaging/held-accept.test.ts: Freeze keep (hold, don't discard) at the acceptInboundNote seam.
// A note from a FROZEN contact (present in the book and blocked) is authenticated, opened through the SAME ratchet path and stored, marked held, so it can be
// kept as evidence. A stranger or a Removed contact is still dropped exactly as before. REAL TripleRatchet, REAL acceptInboundNote, REAL signed wires; only the
// stores are in memory (the io seam).
// Run: npx tsx --test src/lib/messaging/held-accept.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { memIO } from './ratchet-test-io';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { HOLD_CAP_PER_SENDER } from './held-note';
import { NOTE_WIRE_TYPE } from './domains';
import { sealDirectNote, openDirectNoteStagedTyped } from './direct-session';
import type { NoteRecord, NoteThread, NoteWireV0 } from './types';

const ident = (): RatchetIdentity => {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
};
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const ME = 'fp-me', THEM = 'fp-them';

async function world() {
  const [me, them] = [ident(), ident()];
  const sender = await mintHeadlessAgent({ throwaway: true });
  const id = sender.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  const myIO = memIO();
  const theirIO = memIO();
  const notes = new Map<string, NoteRecord>(), threads = new Map<string, NoteThread>();
  const calls = { putThread: 0, putNote: 0, isFrozen: 0, countHeld: [] as string[] };
  const heldCounts = new Map<string, number>();
  const countFlags = { throws: false };
  const flags = { failPut: false };
  const io = {
    putNote: async (n: NoteRecord) => { calls.putNote++; if (flags.failPut) throw new Error('store down'); notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { calls.putThread++; threads.set(t.thread_id, t); },
    // the REAL listThreads skips held threads; only the include-held reader returns them (the old mock returned everything from one reader, which hid F1)
    listThreads: async () => [...threads.values()].filter((t) => t.held !== true),
    listThreadsIncludingHeld: async () => [...threads.values()],
    getNote: async (nid: string) => notes.get(nid) ?? null,
    countHeldFrom: async (fp: string) => { calls.countHeld.push(fp); if (countFlags.throws) throw new Error('count unreadable'); return heldCounts.get(fp) ?? 0; },
  };
  const wireFor = (note_id: string, body: string, thread_id = 'thr'): Promise<NoteWireV0> =>
    signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id, from_fingerprint: id.fingerprint, sent_at: new Date().toISOString(), body, participant_kind: 'human' },
      id.public_key, sender.secret_material.classicalPrivateKey, sender.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key);
  const frame = async (text: string) => (await sealDirectNote(ME, text, them, peerOf(me), theirIO.io))!;
  const accept = async (wire: NoteWireV0, o: { admitted?: boolean; frozen?: boolean } = {}) => {
    const reasons: string[] = []; let created = 0;
    let r: NoteRecord | null = null, threw: unknown = null;
    try {
      r = await acceptInboundNote({
        wire, isAdmitted: async () => !!o.admitted,
        isFrozen: async () => { calls.isFrozen++; return !!o.frozen; },
        io: io as never, onDrop: (x: string) => reasons.push(x), onCreated: () => { created++; },
        openRatchet: (_f: string, body: string) => openDirectNoteStagedTyped(THEM, body, me, peerOf(them), myIO.io),
      } as never);
    } catch (e) { threw = e; }
    return { r, reasons, created, threw };
  };
  return { id, me, peerOf: peerOf(them), myIO, notes, threads, calls, flags, heldCounts, countFlags, wireFor, frame, accept };
}

test('H1 a FROZEN contact\'s note is stored, marked held, with the right body: not dropped, no drop reason', async () => {
  const w = await world();
  const out = await w.accept(await w.wireFor('n1', await w.frame('hello from a frozen contact')), { frozen: true });
  assert.ok(out.r, 'a held note comes back as a record (not null)');
  assert.equal(out.r!.held, true, 'the record is marked held');
  assert.equal(out.r!.body, 'hello from a frozen contact', 'opened through the real ratchet: the stored body is the plaintext');
  assert.equal(out.r!.direction, 'inbound');
  assert.deepEqual(out.reasons, [], 'nothing was dropped');
  assert.equal(w.notes.get('n1')?.held, true, 'and the stored row carries the flag');
  assert.equal(out.created, 1, 'told once that this call created the row (the receipt layer decides what to do with it)');
});

test('H2 a STRANGER (not admitted, not frozen) is dropped exactly as before: not-in-book, nothing stored, session untouched', async () => {
  const w = await world();
  const before = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  const out = await w.accept(await w.wireFor('n2', await w.frame('hi')), { admitted: false, frozen: false });
  assert.equal(out.r, null);
  assert.deepEqual(out.reasons, ['not-in-book']);
  assert.equal(w.notes.size, 0);
  assert.equal(w.calls.putNote + w.calls.putThread, 0, 'no store write of any kind');
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM) ?? null), before, 'the ratchet was never opened for a stranger');
});

test('H3 an ADMITTED contact never asks the frozen question, and its record has no held key at all', async () => {
  const w = await world();
  const out = await w.accept(await w.wireFor('n3', await w.frame('normal')), { admitted: true, frozen: true });
  assert.ok(out.r);
  assert.equal(w.calls.isFrozen, 0, 'isFrozen is consulted only when isAdmitted said no');
  assert.equal('held' in out.r!, false, 'an ordinary note has no held key (nothing distinguishes it by shape)');
});

test('H4 D5 a held note on an EXISTING thread writes NO thread row (a reorder would be a tell)', async () => {
  const w = await world();
  const t0: NoteThread = { thread_id: 'thr', kind: 'direct', participants: [{ fingerprint: w.id.fingerprint, kind: 'human', display_name: 'frozen sender' }] /* the sender is IN the thread, as in every real one (an empty list would make them a non-participant) */, created_at: '2026-01-01T00:00:00.000Z', last_activity_at: '2026-01-01T00:00:00.000Z', retention: { expires_at: null } } as never;
  w.threads.set('thr', t0);
  const before = JSON.stringify(w.threads.get('thr'));
  const out = await w.accept(await w.wireFor('n4', await w.frame('held on an existing thread')), { frozen: true });
  assert.equal(out.r?.held, true);
  assert.equal(w.calls.putThread, 0, 'putThread is never called on the held path when the thread exists');
  assert.equal(JSON.stringify(w.threads.get('thr')), before, 'the thread row is byte-identical (last_activity_at did not move)');
});

test('H11 F1 a SECOND held note in the same held thread writes NO thread row: created_at and last_activity_at stay the first note\'s', async () => {
  const w = await world();
  const a = await w.accept(await w.wireFor('n11a', await w.frame('first held'), 'thr-h'), { frozen: true });
  assert.equal(a.r?.held, true);
  assert.equal(w.calls.putThread, 1);
  const first = JSON.stringify(w.threads.get('thr-h'));
  await new Promise((r) => setTimeout(r, 5));   // the second note must carry a LATER sent_at, or an overwrite could not be seen
  const b = await w.accept(await w.wireFor('n11b', await w.frame('second held'), 'thr-h'), { frozen: true });
  assert.equal(b.r?.held, true);
  assert.equal(w.calls.putThread, 1, 'still ONE putThread in total: the accept path found the held thread');
  assert.equal(JSON.stringify(w.threads.get('thr-h')), first, 'the held thread row is byte-identical');
});

test('H12 F1 after an UNBLOCK the next note on the SAME held thread makes the row an ordinary thread again: flag gone, created_at kept, the earlier note stays held', async () => {
  const w = await world();
  await w.accept(await w.wireFor('n12a', await w.frame('held while blocked'), 'thr-u'), { frozen: true });
  const created = w.threads.get('thr-u')!.created_at;
  await new Promise((r) => setTimeout(r, 5));
  const out = await w.accept(await w.wireFor('n12b', await w.frame('after unblock'), 'thr-u'), { admitted: true });
  assert.equal(out.r?.held, undefined, 'the new note is an ordinary note');
  const t = w.threads.get('thr-u')!;
  assert.equal('held' in t, false, 'the thread row is an ordinary thread again');
  assert.equal(t.created_at, created, 'created_at is the first note\'s: kept');
  assert.equal(w.notes.get('n12a')?.held, true, 'the note held while blocked stays held (each note keeps its own flag)');
  assert.equal(w.notes.get('n12b')?.held, undefined);
});

test('H5 D5 a held note with NO thread yet writes ONE thread row, flagged held, so the store looks the same and the default reader can filter it', async () => {
  const w = await world();
  const out = await w.accept(await w.wireFor('n5', await w.frame('first ever note, from a frozen contact'), 'thr-new'), { frozen: true });
  assert.equal(out.r?.held, true);
  assert.equal(w.calls.putThread, 1);
  assert.equal(w.threads.get('thr-new')?.held, true, 'the thread exists only because of held notes: flagged held');
});

test('H6 D9 the held note commits the ratchet advance: a LATER normal note from the same contact still opens', async () => {
  const w = await world();
  const f1 = await w.frame('one'), f2 = await w.frame('two');
  const before = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  const first = await w.accept(await w.wireFor('a1', f1), { frozen: true });
  assert.equal(first.r?.held, true);
  assert.notEqual(JSON.stringify(w.myIO.rows.get(THEM) ?? null), before, 'the session advanced, exactly as for a normal note');
  const second = await w.accept(await w.wireFor('a2', f2), { admitted: true });   // unfrozen since: now an ordinary contact
  assert.ok(second.r, 'the next frame still opens (it would not if the held note had skipped the advance)');
  assert.equal(second.r!.body, 'two');
  assert.equal('held' in second.r!, false);
});

test('H7 D8 a staging failure THROWS (retryable): nothing acked/created, the session NOT advanced; the retry then stores it held, once', async () => {
  const w = await world();
  const wire = await w.wireFor('n7', await w.frame('retry me'));
  const before = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  w.flags.failPut = true;
  const bad = await w.accept(wire, { frozen: true });
  assert.ok(bad.threw, 'a staging throw reaches the caller, so the envelope stays on the relay');
  assert.equal(bad.created, 0);
  assert.equal(w.notes.size, 0);
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM) ?? null), before, 'the session is un-advanced, so the retry re-opens the frame');
  w.flags.failPut = false;
  const good = await w.accept(wire, { frozen: true });
  assert.equal(good.r?.held, true);
  assert.equal(good.created, 1);
  assert.equal(w.notes.size, 1);
});

test('H8 a FORGED or unsigned note from a frozen contact is still dropped unverified: holding never stores an unauthenticated note', async () => {
  const w = await world();
  const good = await w.wireFor('n8', await w.frame('real'));
  const forged = { ...good, body: good.body + 'x' } as NoteWireV0;
  const out = await w.accept(forged, { frozen: true });
  assert.equal(out.r, null);
  assert.deepEqual(out.reasons, ['unverified']);
  assert.equal(w.notes.size, 0);
  assert.equal(w.calls.isFrozen, 0, 'authentication comes first: the frozen question is never reached');
});

test('H9 a frozen contact cannot overwrite OUR outbound row by reusing its note_id: refused, the outbound row byte-identical', async () => {
  const w = await world();
  const mine: NoteRecord = { note_id: 'n9', thread_id: 'thr', direction: 'outbound', from_fingerprint: 'fp-me', to_fingerprints: [w.id.fingerprint], sent_at: '2026-01-01T00:00:00.000Z', body: 'my own words', participant_kind: 'human', retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE } as never;
  w.notes.set('n9', mine);
  const before = JSON.stringify(w.notes.get('n9'));
  const out = await w.accept(await w.wireFor('n9', await w.frame('try to replace it')), { frozen: true });
  assert.equal(out.r, null);
  assert.equal(JSON.stringify(w.notes.get('n9')), before);
});

test('H10 a REDELIVERED held note returns the stored held row: one row, created once', async () => {
  const w = await world();
  const wire = await w.wireFor('n10', await w.frame('twice'));
  const a = await w.accept(wire, { frozen: true });
  const b = await w.accept(wire, { frozen: true });
  assert.equal(a.r?.held, true);
  assert.ok(b.r, 'a completed delivery whose ack never landed is not a loss');
  assert.equal(b.r!.held, true, 'and it is still the held row');
  assert.equal(w.notes.size, 1);
  assert.equal(a.created + b.created, 1, 'the receipt layer is told of ONE creation');
});

// ── The per-sender hold cap (ruled (a), provisional until Peter sets the number): past it the note is NOT stored and gets NO receipt: it is today's not-in-book drop, byte for byte.
test('HC1 the cap is a NAMED constant, flagged as Peter\'s number, default 500', () => {
  assert.equal(HOLD_CAP_PER_SENDER, 500);
});

test('HC2 at cap-1 held rows the next note IS stored held and the creation is reported (the receipt layer may answer it)', async () => {
  const w = await world();
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER - 1);
  const out = await w.accept(await w.wireFor('c2', await w.frame('the last one that fits')), { frozen: true });
  assert.equal(out.r?.held, true);
  assert.equal(out.created, 1);
});

test('HC3 AT the cap the note is NOT stored and no creation is reported (so no receipt); the relay-visible drop is a stranger\'s (not-in-book) and the ratchet advance IS committed', async () => {
  const w = await world();
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  const before = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  const out = await w.accept(await w.wireFor('c3', await w.frame('one too many')), { frozen: true });
  assert.equal(out.r, null);
  assert.deepEqual(out.reasons, ['not-in-book'], 'the SAME drop reason as a stranger: nothing new for a sender to tell');
  assert.equal(out.created, 0);
  assert.equal(w.notes.size, 0);
  assert.equal(w.calls.putNote + w.calls.putThread, 0);
  assert.notEqual(JSON.stringify(w.myIO.rows.get(THEM) ?? null), before, 'session continuity is not content: the advance is committed past the cap (else an unfreeze later breaks the session, an unexplained tell)');
});

test('HC4 the count is asked for THIS SENDER, and only on the frozen path (never for an admitted contact or a stranger)', async () => {
  const w = await world();
  await w.accept(await w.wireFor('c4a', await w.frame('x')), { admitted: true });
  await w.accept(await w.wireFor('c4b', await w.frame('y')), { admitted: false, frozen: false });
  assert.deepEqual(w.calls.countHeld, [], 'no count for an admitted contact or a stranger');
  await w.accept(await w.wireFor('c4c', await w.frame('z')), { frozen: true });
  assert.deepEqual(w.calls.countHeld, [w.id.fingerprint], 'asked once, for the sender');
});

test('HC5 a count that CANNOT be read throws (retryable, the envelope stays on the relay): never "store without a cap", never "drop"', async () => {
  const w = await world();
  w.countFlags.throws = true;
  const out = await w.accept(await w.wireFor('c5', await w.frame('retry')), { frozen: true });
  assert.ok(out.threw);
  assert.equal(w.notes.size, 0);
  assert.deepEqual(out.reasons, [], 'not a drop: nothing was decided');
});

test('HC6 CONTINUITY: past the cap, then UNFROZEN, the very next frame still opens and nothing the sender wrote was kept (the double ratchet tolerates one skipped frame, so HC3 is the pin that the advance is committed)', async () => {
  const w = await world();
  const f1 = await w.frame('over the cap'), f2 = await w.frame('after the unfreeze');
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  const capped = await w.accept(await w.wireFor('c6a', f1), { frozen: true });
  assert.equal(capped.r, null);
  assert.equal(w.notes.size, 0, 'nothing the sender wrote was kept');
  const next = await w.accept(await w.wireFor('c6b', f2), { admitted: true });
  assert.ok(next.r, 'the session was not left one step behind');
  assert.equal(next.r!.body, 'after the unfreeze');
});

test('HC7 a REDELIVERY of an already-held note is NOT capped, even when the sender is now at the cap: it returns the stored held row', async () => {
  const w = await world();
  const wire = await w.wireFor('c7', await w.frame('kept before the cap was reached'));
  const first = await w.accept(wire, { frozen: true });
  assert.equal(first.r?.held, true);
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  const again = await w.accept(wire, { frozen: true });
  assert.ok(again.r, 'a completed delivery is never turned into a loss by the cap');
  assert.equal(again.r!.held, true);
  assert.equal(w.notes.size, 1);
  assert.equal(again.created, 0);
});

test('HC8 a note stored as ORDINARY before the sender was frozen is never rewritten as held by a redelivery: it is dropped as today and the visible row is untouched', async () => {
  const w = await world();
  const old: NoteRecord = { note_id: 'c8', thread_id: 'thr', direction: 'inbound', from_fingerprint: w.id.fingerprint, to_fingerprints: [], sent_at: '2026-01-01T00:00:00.000Z', body: 'an old note I could always read', participant_kind: 'human', retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE } as never;
  w.notes.set('c8', old);
  const before = JSON.stringify(w.notes.get('c8'));
  const sessionBefore = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  const out = await w.accept(await w.wireFor('c8', await w.frame('x')), { frozen: true });
  assert.equal(out.r, null);
  assert.deepEqual(out.reasons, ['not-in-book']);
  assert.equal(JSON.stringify(w.notes.get('c8')), before, 'the visible note is exactly as it was (it did not become held and vanish)');
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM) ?? null), sessionBefore, 'dropped before any ratchet work, like today');
  assert.equal(w.calls.putNote, 0);
});

test('HC9 a capped note still tells the session callbacks what a normal accept tells them (the frame opened), and nothing else is created', async () => {
  const w = await world();
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  let opened = 0;
  const wire = await w.wireFor('c9', await w.frame('over'));
  const r = await acceptInboundNote({
    wire, isAdmitted: async () => false, isFrozen: async () => true, io: { putNote: async () => { w.calls.putNote++; }, putThread: async () => { w.calls.putThread++; }, listThreads: async () => [], getNote: async () => null, countHeldFrom: async () => HOLD_CAP_PER_SENDER } as never,
    onFrameOpened: async () => { opened++; }, onDrop: () => {}, onCreated: () => { throw new Error('a capped note must not report a creation'); },
    openRatchet: (_f: string, body: string) => openDirectNoteStagedTyped(THEM, body, w.me, w.peerOf, w.myIO.io),
  } as never);
  assert.equal(r, null);
  assert.equal(opened, 1);
  assert.equal(w.calls.putNote + w.calls.putThread, 0);
});

test('HC7b the held-prior rule itself, with a PLAIN body (no ratchet to fall back on): a redelivered held note at the cap returns the stored held row, it is not capped', async () => {
  const w = await world();
  const wire = await w.wireFor('c7b', 'a plain body, no ratchet frame');
  const first = await w.accept(wire, { frozen: true });
  assert.equal(first.r?.held, true);
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  const again = await w.accept(wire, { frozen: true });
  assert.ok(again.r, 'not dropped by the cap: it is a note already kept');
  assert.equal(again.r!.held, true);
  assert.equal(w.notes.size, 1);
  assert.equal(again.created, 0);
  assert.deepEqual(again.reasons, []);
});
