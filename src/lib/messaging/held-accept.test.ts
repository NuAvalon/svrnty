// src/lib/messaging/held-accept.test.ts: Freeze keep (hold, don't discard) at the acceptInboundNote seam.
// A note from a FROZEN contact (present in the book and blocked) is authenticated, opened through the SAME ratchet path and stored, marked held, so it can be
// kept as evidence. A stranger or a Removed contact is still dropped exactly as before. REAL TripleRatchet, REAL acceptInboundNote, REAL signed wires; only the
// stores are in memory (the io seam).
// Run: npx tsx --test src/lib/messaging/held-accept.test.ts
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
import { HOLD_CAP_PER_SENDER, clearedHeld, clearedHeldNote, heldSweepAction } from './held-note';
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
  const clock = { ms: null as number | null };   // the OWNER'S clock for the hold's stamps: null = the real one
  const io = {
    nowMs: () => clock.ms ?? Date.now(),
    putNote: async (n: NoteRecord) => { calls.putNote++; if (flags.failPut) throw new Error('store down'); notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { calls.putThread++; threads.set(t.thread_id, t); },
    // the REAL listThreads skips held threads; only the include-held reader returns them (the old mock returned everything from one reader, which hid F1)
    listThreads: async () => [...threads.values()].filter((t) => t.held !== true),
    listThreadsIncludingHeld: async () => [...threads.values()],
    getNote: async (nid: string) => notes.get(nid) ?? null,
    countHeldFrom: async (fp: string) => { calls.countHeld.push(fp); if (countFlags.throws) throw new Error('count unreadable'); return heldCounts.get(fp) ?? 0; },
  };
  const wireFor = (note_id: string, body: string, thread_id = 'thr', sent_at: string = new Date().toISOString(), extra: Record<string, unknown> = {}): Promise<NoteWireV0> =>
    signNoteWire({ type: NOTE_WIRE_TYPE, note_id, thread_id, from_fingerprint: id.fingerprint, sent_at, body, participant_kind: 'human', ...extra } as never,
      id.public_key, sender.secret_material.classicalPrivateKey, sender.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key);
  const frame = async (text: string) => (await sealDirectNote(ME, text, them, peerOf(me), theirIO.io))!;
  const accept = async (wire: NoteWireV0, o: { admitted?: boolean; frozen?: boolean } = {}) => {
    const reasons: string[] = []; let created = 0; let refused = 0;
    let r: NoteRecord | null = null, threw: unknown = null;
    try {
      r = await acceptInboundNote({
        wire, isAdmitted: async () => !!o.admitted,
        isFrozen: async () => { calls.isFrozen++; return !!o.frozen; },
        io: io as never, onDrop: (x: string) => reasons.push(x), onCreated: () => { created++; }, onRewriteRefused: () => { refused++; },
        openRatchet: (_f: string, body: string) => openDirectNoteStagedTyped(THEM, body, me, peerOf(them), myIO.io),
      } as never);
    } catch (e) { threw = e; }
    return { r, reasons, created, refused, threw };
  };
  return { id, me, peerOf: peerOf(them), myIO, notes, threads, calls, flags, heldCounts, countFlags, clock, wireFor, frame, accept };
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

// ── The O(1) held count, at the accept: what a REDEPOSIT and a failed WRITE do (real ratchet, real signed wires) ──────────────────────────────────────────────────────────────────────────
// The accept's half only. What the pipeline does with a 'ratchet-desync' is a separate, BOUNDED effect: the reason is HOLDABLE (sync/dead-letter.ts), so the consume layer keeps the envelope on the
// relay and writes a METADATA-ONLY dead-letter row (envelope id, first-seen time, reason, a fixed cause token, never frame text), capped at KEEP_MAX_COUNT (50) held envelopes per mailbox, 7 days,
// and ROW_MAX_PER_CONTACT (50) rows per sender. So a redeposit is not "no state change" system-wide; it is that bounded record and nothing else.
test('HR1 a REDEPOSITED over-cap frame (the identical signed wire, delivered again) fails at open as a desync: no NOTE is stored and the session does not move again; one count per delivery', async () => {
  const w = await world();
  w.heldCounts.set(w.id.fingerprint, HOLD_CAP_PER_SENDER);
  const wire = await w.wireFor('hr1', await w.frame('over the cap, then again'));
  const first = await w.accept(wire, { frozen: true });
  assert.equal(first.r, null);
  assert.deepEqual(first.reasons, ['not-in-book'], 'the first delivery is the ordinary over-cap drop');
  const afterFirst = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  const again = await w.accept(wire, { frozen: true });
  assert.equal(again.r, null);
  assert.equal(again.threw, null, 'a redeposit is a verdict, not an error: nothing retries it');
  assert.equal(again.created, 0, 'no creation, so no receipt');
  assert.deepEqual(again.reasons, ['ratchet-desync'], 'the open fails because the first delivery already advanced the session (a one-use message key): the sessions disagree, so it is a desync, a HOLDABLE reason (see above)');
  assert.equal(w.notes.size, 0, 'no note was stored');
  assert.equal(w.calls.putNote + w.calls.putThread, 0);
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM) ?? null), afterFirst, 'and the session did not move again');
  assert.equal(w.calls.countHeld.length, 2, 'the count is asked once per delivery (now a one-row read), before the open');
});

test('HW1 a note write that cannot commit THROWS before the session advances, and the same frame delivered again once the store works is stored: nothing lost, nothing half-written', async () => {
  // The pipeline's half is pinned in consume-mailbox-door.test.ts C5b: a note seam whose accept() throws is retryable: no record, not acked, still on the relay.
  const w = await world();
  const wire = await w.wireFor('hw1', await w.frame('held while the store fights'));
  const before = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  w.flags.failPut = true;
  const out = await w.accept(wire, { frozen: true });
  assert.ok(out.threw, 'the accept throws');
  assert.equal(w.notes.size, 0);
  assert.equal(out.created, 0);
  assert.deepEqual(out.reasons, [], 'not a drop: nothing was decided');
  assert.equal(JSON.stringify(w.myIO.rows.get(THEM) ?? null), before, 'the session did NOT advance (a staged open commits only after the note and thread are stored), so the redelivered frame still opens');
  w.flags.failPut = false;
  const retry = await w.accept(wire, { frozen: true });
  assert.equal(retry.r?.held, true, 'delivered again once the store works: stored held');
  assert.equal(retry.created, 1);
  assert.equal(w.notes.size, 1);
});

test('HW2 the store throws exactly this when its retries run out (so HW1 stands for the real failure): "note write kept losing the race: retry"', () => {
  const store = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
  assert.match(store, /throw new Error\('note write kept losing the race: retry'\)/);
  assert.match(store, /const NOTE_WRITE_ATTEMPTS = 8;/);
});

// ── the hold's age stamps (held_at, expiry_seen_at): from the OWNER'S clock only, never from the wire ─────────────────────────────────────────────────────────────────────────────────
const T0 = Date.parse('2026-06-01T12:00:00.000Z');
const DAYMS = 86_400_000;

test('HG1 a note is held with held_at = the OWNER\'S clock at that moment, and no expiry stamp (the sweep makes that)', async () => {
  const w = await world();
  w.clock.ms = T0;
  const out = await w.accept(await w.wireFor('g1', await w.frame('held now')), { frozen: true });
  assert.equal(out.r?.held, true);
  assert.equal(out.r?.held_at, new Date(T0).toISOString());
  assert.equal('expiry_seen_at' in out.r!, false);
  assert.equal(w.notes.get('g1')?.held_at, new Date(T0).toISOString(), 'and the STORED row carries it');
});

test('HG2 a wire that carries held_at, held and expiry_seen_at (sender-chosen, signed) sets NONE of them: the record has the local stamp, and does not expire at the next sweep', async () => {
  const w = await world();
  w.clock.ms = T0;
  const hostile = { held_at: '2000-01-01T00:00:00.000Z', held: true, expiry_seen_at: '2000-01-02T00:00:00.000Z' };
  const wire = await w.wireFor('g2', await w.frame('a hostile wire'), 'thr', '2000-01-01T00:00:00.000Z', hostile);
  assert.equal((wire as unknown as Record<string, unknown>).held_at, '2000-01-01T00:00:00.000Z', 'the wire the accept sees really carries the sender\'s stamps (so this test is not vacuous)');
  const out = await w.accept(wire, { frozen: true });
  assert.ok(out.r, `accepted (reasons ${JSON.stringify(out.reasons)})`);
  assert.equal(out.r!.held_at, new Date(T0).toISOString(), 'held_at is the owner\'s clock, not the wire\'s');
  assert.equal('expiry_seen_at' in out.r!, false, 'the sender\'s expiry stamp was not copied');
  assert.equal(heldSweepAction(out.r!, T0 + DAYMS), 'keep', 'a note the sender back-dated to 2000 does not expire at the next sweep');
  assert.equal(out.r!.sent_at, '2000-01-01T00:00:00.000Z', 'control: the sender\'s sent_at WAS taken as before (it is just not what the age runs from)');
});

test('HG3 an ADMITTED sender\'s note carries none of the three keys at all, even when the wire names them: an ordinary note is never given a hold stamp', async () => {
  const w = await world();
  const wire = await w.wireFor('g3', await w.frame('an ordinary note'), 'thr', new Date().toISOString(), { held_at: '2000-01-01T00:00:00.000Z', held: true, expiry_seen_at: '2000-01-02T00:00:00.000Z' });
  const out = await w.accept(wire, { admitted: true });
  assert.ok(out.r);
  for (const k of ['held', 'held_at', 'expiry_seen_at']) assert.equal(k in out.r!, false, `no ${k} key on an ordinary note`);
  for (const k of ['held', 'held_at', 'expiry_seen_at']) assert.equal(k in w.notes.get('g3')!, false, `and none on the stored row (${k})`);
});

test('HG4 a REDELIVERY of a note already held keeps the stamps it has: sending it again does not restart its age or its grace', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  w.clock.ms = T0;
  const a = await w.accept(await w.wireFor('g4', await w.frame('same words'), 'thr', sent), { frozen: true });
  assert.equal(a.r?.held_at, new Date(T0).toISOString());
  // the sweep (a later unlock) stamped it, and then the sender sends the same note again in a new frame, ten days later
  w.notes.set('g4', { ...w.notes.get('g4')!, expiry_seen_at: new Date(T0 + 2 * DAYMS).toISOString() });
  w.clock.ms = T0 + 10 * DAYMS;
  const b = await w.accept(await w.wireFor('g4', await w.frame('same words'), 'thr', sent), { frozen: true });
  assert.ok(b.r, `accepted (reasons ${JSON.stringify(b.reasons)}, threw ${String(b.threw)})`);
  assert.equal(b.r!.held_at, new Date(T0).toISOString(), 'held_at is still when it was FIRST held');
  assert.equal(b.r!.expiry_seen_at, new Date(T0 + 2 * DAYMS).toISOString(), 'and the sweep\'s mark is kept');
  assert.equal(w.notes.get('g4')?.held_at, new Date(T0).toISOString());
});

test('HG5 a note held BEFORE the field existed (no held_at) and then redelivered starts its clock now, and forgets a stale expiry stamp', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  w.clock.ms = T0;
  await w.accept(await w.wireFor('g5', await w.frame('legacy words'), 'thr', sent), { frozen: true });
  const legacy = { ...w.notes.get('g5')!, expiry_seen_at: new Date(T0 - DAYMS).toISOString() };
  delete (legacy as { held_at?: string }).held_at;
  w.notes.set('g5', legacy);
  w.clock.ms = T0 + 5 * DAYMS;
  const b = await w.accept(await w.wireFor('g5', await w.frame('legacy words'), 'thr', sent), { frozen: true });
  assert.ok(b.r, `accepted (reasons ${JSON.stringify(b.reasons)}, threw ${String(b.threw)})`);
  assert.equal(b.r!.held_at, new Date(T0 + 5 * DAYMS).toISOString());
  assert.equal('expiry_seen_at' in b.r!, false);
});

// ── the hold is the OWNER'S: an unblocked sender's redelivery never moves a held note out of the hold ──────────────────────────────────────────────────────────────────────────
test('HD1 an ADMITTED sender re-sending a note this device holds (a fresh frame, same words) is a DUPLICATE: the held row is byte-identical with its stamps, nothing is written, no receipt, no refusal signal, the session still advances', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  w.clock.ms = T0;
  const a = await w.accept(await w.wireFor('hd1', await w.frame('same words'), 'thr', sent), { frozen: true });
  assert.equal(a.r?.held, true);
  w.notes.set('hd1', { ...w.notes.get('hd1')!, expiry_seen_at: new Date(T0 + 2 * DAYMS).toISOString() });   // the sweep marked it
  const rowBefore = JSON.stringify(w.notes.get('hd1'));
  const threadsBefore = JSON.stringify([...w.threads.entries()]);
  const writesBefore = { putNote: w.calls.putNote, putThread: w.calls.putThread };
  const sessionBefore = JSON.stringify(w.myIO.rows.get(THEM) ?? null);
  w.clock.ms = T0 + 10 * DAYMS;
  const b = await w.accept(await w.wireFor('hd1', await w.frame('same words'), 'thr', sent), { admitted: true });
  assert.ok(b.r, `returned the stored note (reasons ${JSON.stringify(b.reasons)}, threw ${String(b.threw)})`);
  assert.equal(JSON.stringify(b.r), rowBefore, 'what comes back is the stored held row');
  assert.equal(JSON.stringify(w.notes.get('hd1')), rowBefore, 'the stored row is BYTE-IDENTICAL: still held, stamps unchanged');
  assert.equal(JSON.stringify([...w.threads.entries()]), threadsBefore, 'the thread rows are untouched');
  assert.deepEqual({ putNote: w.calls.putNote, putThread: w.calls.putThread }, writesBefore, 'NO write of any kind (so the held-count row, which only a note write moves, is untouched)');
  assert.equal(b.created, 0, 'no creation reported, so no receipt beyond what a duplicate gets');
  assert.equal(b.refused, 0, 'and no rewrite-refused signal: identical content is not an attack');
  assert.deepEqual(b.reasons, [], 'nothing dropped');
  assert.notEqual(JSON.stringify(w.myIO.rows.get(THEM) ?? null), sessionBefore, 'the session ADVANCED: the staged open was committed (session continuity is not content)');
  const c = await w.accept(await w.wireFor('hd1b', await w.frame('and the next one'), 'thr2'), { admitted: true });
  assert.ok(c.r, 'a later note from the same sender still opens (the session is not behind)');
  assert.equal('held' in c.r!, false, 'and an admitted sender\'s new note is an ordinary one');
});

test('HD2 an admitted sender re-sending a held note with CHANGED words is refused as a rewrite (the existing first-write-wins rule, with its signal), and the held row is left exactly as it was', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  w.clock.ms = T0;
  await w.accept(await w.wireFor('hd2', await w.frame('the real words'), 'thr', sent), { frozen: true });
  const rowBefore = JSON.stringify(w.notes.get('hd2'));
  const b = await w.accept(await w.wireFor('hd2', await w.frame('different words'), 'thr', sent), { admitted: true });
  assert.ok(b.r);
  assert.equal(b.refused, 1, 'refused as a rewrite, with the signal');
  assert.equal(JSON.stringify(w.notes.get('hd2')), rowBefore);
});

test('HD3 freeze, hold, stamp, RELEASE, re-freeze: the released note is dropped if re-sent (never re-held), and a NEW note gets a fresh LOCAL held_at and no expiry_seen_at', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  w.clock.ms = T0;
  await w.accept(await w.wireFor('hd3', await w.frame('kept words'), 'thr', sent), { frozen: true });
  w.notes.set('hd3', { ...w.notes.get('hd3')!, expiry_seen_at: new Date(T0 + 2 * DAYMS).toISOString() });
  // the owner RELEASES it (the store's release does exactly this to the row and its thread)
  const released = clearedHeldNote(w.notes.get('hd3')!);
  w.notes.set('hd3', released);
  w.threads.set('thr', clearedHeld(w.threads.get('thr')!));
  for (const k of ['held', 'held_at', 'expiry_seen_at']) assert.equal(k in w.notes.get('hd3')!, false, `released: no ${k}`);
  // the sender is frozen AGAIN and re-sends the same note
  w.clock.ms = T0 + 10 * DAYMS;
  const again = await w.accept(await w.wireFor('hd3', await w.frame('kept words'), 'thr', sent), { frozen: true });
  assert.equal(again.r, null, 'a released (ordinary) note re-sent by a frozen sender is dropped, as before: never re-held');
  assert.deepEqual(again.reasons, ['not-in-book']);
  assert.deepEqual(w.notes.get('hd3'), released, 'the released row is exactly as it was');
  // and a NEW note from the re-frozen sender is held with the NEW local time and no expiry mark
  const fresh = await w.accept(await w.wireFor('hd3b', await w.frame('a new note after the re-freeze'), 'thr', '2026-06-10T00:00:00.000Z'), { frozen: true });
  assert.equal(fresh.r?.held, true);
  assert.equal(fresh.r?.held_at, new Date(T0 + 10 * DAYMS).toISOString(), 'held_at is the NEW local time, not the old one');
  assert.equal('expiry_seen_at' in fresh.r!, false);
});

test('HD4 CONTROL: an admitted sender re-sending an ORDINARY note behaves exactly as before (the idempotent rewrite proceeds): only a HELD prior is protected', async () => {
  const w = await world();
  const sent = '2026-05-30T00:00:00.000Z';
  const a = await w.accept(await w.wireFor('hd4', await w.frame('ordinary words'), 'thr', sent), { admitted: true });
  assert.equal('held' in a.r!, false);
  const putsBefore = w.calls.putNote;
  const b = await w.accept(await w.wireFor('hd4', await w.frame('ordinary words'), 'thr', sent), { admitted: true });
  assert.ok(b.r);
  assert.equal(w.calls.putNote, putsBefore + 1, 'the ordinary redelivery is still written (idempotently), as it always was');
  assert.equal(b.refused, 0);
});

