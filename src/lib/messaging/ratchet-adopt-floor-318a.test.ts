// src/lib/messaging/ratchet-adopt-floor-318a.test.ts
//
// L-318a (Archie lane:svrnty #3263, Flint #3266, task #739): the adopt replay guard must not depend on note retention. The REAL receive seam
// (acceptInboundNote), REAL ratchet crypto, REAL note signing and the real policy builder; the only fakes are the storages (session rows, notes,
// threads) and the floor row, which the test wires exactly the way live-book-poll does (adoptedFloorAt + onSessionStarted).
//   F1  THE HOLE (control, no floor wired): the user deletes the conversation, a replay of the first frame that created the session is ADOPTED.
//   F2  with the floor: the same replay is REFUSED, the session is byte-identical, nothing is stored.
//   F3  the floor RISES with an adoption (a peer's reset), and then replays of BOTH the old and the new first frame are refused after a delete.
//   F4  a continuation never touches the floor; a LATER reset (signed newer than the floor) is still adopted (the fix must not over-hold).
//   F5  a far-future floor is ignored (no lockout), an unreadable floor row means NO, a garbage floor is skipped; a throwing floor writer cannot undo a stored note.
//   F6  the pure pieces: raisedFloor only rises, parseAdoptFloorRow is strict, the key is built from validated hex, the prefix is allowed.
//   F7  STATIC: live-book-poll wires the floor reader into the policy and the writer into onSessionStarted.
// Run: npx tsx --test src/lib/messaging/ratchet-adopt-floor-318a.test.ts
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
import { buildAdoptFirstFrame, FUTURE_SLACK_MS } from './session-adopt-policy';
import { ADOPT_FLOOR_PREFIX, adoptFloorKey, parseAdoptFloorRow, raisedFloor } from './adopt-floor';
import { isAllowedSettingsRowKey } from './settings-row-keys';
import type { NoteRecord, NoteThread, NoteWireV0 } from './types';

const ident = (): RatchetIdentity => {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
};
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const NOW = Date.now();
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();

interface Party {
  ratchet: RatchetIdentity; fp: string; sign: (w: NoteWireV0) => Promise<NoteWireV0>;
  sess: ReturnType<typeof memIO>; notes: Map<string, NoteRecord>; threads: Map<string, NoteThread>;
  floor: Map<string, string>; floorWrites: Array<{ peer: string; at: string; stored: boolean }>;
}
async function party(): Promise<Party> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return {
    ratchet: ident(), fp: id.fingerprint,
    sign: (wire) => signNoteWire(wire, id.public_key, a.secret_material.classicalPrivateKey, a.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key),
    sess: memIO(), notes: new Map(), threads: new Map(), floor: new Map(), floorWrites: [],
  };
}
const wireFrom = (from: Party, note_id: string, body: string, sentAt: string): Promise<NoteWireV0> =>
  from.sign({ type: NOTE_WIRE_TYPE, note_id, thread_id: 'thr', from_fingerprint: from.fp, sent_at: sentAt, body, participant_kind: 'human' });
const sealFrom = (from: Party, to: Party, text: string, fromSess = from.sess) => sealDirectNote(to.fp, text, from.ratchet, peerOf(to.ratchet), fromSess.io);

interface Opts {
  withFloor?: boolean;                       // wire the floor the way live-book-poll does (default true)
  floorReader?: () => Promise<string | undefined>;
  floorWriterThrows?: boolean;
}
/** `rcv` receives `wire` from `snd` through the real acceptInboundNote, wired like live-book-poll (stored-notes reader + the floor). */
async function receive(rcv: Party, snd: Party, wire: NoteWireV0, o: Opts = {}) {
  const withFloor = o.withFloor ?? true;
  const reasons: string[] = [];
  const io = {
    putNote: async (n: NoteRecord) => { rcv.notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { rcv.threads.set(t.thread_id, t); },
    listThreads: async () => [...rcv.threads.values()],
    getNote: async (nid: string) => rcv.notes.get(nid) ?? null,
  };
  const stored = async () => [...rcv.notes.values()].filter((n) => n.direction === 'inbound' && n.from_fingerprint.toLowerCase() === wire.from_fingerprint.toLowerCase()).map((n) => n.sent_at);
  const r = await acceptInboundNote({
    wire, isAdmitted: async () => true, io: io as never,
    onDrop: (x) => { reasons.push(x); },
    openRatchet: (fp, body, ctx) => openDirectNoteStagedTyped(
      fp, body, rcv.ratchet, peerOf(snd.ratchet), rcv.sess.io,
      buildAdoptFirstFrame({
        ownFingerprint: rcv.fp, peerFingerprint: fp, sentAt: ctx.sentAt, storedSentAts: stored, now: () => NOW,
        ...(withFloor ? { adoptedFloorAt: o.floorReader ?? (async () => rcv.floor.get(fp)) } : {}),
      }),
    ),
    ...(withFloor ? {
      onSessionStarted: async (peer: string, signedSentAt: string) => {
        rcv.floorWrites.push({ peer, at: signedSentAt, stored: rcv.notes.has(wire.note_id) });
        if (o.floorWriterThrows) throw new Error('settings store locked');
        const next = raisedFloor(rcv.floor.get(peer), signedSentAt, NOW);
        if (next !== null) rcv.floor.set(peer, next);
      },
    } : {}),
  });
  return { r, reasons };
}
const deleteConversation = (p: Party) => { p.notes.clear(); p.threads.clear(); };

/** Bob's session with Alice was created by Alice's FIRST frame f1 (signed T-1h), opened and stored. Alice then keeps f1 (a relay operator could too). */
async function established(o: Opts = {}) {
  const alice = await party(), bob = await party();
  const aliceSess = memIO();
  const f1 = (await sealFrom(alice, bob, 'first ever', aliceSess))!;
  const w1 = await wireFrom(alice, 'n1', f1, at(-3_600_000));
  const got = await receive(bob, alice, w1, o);
  assert.ok(got.r, 'setup: the first frame opens and is stored'); assert.deepEqual(got.reasons, []);
  return { alice, bob, aliceSess, f1 };
}

test('F1 THE HOLE (control, no floor wired): after the conversation is deleted, a replay of the first frame that created the session is ADOPTED', async () => {
  const { alice, bob, f1 } = await established({ withFloor: false });
  const sessionBefore = JSON.stringify(bob.sess.rows.get(alice.fp));
  deleteConversation(bob);                                         // the user deletes the conversation: no note from Alice is stored any more
  const replay = await receive(bob, alice, await wireFrom(alice, 'rp', f1, at(-3_600_000)), { withFloor: false });
  assert.ok(replay.r, 'WITHOUT a floor the 7-day window lets the replay in (this is the bug L-318a closes)');
  assert.notEqual(JSON.stringify(bob.sess.rows.get(alice.fp)), sessionBefore, 'and the established session was replaced');
});

test('F2 with the floor, the SAME replay is refused: session byte-identical, nothing stored, the floor row was written once AFTER the note was stored', async () => {
  const { alice, bob, f1 } = await established();
  assert.equal(bob.floorWrites.length, 1);
  assert.equal(bob.floorWrites[0].stored, true, 'the floor is written after the note is stored (and the session committed)');
  assert.equal(bob.floor.get(alice.fp), at(-3_600_000), 'the floor is the first frame\'s SIGNED sent_at');
  const sessionBefore = JSON.stringify(bob.sess.rows.get(alice.fp));
  deleteConversation(bob);
  for (const [i, t] of [at(-3_600_000), at(-3_700_000), at(-60_000) /* a replayer cannot pick a newer signed time; this shows the bar itself */].entries()) {
    const replay = await receive(bob, alice, await wireFrom(alice, `rp${i}`, f1, t));
    if (i < 2) { assert.equal(replay.r, null, `signed ${t}: refused`); assert.deepEqual(replay.reasons, ['ratchet-desync']); assert.equal(bob.notes.has(`rp${i}`), false); }
    else { assert.ok(replay.r, 'control: a first frame genuinely signed NEWER than the floor is adopted (the bar is the floor, not a blanket refusal)'); }
    if (i < 2) assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), sessionBefore, 'session byte-identical');
  }
});

test('F3 the floor RISES with an adoption: after Alice resets and the conversation is deleted, replays of BOTH her old and her new first frame are refused', async () => {
  const { alice, bob, f1 } = await established();
  const aliceNew = memIO();
  const f2 = (await sealFrom(alice, bob, 'after the reset', aliceNew))!;
  const adopted = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-120_000)));
  assert.ok(adopted.r, 'the reset is adopted'); assert.equal(bob.floor.get(alice.fp), at(-120_000), 'the floor rose to the NEW first frame');
  assert.equal(bob.floorWrites.length, 2);
  const sessionBefore = JSON.stringify(bob.sess.rows.get(alice.fp));
  deleteConversation(bob);
  for (const [name, frame, t] of [['old first frame', f1, at(-3_600_000)], ['new first frame', f2, at(-120_000)]] as const) {
    const r = await receive(bob, alice, await wireFrom(alice, `rp-${name}`, frame, t));
    assert.equal(r.r, null, `${name}: refused`); assert.deepEqual(r.reasons, ['ratchet-desync']);
  }
  assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), sessionBefore);
});

test('F4 a continuation never touches the floor, and a LATER reset (signed newer than the floor) is still adopted: the fix does not over-hold', async () => {
  const { alice, bob, aliceSess } = await established();
  const f1b = (await sealFrom(alice, bob, 'second frame of the same session', aliceSess))!;
  assert.ok((await receive(bob, alice, await wireFrom(alice, 'n1b', f1b, at(-3_000_000)))).r);
  assert.equal(bob.floorWrites.length, 1, 'a continuation is not a session start: no floor write');
  assert.equal(bob.floor.get(alice.fp), at(-3_600_000));
  deleteConversation(bob);
  const aliceNew = memIO();
  const f3 = (await sealFrom(alice, bob, 'a genuine later reset', aliceNew))!;
  const later = await receive(bob, alice, await wireFrom(alice, 'n3', f3, at(-30_000)));
  assert.ok(later.r, 'newer than the floor: adopted even though no note is stored'); assert.equal(bob.floor.get(alice.fp), at(-30_000));
});

test('F5 edges: a far-future floor is ignored (no lockout), an unreadable floor row means NO, a garbage floor is skipped, a throwing floor writer cannot undo a stored note', async () => {
  const mk = async () => { const x = await established(); deleteConversation(x.bob); return x; };
  { // far-future floor (e.g. a fresh first frame once dated years ahead): ignored, so a real reset still adopts
    const { alice, bob } = await mk(); bob.floor.set(alice.fp, at(FUTURE_SLACK_MS + 60_000));
    const f2 = (await sealFrom(alice, bob, 'reset', memIO()))!;
    assert.ok((await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-60_000)))).r, 'a floor beyond now + slack does not lock the contact out');
  }
  { // the floor row cannot be read (store locked): NO, the frame stays a held desync
    const { alice, bob } = await mk(); const before = JSON.stringify(bob.sess.rows.get(alice.fp));
    const f2 = (await sealFrom(alice, bob, 'reset', memIO()))!;
    const r = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-60_000)), { floorReader: async () => { throw new Error('locked'); } });
    assert.equal(r.r, null); assert.deepEqual(r.reasons, ['ratchet-desync']); assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), before);
  }
  { // garbage floor value: skipped, the stored-notes / window rules decide as before
    const { alice, bob } = await mk();
    const f2 = (await sealFrom(alice, bob, 'reset', memIO()))!;
    assert.ok((await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-60_000)), { floorReader: async () => 'not a time' })).r);
    // a value Date.parse would ACCEPT (RFC 2822), dated NEWER than the candidate: a lenient parse would raise the bar above the frame and block a real reset
    const { alice: a2, bob: b2 } = await mk();
    const f2b = (await sealFrom(a2, b2, 'reset', memIO()))!;
    const lenient = new Date(NOW - 30_000).toUTCString();
    assert.ok(Number.isFinite(Date.parse(lenient)) && Date.parse(lenient) > NOW - 60_000, 'precondition: Date.parse accepts it and it is newer than the frame');
    assert.ok((await receive(b2, a2, await wireFrom(a2, 'n2', f2b, at(-60_000)), { floorReader: async () => lenient })).r, 'a non-strict floor value is skipped, not read leniently');
  }
  { // the writer throws after commit: the note and the session stay
    const alice = await party(), bob = await party();
    const f1 = (await sealFrom(alice, bob, 'first', memIO()))!;
    const r = await receive(bob, alice, await wireFrom(alice, 'n1', f1, at(-3_600_000)), { floorWriterThrows: true });
    assert.ok(r.r); assert.ok(bob.notes.has('n1')); assert.ok(bob.sess.rows.get(alice.fp)); assert.equal(bob.floor.has(alice.fp), false, 'no floor, so the pre-L-318a behaviour, never a stricter one');
  }
});

test('F6 the pure pieces: the floor only rises and never beyond now + slack, the row is strict, the key is built from validated hex, the prefix is an allowed settings prefix', () => {
  const a = at(-3_600_000), b = at(-60_000);
  assert.equal(raisedFloor(undefined, a, NOW), a); assert.equal(raisedFloor(a, b, NOW), b);
  assert.equal(raisedFloor(b, a, NOW), null, 'never lowered'); assert.equal(raisedFloor(a, a, NOW), null, 'equal is no change');
  assert.equal(raisedFloor(undefined, 'yesterday', NOW), null); assert.equal(raisedFloor(undefined, undefined, NOW), null); assert.equal(raisedFloor(a, '2026-11-01 10:00', NOW), null);
  assert.equal(raisedFloor('garbage', a, NOW), a, 'an unusable stored floor is replaced');
  assert.equal(raisedFloor(undefined, at(FUTURE_SLACK_MS), NOW), at(FUTURE_SLACK_MS), 'now + slack exactly is still storable');
  assert.equal(raisedFloor(undefined, at(FUTURE_SLACK_MS + 1), NOW), null, 'one ms beyond now + slack is not');
  assert.equal(raisedFloor(a, at(10 * 365 * 86_400_000), NOW), null, 'a far-future candidate never replaces a real floor'); assert.equal(raisedFloor(undefined, a, NaN), null);
  const fp = 'ab12'.repeat(16);
  assert.deepEqual(parseAdoptFloorRow({ fp, sent_at: a }), { fp, sent_at: a });
  for (const bad of [null, 5, [], {}, { fp, sent_at: a, extra: 1 }, { fp: fp.toUpperCase(), sent_at: a }, { fp: 'xyz', sent_at: a }, { fp, sent_at: 'not a time' }, { fp }, { sent_at: a }]) assert.equal(parseAdoptFloorRow(bad), null, JSON.stringify(bad));
  assert.equal(adoptFloorKey(fp), `${ADOPT_FLOOR_PREFIX}${fp}`); assert.equal(adoptFloorKey('../../notes_encryption_salt'), null); assert.equal(adoptFloorKey(undefined), null);
  assert.equal(isAllowedSettingsRowKey(adoptFloorKey(fp)), true); assert.equal(isAllowedSettingsRowKey('notes_encryption_salt'), false);
});

test('F8 (Flint #3312 R1) a far-future first frame does not switch the protection off: the floor is not written, the next normal first frame raises it, and its replay after a delete is refused', async () => {
  const alice = await party(), bob = await party();
  const farFuture = at(10 * 365 * 86_400_000);
  const g1 = (await sealFrom(alice, bob, 'first, from a broken clock', memIO()))!;
  assert.ok((await receive(bob, alice, await wireFrom(alice, 'n1', g1, farFuture))).r, 'the first frame opens (a fresh contact: no session to protect)');
  assert.equal(bob.floor.has(alice.fp), false, 'a far-future signed time is NOT stored as the floor');
  const f2 = (await sealFrom(alice, bob, 'a normal reset', memIO()))!;
  deleteConversation(bob);
  const adopted = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-120_000)));
  assert.ok(adopted.r, 'the contact can still reset (no far-future floor locks them out)'); assert.equal(bob.floor.get(alice.fp), at(-120_000), 'and the floor now rises to the normal frame');
  const before = JSON.stringify(bob.sess.rows.get(alice.fp)); deleteConversation(bob);
  const replay = await receive(bob, alice, await wireFrom(alice, 'rp', f2, at(-120_000)));
  assert.equal(replay.r, null); assert.deepEqual(replay.reasons, ['ratchet-desync']); assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), before, 'the replay is refused, session untouched');
});

test('F7 STATIC: live-book-poll passes the floor reader to the adopt policy and the floor writer to onSessionStarted; transport fires it only for a started session', () => {
  const lbp = readFileSync(new URL('../sync/live-book-poll.ts', import.meta.url), 'utf8');
  assert.match(lbp, /adoptedFloorAt: async \(\) => \(await import\('@\/lib\/messaging\/adopt-floor-store'\)\)\.getAdoptFloor\(fromFp\)/);
  assert.match(lbp, /onSessionStarted: async \(fp, signedSentAt\) => \{\s*const \{ raiseAdoptFloor \} = await import\('@\/lib\/messaging\/adopt-floor-store'\);\s*await raiseAdoptFloor\(fp, signedSentAt\);/);
  const tr = readFileSync(new URL('./transport.ts', import.meta.url), 'utf8');
  assert.match(tr, /if \(staged\?\.startedSession\) \{\s*try \{ await args\.onSessionStarted\?\.\(args\.wire\.from_fingerprint, args\.wire\.sent_at\); \}/);
  assert.ok(tr.indexOf('await staged.commit()') < tr.indexOf('args.onSessionStarted'), 'the floor is raised only AFTER the session commit');
});
