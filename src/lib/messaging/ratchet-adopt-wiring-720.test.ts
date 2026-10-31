// src/lib/messaging/ratchet-adopt-wiring-720.test.ts
//
// #720 R5/R6 STEP B2: the adopt policy wired into the REAL receive seam (acceptInboundNote) with REAL ratchet crypto, REAL note signing and the real
// policy builder. The only fakes are the three storages (ratchet session rows, notes, threads). What this pins:
//   W1  the opener is handed the note's SIGNED sent_at exactly as received (never a default).
//   W2  a peer's reset (new first frame, newer signed time) is adopted: note stored, session replaced, the hook fires ONCE, AFTER the note is stored and
//       the session committed, and our reply opens on the peer's new side (they converge). W3 the next frame of the new session is a plain open (no hook).
//   W4  a REPLAYED old first frame (signed time not newer than a stored note) is a held desync: session byte-identical, no hook.
//   W5  with nothing stored from that contact the 7-day window decides. W6 a missing / non-ISO signed time never adopts.
//   W7  a throwing hook cannot undo a stored note + committed session. W8 (N-R5c) an unverified or non-admitted frame never reaches the opener at all.
//   W9  (N-R6) both sides reset at once: exactly the LOWER fingerprint's session survives and the two converge.
//   W12 (Archie #2350) a stored note dated beyond now + 5 min is IGNORED by the replay guard and counted, so one far-future note cannot lock a contact out of resetting.
//   W10 a stored-notes reader that throws means NO, and an unparsable stored time is skipped. W11 STATIC guard on the live composition (live-book-poll + store).
// Run: npx tsx --test src/lib/messaging/ratchet-adopt-wiring-720.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { memIO } from './ratchet-test-io';
import { signNoteWire } from './note-auth';
import { acceptInboundNote } from './transport';
import { NOTE_WIRE_TYPE } from './domains';
import { sealDirectNote, openDirectNoteStagedTyped } from './direct-session';
import { buildAdoptFirstFrame, createAdoptCounter, FUTURE_SLACK_MS, RELAY_WINDOW_MS } from './session-adopt-policy';
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
  ratchet: RatchetIdentity;
  fp: string;
  sign: (wire: NoteWireV0) => Promise<NoteWireV0>;
  sess: ReturnType<typeof memIO>;
  notes: Map<string, NoteRecord>;
  threads: Map<string, NoteThread>;
  hooks: Array<{ peer: string; stored: boolean; puts: number }>;
}

async function party(): Promise<Party> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return {
    ratchet: ident(),
    fp: id.fingerprint,
    sign: (wire) => signNoteWire(wire, id.public_key, a.secret_material.classicalPrivateKey, a.secret_material.classicalKpass, id.pq_kem_public_key, id.pq_sig_public_key),
    sess: memIO(),
    notes: new Map(),
    threads: new Map(),
    hooks: [],
  };
}

/** A signed note from `from`, carrying `body`, stamped `sentAt` (signed: it is part of the signature input). */
const wireFrom = (from: Party, note_id: string, body: string, sentAt: string): Promise<NoteWireV0> =>
  from.sign({ type: NOTE_WIRE_TYPE, note_id, thread_id: 'thr', from_fingerprint: from.fp, sent_at: sentAt, body, participant_kind: 'human' });

/** `from` seals the next frame of ITS session with `to` into `fromSess` (the sender's own storage). */
const sealFrom = (from: Party, to: Party, text: string, fromSess = from.sess) => sealDirectNote(to.fp, text, from.ratchet, peerOf(to.ratchet), fromSess.io);

interface Opts {
  admitted?: boolean;
  hook?: (peer: string) => Promise<void>;
  spy?: { ctx?: { sentAt: string | undefined }; opened: number };
  storedSentAts?: () => Promise<string[]>;
}

/** `rcv` receives `wire` from `snd` through the real acceptInboundNote, with the adopt policy built exactly the way live-book-poll builds it. */
async function receive(rcv: Party, snd: Party, wire: NoteWireV0, o: Opts = {}) {
  const reasons: string[] = [];
  const io = {
    putNote: async (n: NoteRecord) => { rcv.notes.set(n.note_id, n); },
    putThread: async (t: NoteThread) => { rcv.threads.set(t.thread_id, t); },
    listThreads: async () => [...rcv.threads.values()],
    getNote: async (nid: string) => rcv.notes.get(nid) ?? null,
  };
  const stored = async () => [...rcv.notes.values()].filter((n) => n.direction === 'inbound' && n.from_fingerprint.toLowerCase() === wire.from_fingerprint.toLowerCase()).map((n) => n.sent_at);
  const r = await acceptInboundNote({
    wire,
    isAdmitted: async () => o.admitted ?? true,
    io: io as never,
    onDrop: (x) => reasons.push(x),
    openRatchet: (fp, body, ctx) => {
      if (o.spy) { o.spy.ctx = ctx; o.spy.opened++; }
      return openDirectNoteStagedTyped(
        fp, body, rcv.ratchet, peerOf(snd.ratchet), rcv.sess.io,
        buildAdoptFirstFrame({ ownFingerprint: rcv.fp, peerFingerprint: fp, sentAt: ctx.sentAt, storedSentAts: o.storedSentAts ?? stored, now: () => NOW }),
      );
    },
    onSessionReplaced: async (peer) => {
      rcv.hooks.push({ peer, stored: rcv.notes.has(wire.note_id), puts: rcv.sess.puts() });
      if (o.hook) await o.hook(peer);
    },
  });
  return { r, reasons };
}

/** Bob holds a CONFIRMED session with Alice (her n1 at T-1h opened and stored). Alice then resets: a NEW session whose frames Bob has not seen. */
async function aliceResets() {
  const alice = await party(), bob = await party();
  const aliceOld = memIO(), aliceNew = memIO();
  const f1 = (await sealFrom(alice, bob, 'before the reset', aliceOld))!;
  const ok = await receive(bob, alice, await wireFrom(alice, 'n1', f1, at(-3_600_000)));
  assert.ok(ok.r, 'setup: the first frame opens and is stored'); assert.deepEqual(ok.reasons, []);
  assert.deepEqual(bob.hooks, [], 'setup: an ordinary first frame is not a replacement');
  return { alice, bob, aliceNew };
}

test('W1 the opener is handed the note\'s SIGNED sent_at exactly as it came, and a missing one stays missing (never defaulted to now)', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const f2 = (await sealFrom(alice, bob, 'after', aliceNew))!;
  const spy = { opened: 0 } as NonNullable<Opts['spy']>;
  const t = at(-1000);
  await receive(bob, alice, await wireFrom(alice, 'n2', f2, t), { spy });
  assert.equal(spy.opened, 1);
  assert.equal(spy.ctx?.sentAt, t);
  const spy2 = { opened: 0 } as NonNullable<Opts['spy']>;
  await receive(bob, alice, await wireFrom(alice, 'n2b', f2, ''), { spy: spy2 });
  assert.equal(spy2.ctx?.sentAt, '', 'an empty signed time is passed through as empty, not replaced by the clock');
});

test('W2 the peer\'s reset is ADOPTED: note stored, session replaced, hook fires once AFTER store + commit, and our reply opens on their new side', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const before = JSON.stringify(bob.sess.rows.get(alice.fp));
  const putsBefore = bob.sess.puts();
  const f2 = (await sealFrom(alice, bob, 'after the reset', aliceNew))!;
  const got = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-1000)));
  assert.ok(got.r, 'the new first frame opened'); assert.equal(got.r!.body, 'after the reset'); assert.deepEqual(got.reasons, []);
  assert.ok(bob.notes.has('n2'));
  assert.notEqual(JSON.stringify(bob.sess.rows.get(alice.fp)), before, 'the stored session was REPLACED');
  assert.equal(bob.sess.puts(), putsBefore + 1, 'exactly one session write');
  assert.equal(bob.hooks.length, 1); assert.equal(bob.hooks[0].peer, alice.fp);
  assert.equal(bob.hooks[0].stored, true, 'the hook ran after the note was stored');
  assert.equal(bob.hooks[0].puts, putsBefore + 1, 'the hook ran after the session commit');
  const reply = (await sealFrom(bob, alice, 'reply from bob'))!;                      // bob\'s own storage: continues the ADOPTED session
  const back = await openDirectNoteStagedTyped(bob.fp, reply, alice.ratchet, peerOf(bob.ratchet), aliceNew.io);
  assert.ok(!('failed' in back)); assert.equal((back as { plaintext: string }).plaintext, 'reply from bob');
  (back as { release: () => void }).release();
});

test('W3 the NEXT frame of the new session is a plain open: no replacement, no hook', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const f2 = (await sealFrom(alice, bob, 'two', aliceNew))!, f3 = (await sealFrom(alice, bob, 'three', aliceNew))!;
  assert.ok((await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-2000)))).r);
  assert.equal(bob.hooks.length, 1);
  const third = await receive(bob, alice, await wireFrom(alice, 'n3', f3, at(-1000)));
  assert.ok(third.r); assert.equal(third.r!.body, 'three');
  assert.equal(bob.hooks.length, 1, 'still one: a continuation replaces nothing');
});

test('W4 a REPLAYED first frame (signed time not newer than a stored note from that contact) stays a held desync: session byte-identical, no hook, nothing stored', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const before = JSON.stringify(bob.sess.rows.get(alice.fp));
  const f2 = (await sealFrom(alice, bob, 'old first frame replayed', aliceNew))!;
  for (const [i, t] of [at(-3_600_000), at(-7_200_000)].entries()) {                     // equal to the stored n1, and older
    const r = await receive(bob, alice, await wireFrom(alice, `rp${i}`, f2, t));
    assert.equal(r.r, null); assert.deepEqual(r.reasons, ['ratchet-desync']);
    assert.equal(bob.notes.has(`rp${i}`), false);
  }
  assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), before);
  assert.deepEqual(bob.hooks, []);
});

test('W5 with NOTHING stored from that contact the 7-day relay window decides: fresh adopts, older than the window does not', async () => {
  for (const [offset, adopted] of [[-1000, true], [-RELAY_WINDOW_MS - 60_000, false]] as const) {
    const alice = await party(), bob = await party();
    const aliceOld = memIO(), aliceNew = memIO();
    const f1 = (await sealFrom(alice, bob, 'seed', aliceOld))!;
    const s = await openDirectNoteStagedTyped(alice.fp, f1, bob.ratchet, peerOf(alice.ratchet), bob.sess.io);   // a session row, but NO stored note (aged out)
    assert.ok(!('failed' in s)); await (s as { commit: () => Promise<void> }).commit();
    const f2 = (await sealFrom(alice, bob, 'fresh start', aliceNew))!;
    const r = await receive(bob, alice, await wireFrom(alice, 'nx', f2, at(offset)));
    assert.equal(!!r.r, adopted, `offset ${offset}`);
    assert.equal(bob.hooks.length, adopted ? 1 : 0);
  }
});

test('W6 a missing, non-ISO or zone-less signed time never adopts (Date.parse would have accepted some of these)', async () => {
  for (const bad of ['', '5', 'yesterday', '2026-10-31', '2026-10-31T12:00:00', '2026-10-31 12:00:00Z']) {
    const alice = await party(), bob = await party();
    const aliceOld = memIO(), aliceNew = memIO();
    const s = await openDirectNoteStagedTyped(alice.fp, (await sealFrom(alice, bob, 'seed', aliceOld))!, bob.ratchet, peerOf(alice.ratchet), bob.sess.io);
    assert.ok(!('failed' in s)); await (s as { commit: () => Promise<void> }).commit();
    const f2 = (await sealFrom(alice, bob, 'x', aliceNew))!;
    const r = await receive(bob, alice, await wireFrom(alice, 'nb', f2, bad));
    assert.equal(r.r, null, `"${bad}"`); assert.deepEqual(r.reasons, ['ratchet-desync']); assert.equal(bob.hooks.length, 0);
  }
});

test('W7 a hook that throws cannot undo a stored note and a committed session', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const f2 = (await sealFrom(alice, bob, 'after', aliceNew))!;
  const r = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-1000)), { hook: async () => { throw new Error('dead-letter store locked'); } });
  assert.ok(r.r, 'the accepted note is still returned'); assert.ok(bob.notes.has('n2'));
  const reply = (await sealFrom(bob, alice, 'still converged'))!;
  const back = await openDirectNoteStagedTyped(bob.fp, reply, alice.ratchet, peerOf(bob.ratchet), aliceNew.io);
  assert.ok(!('failed' in back), 'the adopted session was committed'); (back as { release: () => void }).release();
});

test('W8 (N-R5c) an UNVERIFIED frame and a NON-ADMITTED sender never reach the opener: no acceptFirst, no hook, session untouched', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const before = JSON.stringify(bob.sess.rows.get(alice.fp));
  const f2 = (await sealFrom(alice, bob, 'forged?', aliceNew))!;
  const good = await wireFrom(alice, 'nf', f2, at(-1000));
  const forged: NoteWireV0 = { ...good, body: good.body + ' ' };                         // signature no longer covers the body
  const spy = { opened: 0 } as NonNullable<Opts['spy']>;
  const a = await receive(bob, alice, forged, { spy });
  assert.equal(a.r, null); assert.deepEqual(a.reasons, ['unverified']);
  const b = await receive(bob, alice, good, { spy, admitted: false });
  assert.equal(b.r, null); assert.deepEqual(b.reasons, ['not-in-book']);
  assert.equal(spy.opened, 0, 'the ratchet opener was never called');
  assert.deepEqual(bob.hooks, []);
  assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), before);
});

test('W9 (N-R6) both sides reset at once: only the LOWER fingerprint\'s session survives, and the two converge', async () => {
  const p = await party(), q = await party();
  const [lo, hi] = p.fp.toLowerCase() < q.fp.toLowerCase() ? [p, q] : [q, p];
  const loOwn = (await sealFrom(lo, hi, 'lo first'))!;                                    // each side initiated its OWN session and heard nothing
  const hiOwn = (await sealFrom(hi, lo, 'hi first'))!;
  const hiGets = await receive(hi, lo, await wireFrom(lo, 'lo1', loOwn, at(-2000)));
  assert.ok(hiGets.r, 'the HIGHER side adopts the lower\'s session'); assert.equal(hi.hooks.length, 1);
  const loGets = await receive(lo, hi, await wireFrom(hi, 'hi1', hiOwn, at(-1000)));
  assert.equal(loGets.r, null, 'the LOWER side refuses the higher\'s first frame'); assert.deepEqual(loGets.reasons, ['ratchet-desync']);
  assert.equal(lo.hooks.length, 0);
  const hiReply = (await sealFrom(hi, lo, 'hi, on the adopted session'))!;
  const loSees = await receive(lo, hi, await wireFrom(hi, 'hi2', hiReply, at(-500)));
  assert.ok(loSees.r, 'the lower side opens it: converged'); assert.equal(loSees.r!.body, 'hi, on the adopted session');
});

test('W10 a stored-times reader that throws means NO; an unparsable stored time is skipped, the parseable ones still decide', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  const f2 = (await sealFrom(alice, bob, 'x', aliceNew))!;
  const r = await receive(bob, alice, await wireFrom(alice, 'nt', f2, at(-1000)), { storedSentAts: async () => { throw new Error('notes store locked'); } });
  assert.equal(r.r, null); assert.deepEqual(r.reasons, ['ratchet-desync']); assert.equal(bob.hooks.length, 0);
  // an unparsable stored time is skipped (it cannot help a replayer), the parseable ones still decide
  const ask = (stored: string[], sentAt: string) => buildAdoptFirstFrame({ ownFingerprint: 'bb', peerFingerprint: 'aa', sentAt, storedSentAts: async () => stored, now: () => NOW })({ unconfirmed: false });
  assert.equal(await ask(['garbage', at(-5000)], at(-1000)), true, 'garbage skipped, newer than the real one');
  assert.equal(await ask(['garbage', at(-5000)], at(-6000)), false, 'garbage skipped, but older than the real one');
  assert.equal(await ask(['garbage'], at(-1000)), true, 'only garbage stored = nothing stored: inside the window');
  assert.equal(await ask([at(-9000), at(-5000)], at(-7000)), false, 'newer than the OLDEST stored note but not the NEWEST: refused (the guard is against every stored note)');
  assert.equal(await ask([at(-5000), at(-9000)], at(-7000)), false, 'order of the stored list does not matter');
  assert.equal(await ask([at(-9000), at(-5000)], at(-4000)), true, 'newer than all of them');
});

test('W12 (Archie #2350) one FAR-FUTURE stored note from the contact does not lock them out: a real reset adopts, a replayed old first frame is still refused, and the ignored note is counted', async () => {
  const { alice, bob, aliceNew } = await aliceResets();
  bob.notes.set('future', { note_id: 'future', thread_id: 'thr', direction: 'inbound', from_fingerprint: alice.fp, to_fingerprints: [], sent_at: at(30 * 24 * 3_600_000), body: 'dated a month ahead', participant_kind: 'human', retention: { expires_at: null }, wire_type: NOTE_WIRE_TYPE } as NoteRecord);
  const before = JSON.stringify(bob.sess.rows.get(alice.fp));
  const replay = (await sealFrom(alice, bob, 'replayed old first frame', memIO()))!;
  const refused = await receive(bob, alice, await wireFrom(alice, 'rp', replay, at(-7_200_000)));   // older than the real stored n1
  assert.equal(refused.r, null); assert.deepEqual(refused.reasons, ['ratchet-desync']);
  assert.equal(JSON.stringify(bob.sess.rows.get(alice.fp)), before, 'control: the replay changed nothing');
  const f2 = (await sealFrom(alice, bob, 'a real reset', aliceNew))!;
  const got = await receive(bob, alice, await wireFrom(alice, 'n2', f2, at(-1000)));
  assert.ok(got.r, 'newer than every REAL stored note: adopted despite the future-dated one'); assert.equal(bob.hooks.length, 1);
});

test('W12b the future slack edge is exact (now + 5 min counts, one ms beyond is ignored and counted), and the counter reports then resets', async () => {
  const counter = createAdoptCounter();
  const ask = (stored: string[], sentAt: string) => buildAdoptFirstFrame({ ownFingerprint: 'bb', peerFingerprint: 'aa', sentAt, storedSentAts: async () => stored, now: () => NOW, onIgnoredFuture: (n) => counter.bumpFutureIgnored(n) })({ unconfirmed: false });
  assert.equal(await ask([at(FUTURE_SLACK_MS)], at(-1000)), false, 'dated exactly now + slack: still counts as evidence, so a frame older than it is refused');
  assert.deepEqual(counter.take(), { future_ignored: 0 });
  assert.equal(await ask([at(FUTURE_SLACK_MS + 1)], at(-1000)), true, 'one ms beyond the slack: ignored');
  assert.equal(await ask([at(FUTURE_SLACK_MS + 1), at(2 * FUTURE_SLACK_MS)], at(-1000)), true);
  assert.deepEqual(counter.take(), { future_ignored: 3 }, '1 + 2 ignored notes');
  assert.deepEqual(counter.take(), { future_ignored: 0 }, 'take() resets');
  // a counter that throws must not change the answer
  const boom = buildAdoptFirstFrame({ ownFingerprint: 'bb', peerFingerprint: 'aa', sentAt: at(-1000), storedSentAts: async () => [at(FUTURE_SLACK_MS + 5)], now: () => NOW, onIgnoredFuture: () => { throw new Error('x'); } });
  assert.equal(await boom({ unconfirmed: false }), true);
});

// W11: live-book-poll's composition needs IndexedDB, which this harness does not have, so the wiring is pinned by SOURCE (like the reset W2/W3 guards).
// The real-browser proof (reset UI e2e) is what finally runs it.
import { readFileSync } from 'node:fs';
const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');

test('W11 STATIC: live-book-poll builds the adopt policy from THIS owner\'s fp, the PEER\'s fp, the signed ctx.sentAt and the stored notes, and releases held frames on replace', () => {
  const lbp = read('../sync/live-book-poll.ts');
  const seam = lbp.slice(lbp.indexOf('export function buildNoteSeam'));
  for (const needle of [
    'openRatchet: async (fromFp, body, ctx) =>',
    'buildAdoptFirstFrame({',
    'ownFingerprint: owner.fingerprint,',
    'peerFingerprint: fromFp,',
    'sentAt: ctx?.sentAt,',
    'storedSentAts: () => listInboundSentAtFrom(fromFp),',
    'onIgnoredFuture: (n) => adoptCounts?.bumpFutureIgnored(n),',
    'onSessionReplaced: async (fp) =>',
    'await markSessionReset(fp);',
  ]) assert.ok(seam.includes(needle), `buildNoteSeam lost: ${needle}`);
  // the counter must reach BOTH the note seam and the consume deps, or the count is silently never reported
  const whole = lbp;
  assert.ok(whole.includes('}, legs, adoptCounts),'), 'the note seam is built with the adopt counter');
  assert.ok(/openLegs: legs,\s*adoptCounts,/.test(whole), 'the consume deps carry the adopt counter');
  const store = read('./store.ts');
  const reader = store.slice(store.indexOf('export async function listInboundSentAtFrom'), store.indexOf('export async function deleteThread'));
  assert.ok(reader.includes("n.direction === 'inbound'") && reader.includes('n.from_fingerprint.toLowerCase() === want'), 'the reader must count inbound notes from the peer, case-insensitively');
});
