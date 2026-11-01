// scripts/devin-comm-tr.test.ts
// Run: npx tsx --test scripts/devin-comm-tr.test.ts
//
// F1 (Flint spec v1 bcade56d): a headless agent adopts a contact's NEW first frame after that contact reset, through the SAME policy as the
// PWA (session-adopt-policy.ts), and never otherwise. Real ratchet crypto (TripleRatchet); the policy is the real buildAdoptFirstFrame.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../src/lib/crypto/pq';
import { TripleRatchet, type RatchetIdentity, type RatchetPeer } from '../src/lib/crypto/message-ratchet';
import { buildAdoptFirstFrame, FUTURE_SLACK_MS, RELAY_WINDOW_MS } from '../src/lib/messaging/session-adopt-policy';
import { journalSentAts, openTrFrame, type TrSessions } from './devin-comm-tr';
import { countedOpen } from './devin-comm-inbound';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

const LO = 'a'.repeat(64);
const HI = 'f'.repeat(64);
const NOW = Date.parse('2026-10-31T08:00:00Z');
const iso = (ms: number) => new Date(ms).toISOString();
const line = (peer_fp: string, note_id: string, sent_at: string) => JSON.stringify({ note_id, peer_fp, sent_at, plaintext: 'x' }) + '\n';

/** ME (headless) holds a CONFIRMED session with ALICE (she sent, ME opened). Then ALICE resets: f2 = her NEW first frame, f3 = its continuation. */
async function aliceResets(meFp = HI, aliceFp = LO) {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const old = TripleRatchet.initiate(alice, peerOf(me));
  const f1 = await old.send('before the reset');
  const opened = await TripleRatchet.acceptFirst(me, peerOf(alice), f1);
  assert.ok(opened);
  const sessions: TrSessions = { [aliceFp]: opened.session.exportState() };
  const fresh = TripleRatchet.initiate(alice, peerOf(me));
  const f2 = await fresh.send('after the reset');
  const f3 = await fresh.send('second after the reset');
  return { me, alice, meFp, aliceFp, sessions, f2, f3 };
}

const ask = (o: { me: string; peer: string; sentAt: string | undefined; journal: string | (() => string); noteId?: string; now?: number }) =>
  buildAdoptFirstFrame({
    ownFingerprint: o.me,
    peerFingerprint: o.peer,
    sentAt: o.sentAt,
    storedSentAts: async () => journalSentAts(typeof o.journal === 'function' ? o.journal() : o.journal, o.peer, o.noteId ?? 'n_candidate'),
    now: () => o.now ?? NOW,
  });

test('F1 NEG1: after a reset, the contact\'s NEW first frame opens on headless and the session is REPLACED (base: receive() fails → null → tombstoned)', async () => {
  const x = await aliceResets();
  const journal = line(x.aliceFp, 'n_old', iso(NOW - 3600e3));
  const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - 60e3), journal }));
  assert.ok(r, 'opened');
  assert.equal(r.plaintext, 'after the reset');
  assert.equal(r.adopted, true);
  assert.notEqual(JSON.stringify(r.next), JSON.stringify(x.sessions[x.aliceFp]), 'a new session to save');
});

test('F1 NEG2: after adoption, the contact\'s next continuation frame opens on the NEW session (no policy needed)', async () => {
  const x = await aliceResets();
  const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - 60e3), journal: '' + line(x.aliceFp, 'n_old', iso(NOW - 3600e3)) }));
  assert.ok(r);
  const r2 = await openTrFrame({ [x.aliceFp]: r.next }, x.aliceFp, x.me, peerOf(x.alice), x.f3);
  assert.ok(r2);
  assert.equal(r2.plaintext, 'second after the reset');
  assert.equal(r2.adopted, false);
});

test('F1 NEG3: a CONTINUATION frame of another, CONFIRMED session is never adopted, even when the policy says yes; nothing to save, row untouched', async () => {
  const x = await aliceResets();
  // A second session in which Alice HEARD BACK from ME (confirmed), so its later frames carry no handshake (an unconfirmed initiator's do, #318
  // N-R5f). ME's stored row is the other session, so receive() fails and only acceptFirst could open it, which a continuation never does.
  const a1 = TripleRatchet.initiate(x.alice, peerOf(x.me));
  const m1 = await TripleRatchet.acceptFirst(x.me, peerOf(x.alice), await a1.send('hello'));
  assert.ok(m1);
  assert.equal(await a1.receive(await m1.session.send('reply')), 'reply');
  const continuation = await a1.send('continuation of a confirmed session');
  const before = JSON.stringify(x.sessions);
  const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), continuation, async () => true);
  assert.equal(r, null);
  assert.equal(JSON.stringify(x.sessions), before);
});

test('F1 NEG4: replay guard: a first frame dated at or before the newest journaled note from that contact is refused', async () => {
  const x = await aliceResets();
  const newest = NOW - 600e3;
  const journal = line(x.aliceFp, 'n_a', iso(NOW - 7200e3)) + line(x.aliceFp, 'n_b', iso(newest));
  for (const sentAt of [iso(newest), iso(newest - 1)]) {
    const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt, journal }));
    assert.equal(r, null, `sentAt ${sentAt}`);
  }
  const ok = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(newest + 1), journal }));
  assert.ok(ok, 'control: 1 ms newer adopts');
});

test('F1 NEG4b: another contact\'s journal entries never count, and the CANDIDATE\'s own journal line (the loom notice poll-json writes before trOpen) is excluded', async () => {
  const x = await aliceResets();
  const sentAt = iso(NOW - 60e3);
  const journal = line('b'.repeat(64), 'n_other', iso(NOW)) + line(x.aliceFp, 'n_candidate', sentAt) + line(x.aliceFp, 'n_old', iso(NOW - 3600e3));
  const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt, journal, noteId: 'n_candidate' }));
  assert.ok(r, 'adopts: neither the other contact\'s newer note nor the candidate itself is a stored message from Alice');
});

test('F1 NEG5: dated beyond now + 5 min → refused; with NO journaled note from the contact, older than the relay window → refused', async () => {
  const x = await aliceResets();
  const future = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW + FUTURE_SLACK_MS + 1), journal: '' }));
  assert.equal(future, null);
  const stale = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - RELAY_WINDOW_MS - 1), journal: '' }));
  assert.equal(stale, null);
  const ok = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - 60e3), journal: '' }));
  assert.ok(ok, 'control: inside the window with no journal entries adopts');
});

test('F1 NEG6 (R6): both sides unconfirmed (simultaneous starts): headless = LOWER fp refuses, headless = HIGHER fp adopts', async () => {
  for (const [meFp, peerFp, adopts] of [[LO, HI, false], [HI, LO, true]] as const) {
    const me = ratchetIdentity(), alice = ratchetIdentity();
    const mine = TripleRatchet.initiate(me, peerOf(alice));
    await mine.send('my own first frame'); // ME started too and never heard back: unconfirmed
    const sessions: TrSessions = { [peerFp]: mine.exportState() };
    assert.equal(sessions[peerFp].recvCk, null);
    const fA = await TripleRatchet.initiate(alice, peerOf(me)).send('her first frame');
    const r = await openTrFrame(sessions, peerFp, me, peerOf(alice), fA, ask({ me: meFp, peer: peerFp, sentAt: iso(NOW - 60e3), journal: '' }));
    assert.equal(r !== null, adopts, `me ${meFp.slice(0, 1)} vs peer ${peerFp.slice(0, 1)}`);
  }
});

test('F1 NEG7: the journal cannot be read → refused (fail closed), nothing to save', async () => {
  const x = await aliceResets();
  const r = await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - 60e3), journal: () => { throw new Error('EACCES'); } }));
  assert.equal(r, null);
});

test('F1 NEG8: without a policy (the poll / loop display paths) the reset\'s first frame is NOT adopted; in devin-comm only poll-json passes one', async () => {
  const x = await aliceResets();
  assert.equal(await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2), null);
  const src = readFileSync(join(process.cwd(), 'scripts/devin-comm.ts'), 'utf8');
  const calls = [...src.matchAll(/trOpen\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g)].map((m) => m[1]).filter((a) => !a.includes('a: SerializedMintArtifact'));
  assert.equal(calls.length, 3, 'poll, poll-json, loop');
  assert.equal(calls.filter((a) => /\badopt\b|adoptFor\(/.test(a)).length, 1, 'exactly one call site (poll-json) passes the adopt policy');
});

test('F1 NEG9: attempt map: a refused adoption is charged +1, a successful one clears ONLY its own key, a tombstone stays; devin-comm never deletes attempts elsewhere', async () => {
  const x = await aliceResets();
  const attempts: Record<string, number> = { [`${x.aliceFp}:n_dead`]: 5, [`${x.aliceFp}:n_other`]: 2 };
  const key = `${x.aliceFp}:n_candidate`;
  const refuse = ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW + FUTURE_SLACK_MS + 1), journal: '' });
  const pt1 = await countedOpen(attempts, key, () => {}, async (charge) => { charge(); return (await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, refuse))?.plaintext ?? null; });
  assert.equal(pt1, null);
  assert.equal(attempts[key], 1, 'refused adoption = an ordinary failed open');
  const adopt = ask({ me: x.meFp, peer: x.aliceFp, sentAt: iso(NOW - 60e3), journal: '' });
  const pt2 = await countedOpen(attempts, key, () => {}, async (charge) => { charge(); return (await openTrFrame(x.sessions, x.aliceFp, x.me, peerOf(x.alice), x.f2, adopt))?.plaintext ?? null; });
  assert.equal(pt2, 'after the reset');
  assert.deepEqual(attempts, { [`${x.aliceFp}:n_dead`]: 5, [`${x.aliceFp}:n_other`]: 2 }, 'only its own key cleared; the tombstone and the other counter untouched');
  const src = readFileSync(join(process.cwd(), 'scripts/devin-comm.ts'), 'utf8');
  assert.equal((src.match(/delete attempts\[/g) ?? []).length, 0, 'no adoption path clears counters directly (countedOpen is the only place)');
  const loop = src.slice(src.indexOf("if (cmd === 'poll-json')"));
  assert.ok(loop.indexOf('>= MAX_ATTEMPTS') < loop.indexOf('countedOpen(attempts'), 'a tombstoned key is skipped BEFORE any open is tried');
});
