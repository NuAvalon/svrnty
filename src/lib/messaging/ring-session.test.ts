// src/lib/messaging/ring-session.test.ts
// Group fan-out over the hybrid triple ratchet, plus reply-thread fields.
// Run: npx tsx --test src/lib/messaging/ring-session.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '@/lib/crypto/pq';
import type { RatchetIdentity } from '@/lib/crypto/message-ratchet';
import { RingSession, type RingPeer } from './ring-session';
import { mainTimeline, replyCount, replyLink, sideThread } from './threads';

function identity(name: string): RatchetIdentity & { fingerprint: string } {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return {
    fingerprint: name,
    x25519Sec,
    x25519Pub: x25519.getPublicKey(x25519Sec),
    mlkem1024Sec: kem.secretKey,
    mlkem1024Pub: kem.publicKey,
  };
}

function peer(id: RatchetIdentity & { fingerprint: string }): RingPeer {
  return { fingerprint: id.fingerprint, x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub };
}

function note(over: { note_id: string; body: string; reply_to?: string; thread_root?: string }) {
  return {
    note_id: over.note_id,
    thread_id: 'thr_ring',
    sent_at: '2026-09-30T00:00:00.000Z',
    body: over.body,
    participant_kind: 'human' as const,
    reply_to: over.reply_to,
    thread_root: over.thread_root,
  };
}

test('fan-out: both other members open the note, a stranger and a removed member do not', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const carol = identity('carol');
  const dave = identity('dave');
  const members = [alice.fingerprint, bob.fingerprint, carol.fingerprint];

  const a = RingSession.create('ring_kin', alice.fingerprint, members);
  const sent = await a.send(alice, [peer(bob), peer(carol)], note({ note_id: 'note_1', body: 'evening' }));
  assert.deepEqual(sent.map((s) => s.fingerprint).sort(), ['bob', 'carol']);

  const b = RingSession.create('ring_kin', bob.fingerprint, members);
  const c = RingSession.create('ring_kin', carol.fingerprint, members);
  const openedB = await b.receive(bob, peer(alice), sent.find((s) => s.fingerprint === 'bob')!.packet);
  const openedC = await c.receive(carol, peer(alice), sent.find((s) => s.fingerprint === 'carol')!.packet);
  assert.equal(openedB?.body, 'evening');
  assert.equal(openedC?.body, 'evening');
  assert.equal(openedB?.sender_fp, 'alice');

  const d = RingSession.create('ring_kin', dave.fingerprint, [dave.fingerprint, alice.fingerprint]);
  assert.equal(await d.receive(dave, peer(alice), sent[0]!.packet), null);

  // Carol's copy of Bob's blob does not open under Carol's keys.
  assert.equal(
    await c.receive(carol, peer(alice), sent.find((s) => s.fingerprint === 'bob')!.packet),
    null,
  );
});

test('reply thread fields survive the fan-out', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const a = RingSession.create('ring_kin', alice.fingerprint, ['alice', 'bob']);
  const sent = await a.send(alice, [peer(bob)], note({
    note_id: 'note_2',
    body: 'in the thread',
    reply_to: 'note_1',
    thread_root: 'note_1',
  }));
  const b = RingSession.create('ring_kin', bob.fingerprint, ['alice', 'bob']);
  const opened = await b.receive(bob, peer(alice), sent[0]!.packet);
  assert.equal(opened?.reply_to, 'note_1');
  assert.equal(opened?.thread_root, 'note_1');
});

test('rekey drops the removed member; the one who stays can follow the new epoch', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const carol = identity('carol');
  const members = ['alice', 'bob', 'carol'];
  const a = RingSession.create('ring_kin', 'alice', members);
  const first = await a.send(alice, [peer(bob), peer(carol)], note({ note_id: 'note_1', body: 'all three' }));
  const b = RingSession.create('ring_kin', 'bob', members);
  const c = RingSession.create('ring_kin', 'carol', members);
  assert.equal((await b.receive(bob, peer(alice), first.find((s) => s.fingerprint === 'bob')!.packet))?.body, 'all three');
  assert.equal((await c.receive(carol, peer(alice), first.find((s) => s.fingerprint === 'carol')!.packet))?.body, 'all three');

  a.rekey(['alice', 'bob']);
  const second = await a.send(alice, [peer(bob)], note({ note_id: 'note_2', body: 'without carol' }));
  assert.deepEqual(second.map((s) => s.fingerprint), ['bob']);
  const followed = await b.receive(bob, peer(alice), second[0]!.packet);
  assert.equal(followed?.body, 'without carol');
  assert.equal(followed?.epoch, 2);
  assert.deepEqual(followed?.members.sort(), ['alice', 'bob']);
  assert.equal(b.epoch, 2);

  assert.equal(await c.receive(carol, peer(alice), second[0]!.packet), null, 'removed member cannot open the new epoch');
});

test('a second init at the same epoch does not clobber a live session', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const mallory = identity('mallory');
  const a = RingSession.create('ring_kin', 'alice', ['alice', 'bob']);
  const first = await a.send(alice, [peer(bob)], note({ note_id: 'note_1', body: 'real' }));
  const b = RingSession.create('ring_kin', 'bob', ['alice', 'bob']);
  assert.equal((await b.receive(bob, peer(alice), first[0]!.packet))?.body, 'real');

  const forged = RingSession.create('ring_kin', 'mallory', ['mallory', 'bob']);
  const evil = await forged.send(mallory, [peer(bob)], note({ note_id: 'note_x', body: 'fake' }));
  assert.equal(await b.receive(bob, peer(alice), evil[0]!.packet), null);

  const again = await a.send(alice, [peer(bob)], note({ note_id: 'note_2', body: 'still alice' }));
  assert.equal((await b.receive(bob, peer(alice), again[0]!.packet))?.body, 'still alice');
});

test('snapshot round-trip still opens the next note', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const a = RingSession.create('ring_kin', 'alice', ['alice', 'bob']);
  const first = await a.send(alice, [peer(bob)], note({ note_id: 'note_1', body: 'one' }));
  const restored = RingSession.importSnapshot(a.exportSnapshot());
  assert.ok(restored);
  const second = await restored!.send(alice, [peer(bob)], note({ note_id: 'note_2', body: 'two' }));
  const b = RingSession.create('ring_kin', 'bob', ['alice', 'bob']);
  assert.equal((await b.receive(bob, peer(alice), first[0]!.packet))?.body, 'one');
  const b2 = RingSession.importSnapshot(b.exportSnapshot());
  assert.equal((await b2!.receive(bob, peer(alice), second[0]!.packet))?.body, 'two');
});

test('(PCS) a snapshot from before our send cannot read the reply to that send', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const a = RingSession.create('ring_kin', 'alice', ['alice', 'bob']);
  const first = await a.send(alice, [peer(bob)], note({ note_id: 'note_1', body: 'setup' }));
  const b = RingSession.create('ring_kin', 'bob', ['alice', 'bob']);
  assert.ok(await b.receive(bob, peer(alice), first[0]!.packet));
  const seized = RingSession.importSnapshot(b.exportSnapshot());
  assert.ok(seized);

  const reply = await b.send(bob, [peer(alice)], note({ note_id: 'note_2', body: 'bob heals' }));
  assert.equal((await a.receive(alice, peer(bob), reply[0]!.packet))?.body, 'bob heals');
  const follow = await a.send(alice, [peer(bob)], note({ note_id: 'note_3', body: 'to the fresh kem' }));
  assert.equal((await b.receive(bob, peer(alice), follow[0]!.packet))?.body, 'to the fresh kem');
  assert.equal(await seized!.receive(bob, peer(alice), follow[0]!.packet), null);
});

test('history is sealed only to the person just added', async () => {
  const alice = identity('alice');
  const bob = identity('bob');
  const carol = identity('carol');
  const members = ['alice', 'bob', 'carol'];
  const a = RingSession.create('ring_kin', 'alice', members, 2);
  const history = [
    {
      note_id: 'note_1',
      sent_at: '2026-09-30T00:00:00.000Z',
      from_fingerprint: 'alice',
      body: 'before carol',
    },
  ];
  const bundle = await a.sendOne(alice, peer(carol), note({ note_id: 'note_h', body: '' }), history);
  assert.equal(bundle.fingerprint, 'carol');

  const carolSession = RingSession.create('ring_kin', 'carol', members, 2);
  const opened = await carolSession.receive(carol, peer(alice), bundle.packet);
  assert.equal(opened?.history?.length, 1);
  assert.equal(opened?.history?.[0]?.body, 'before carol');

  const bobSession = RingSession.create('ring_kin', 'bob', ['alice', 'bob'], 1);
  assert.equal(await bobSession.receive(bob, peer(alice), bundle.packet), null);

  const next = await a.send(alice, [peer(bob), peer(carol)], note({ note_id: 'note_2', body: 'after' }));
  assert.equal(next.find((s) => s.fingerprint === 'bob')?.packet === bundle.packet, false);
  const bobNow = RingSession.create('ring_kin', 'bob', members, 2);
  assert.equal((await bobNow.receive(bob, peer(alice), next.find((s) => s.fingerprint === 'bob')!.packet))?.body, 'after');
  const followed = await carolSession.receive(carol, peer(alice), next.find((s) => s.fingerprint === 'carol')!.packet);
  assert.equal(followed?.body, 'after');
  assert.equal(followed?.history, undefined);
});

test('a bad history item is refused before it is sealed', async () => {
  const alice = identity('alice');
  const carol = identity('carol');
  const a = RingSession.create('ring_kin', 'alice', ['alice', 'carol']);
  await assert.rejects(
    () => a.sendOne(alice, peer(carol), note({ note_id: 'note_h', body: '' }), [
      { note_id: 'note_1', sent_at: '2026-09-30T00:00:00.000Z', from_fingerprint: 'nope space', body: 'x' },
    ]),
    /bad history item/,
  );
});

test('side threads group under their root and stay off the main timeline', () => {
  const notes = [
    { note_id: 'note_1', sent_at: '1', body: 'root' },
    { note_id: 'note_2', sent_at: '2', body: 'main' },
    { note_id: 'note_3', sent_at: '3', reply_to: 'note_1', thread_root: 'note_1', body: 'reply' },
    { note_id: 'note_4', sent_at: '4', reply_to: 'note_3', thread_root: 'note_1', body: 'deeper' },
  ];
  assert.deepEqual(mainTimeline(notes).map((n) => n.note_id), ['note_1', 'note_2']);
  assert.equal(replyCount(notes, 'note_1'), 2);
  assert.deepEqual(sideThread(notes, 'note_1').map((n) => n.note_id), ['note_1', 'note_3', 'note_4']);
  assert.deepEqual(replyLink(notes, 'note_3'), { reply_to: 'note_3', thread_root: 'note_1' });
  assert.deepEqual(replyLink(notes, 'note_2'), { reply_to: 'note_2', thread_root: 'note_2' });
  assert.equal(replyLink(notes, 'missing'), null);
});
