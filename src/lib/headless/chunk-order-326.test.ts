// src/lib/headless/chunk-order-326.test.ts
// Run: npx tsx --test src/lib/headless/chunk-order-326.test.ts
//
// #326 (#712 group commit) x #335 (#713 headless dead-letter sink): the PINNED order at every ack chunk (Flint #189113/#189122):
//   store save → dead-letter flush → ack. No ack if either write fails.
// O1 the order NEG: it FAILS if an ack precedes either write (checked by event order AND by what is on disk at the moment of each ack).
// O2 a failing store save leaves the dead-letter ops STAGED (still in the sink, flushed later) and the chunk UNACKED.
// O3 #712 C2 x #713: a note refused at the commit re-apply (sender blocked meanwhile) is an honest 'not-in-book' LOSS whose row (with the
//    authenticated fp) is on disk before its ack, never acked unrecorded and never mislabelled 'verify-failed' (#332).
// O4 that row cannot be staged → that envelope is NOT acked (stays on the relay, unrecorded++); the rest of the chunk is.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
void createHash;
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { consumeInboundContactUpdates } from '@/lib/sync/consume-mailbox';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';
import { DEAD_LETTER_FILE } from './headless-dead-letter';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key,
  };
}
function owner(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig,
  };
}
function asContact(id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact {
  return { id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, trust_level: 'known', ...over };
}

/** In-memory smart mailbox. `acks` records every /ack body; `failAck(n)` makes the next n /ack calls throw (a kill after the commit). */
function mockRelay(onAck?: (ids: string[]) => void) {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  const acks: string[][] = [];
  let seq = 0;
  let failAcks = 0;
  let queueReply: 'ok' | 'refused' | 'unreadable' = 'ok';
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `env_${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/queue')) {
      if (queueReply === 'refused') return new Response('{}', { status: 401 });
      if (queueReply === 'unreadable') return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      const mid = new URL(u).searchParams.get('mailbox_id') ?? '';
      return new Response(JSON.stringify(boxes.get(mid) ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (u.includes('/ack')) {
      if (failAcks > 0) {
        failAcks--;
        throw new Error('killed between commit and ack');
      }
      const { mailbox_id, envelope_ids } = JSON.parse(String(init?.body ?? '{}'));
      onAck?.(envelope_ids);
      acks.push(envelope_ids);
      boxes.set(mailbox_id, (boxes.get(mailbox_id) ?? []).filter((e) => !envelope_ids.includes(e.envelope_id)));
      return new Response(JSON.stringify({ deleted: (envelope_ids as string[]).length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  const queued = () => [...boxes.values()].reduce((n, q) => n + q.length, 0);
  const listIds = () => [...boxes.values()].flat().map((e) => e.envelope_id);
  return { fetchImpl, acks, queued, listIds, failAck: (n: number) => { failAcks = n; }, reply: (r: typeof queueReply) => { queueReply = r; } };
}

function tmpBook(): { dir: string; path: string; open: () => HeadlessStore; hash: () => string; done: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'svrnty-712-'));
  const path = join(dir, 'store.json');
  return {
    dir, path,
    open: () => new HeadlessStore({ path, lockDir: dir }),
    hash: () => createHash('sha256').update(readFileSync(path)).digest('hex'),
    done: () => rmSync(dir, { recursive: true, force: true }),
  };
}

async function sendN(from: Id, to: Id, n: number, fetchImpl: typeof fetch, tag = 'n'): Promise<void> {
  const s = new HeadlessStore();
  for (let i = 0; i < n; i++) {
    const r = await sendNoteFromHeadless({ owner: owner(from), peerFingerprint: to.fp, peerPublicKeyArmored: to.pub, peerPqKemPublicKey: to.kem, body: `${tag} ${i}`, store: s, relayBase: RELAY, fetchImpl });
    assert.equal(r.deposited, true);
  }
}


function rows(path: string): DeadLetterRow[] {
  if (!existsSync(path)) return [];
  const out: DeadLetterRow[] = [];
  const walk = (v: unknown) => {
    if (v && typeof v === 'object') {
      if ('envelope_id' in v && 'reason' in v) out.push(v as DeadLetterRow);
      else for (const x of Object.values(v)) walk(x);
    }
  };
  walk(JSON.parse(readFileSync(path, 'utf8')));
  return out;
}

test('O1 ORDER NEG: every ack chunk is preceded by its store save, THEN its dead-letter flush; at each ack, its notes and loss rows are on disk', async () => {
  const [A, S, B] = [await mint(), await mint(), await mint()]; // A in B's book; S a stranger
  const events: string[] = [];
  const book = tmpBook();
  const dl = join(book.dir, DEAD_LETTER_FILE);
  const strangerIds = new Set<string>();
  const failures: string[] = [];
  const relay = mockRelay((ids) => {
    events.push('ack');
    // what is DURABLE at the moment this chunk is acked
    const onDisk = book.open().listNotes().length;
    const rowIds = new Set(rows(dl).map((r) => r.envelope_id));
    for (const id of ids) if (strangerIds.has(id) && !rowIds.has(id)) failures.push(`loss ${id} acked before its row was on disk`);
    if (onDisk < notesAckedSoFar(ids)) failures.push(`notes acked before the store write (${onDisk} on disk)`);
  });
  const aIds = new Set<string>();
  let aAcked = 0;
  const notesAckedSoFar = (ids: string[]) => (aAcked += ids.filter((id) => aIds.has(id)).length);
  try {
    const seed = book.open();
    seed.upsertContact(asContact(A));
    // 25 envelopes = chunks of 20 + 5, each with losses in it: 12 A, 2 S, 8 A, 3 S
    const plan: Array<[Id, number]> = [[A, 12], [S, 2], [A, 8], [S, 3]];
    for (const [who, n] of plan) {
      const before = new Set(relay.listIds());
      await sendN(who, B, n, relay.fetchImpl, who === A ? 'a' : 's');
      for (const id of relay.listIds()) if (!before.has(id)) (who === S ? strangerIds : aIds).add(id);
    }
    const store = book.open();
    const deps = await buildHeadlessConsumeDeps(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: dl });
    const commit = deps.chunk!.commit;
    deps.chunk!.commit = (live) => {
      const r = commit(live); // returns only after the store write
      events.push('store');
      return r;
    };
    const sink = deps.deadLetter!;
    const flush = sink.flush!;
    sink.flush = async () => {
      await flush.call(sink);
      events.push('dl');
    };
    const settle = sink.settle!;
    sink.settle = async () => {
      events.push('dl-before'); // settle WRITES staged rows: it must never run ahead of the store save of its chunk
      await settle.call(sink);
      events.push('dl');
    };
    const s = await consumeInboundContactUpdates(deps);
    assert.deepEqual(failures, []);
    assert.deepEqual(relay.acks.map((a) => a.length), [20, 5]);
    // the pinned sequence, per chunk: its store save FIRST, then a dead-letter write, then the ack. Any dead-letter write (flush or settle)
    // ahead of its chunk's store save, or an ack ahead of either, fails here.
    const segments = events.join(',').split('ack').slice(0, -1).map((x) => x.split(',').filter(Boolean));
    assert.equal(segments.length, 2, events.join(','));
    for (const seg of segments) {
      assert.equal(seg[0], 'store', `store save first in ${seg.join(',')}`);
      assert.ok(seg.slice(1).includes('dl'), `a dead-letter write after the store save, before the ack: ${seg.join(',')}`);
    }
    assert.equal(s.notes, 20);
    assert.equal(s.lost['not-in-book'], 5);
    assert.equal(s.deadLettered, 5);
    assert.equal(s.unrecorded, 0);
    assert.equal(rows(dl).filter((r) => r.reason === 'not-in-book' && r.fp === S.fp).length, 5, 'one row per loss, with the authenticated fp');
    assert.equal(relay.queued(), 0);
  } finally {
    book.done();
  }
});

test('O2 a failing STORE save: the chunk is NOT acked, and its dead-letter ops stay STAGED (nothing flushed, nothing lost); the next poll acks', async () => {
  const [A, S, B] = [await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  const dl = join(book.dir, DEAD_LETTER_FILE);
  try {
    const seed = book.open();
    seed.upsertContact(asContact(A));
    await sendN(A, B, 2, relay.fetchImpl, 'a');
    await sendN(S, B, 1, relay.fetchImpl, 's');
    const store = book.open();
    const deps = await buildHeadlessConsumeDeps(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: dl });
    deps.chunk!.commit = () => {
      throw new Error('disk full');
    };
    let flushes = 0;
    const sink = deps.deadLetter!;
    const flush = sink.flush!;
    sink.flush = async () => {
      flushes++;
      await flush.call(sink);
    };
    const settle = sink.settle!;
    sink.settle = async () => {
      flushes++;
      await settle.call(sink);
    };
    const s = await consumeInboundContactUpdates(deps);
    assert.equal(relay.acks.length, 0, 'no ack after a failed store save');
    assert.equal(relay.queued(), 3, 'all three stay on the relay');
    assert.equal(s.acked, 0);
    assert.equal(s.deadLettered, 0, 'nothing counts as recorded-then-acked');
    assert.equal(s.unrecorded, 3);
    assert.equal(flushes, 0, 'no dead-letter write (flush or settle) after a failed store save');
    assert.equal(rows(dl).length, 0, 'nothing written yet');
    // STAGED, not dropped: the same sink still holds the loss row and writes it at its next flush
    await flush.call(sink);
    assert.deepEqual(rows(dl).map((r) => [r.reason, r.fp]), [['not-in-book', S.fp]]);
    assert.equal(book.open().listNotes().length, 0, 'the failed chunk wrote no note');
    // the next (healthy) poll consumes all three
    const s2 = await consumeInboundContactUpdates(await buildHeadlessConsumeDeps(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: dl }));
    assert.equal(s2.acked, 3);
    assert.equal(s2.notes, 2);
    assert.equal(relay.queued(), 0);
    assert.equal(rows(dl).filter((r) => r.fp === S.fp).length, 1, 'still one row for the stranger (re-record keeps one)');
  } finally {
    book.done();
  }
});

async function blockedMidChunk(sinkWrap?: (real: NonNullable<Awaited<ReturnType<typeof buildHeadlessConsumeDeps>>['deadLetter']>) => NonNullable<Awaited<ReturnType<typeof buildHeadlessConsumeDeps>>['deadLetter']>) {
  const [X, Y, B] = [await mint(), await mint(), await mint()];
  const book = tmpBook();
  const dl = join(book.dir, DEAD_LETTER_FILE);
  const atAck: Array<{ ids: string[]; rows: DeadLetterRow[] }> = [];
  const relay = mockRelay((ids) => atAck.push({ ids, rows: rows(dl) }));
  const seed = book.open();
  seed.upsertContact(asContact(X));
  seed.upsertContact(asContact(Y));
  await sendN(X, B, 1, relay.fetchImpl, 'from-x');
  const xId = relay.listIds()[0];
  await sendN(Y, B, 1, relay.fetchImpl, 'from-y');
  const store = book.open();
  const other = book.open(); // another process on the same book
  const deps = await buildHeadlessConsumeDeps(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: dl });
  if (sinkWrap) deps.deadLetter = sinkWrap(deps.deadLetter!);
  const accept = deps.note!.accept;
  let calls = 0;
  deps.note!.accept = async (w) => {
    if (++calls === 2) other.updateContact(asContact(X).id, { blocked: true }); // X's note already accepted in memory
    return accept(w);
  };
  const s = await consumeInboundContactUpdates(deps);
  return { X, Y, s, relay, atAck, xId, dl, book };
}

test('O3 C2 x #713: a note refused at the commit re-apply is an honest not-in-book LOSS, its row (authenticated fp) on disk BEFORE its ack', async () => {
  const { X, Y, s, atAck, xId, dl, book } = await blockedMidChunk();
  try {
    assert.deepEqual(book.open().listNotes().map((n) => n.from_fingerprint), [Y.fp]);
    assert.equal(s.notes, 1);
    assert.equal(s.lost['not-in-book'], 1);
    assert.equal(s.lost['verify-failed'], undefined, '#332: never mislabelled as forged crypto');
    assert.equal(s.deadLettered, 1);
    assert.equal(s.acked, 2);
    const ackOfX = atAck.find((a) => a.ids.includes(xId));
    assert.ok(ackOfX, 'X is consumed (acked), like a sender blocked before the poll');
    assert.deepEqual(ackOfX!.rows.filter((r) => r.envelope_id === xId).map((r) => [r.reason, r.fp]), [['not-in-book', X.fp]], 'its row was durable at the moment of its ack');
    assert.equal(rows(dl).length, 1);
  } finally {
    book.done();
  }
});

test('O4 C2 x #713: the refused note\'s row cannot be staged → THAT envelope is NOT acked (stays on the relay); the rest of the chunk is', async () => {
  const { Y, s, relay, xId, book } = await blockedMidChunk((real) => ({
    ...real,
    record: async (row) => {
      if (row.reason === 'not-in-book') throw new Error('sink full');
      return real.record(row);
    },
  }));
  try {
    assert.deepEqual(book.open().listNotes().map((n) => n.from_fingerprint), [Y.fp]);
    assert.equal(s.acked, 1, 'only Y is acked');
    assert.deepEqual(relay.listIds(), [xId], 'X stays on the relay for a later poll, never acked unrecorded');
    assert.equal(s.unrecorded, 1);
    assert.equal(s.deadLettered, 0);
  } finally {
    book.done();
  }
});
