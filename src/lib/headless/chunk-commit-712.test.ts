// src/lib/headless/chunk-commit-712.test.ts
// Run: npx tsx --test src/lib/headless/chunk-commit-712.test.ts
//
// #712 (Flint S1-S5 #183639, ruling #2379 C1 + C2, Archie #2381 time budget): a headless poll writes the store ONCE per ack chunk
// (<= 20 envelopes), never acks an envelope before the write that holds it, dedupes a redelivered envelope by its relay id BEFORE
// opening it, lets a block that landed mid-chunk win over the re-apply, and stops between envelopes when its time budget runs out.
// Real minted identities + real hybrid sends against an in-memory relay; the receiver's store is file-backed with the writer lock.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { consumeInboundContactUpdates, envelopeDedupeKey } from '@/lib/sync/consume-mailbox';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
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
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `env_${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/queue')) {
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
  return { fetchImpl, acks, queued, listIds, failAck: (n: number) => { failAcks = n; } };
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

test('#712 S3: 25 notes in one poll = ONE store write per ack chunk (2), not one per note; every note stored once; 2 ack requests', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    const seed = book.open();
    seed.upsertContact(asContact(A));
    await sendN(A, B, 25, relay.fetchImpl);
    const store = book.open();
    const before = store.writes;
    const s = await pollHeadlessOnce(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.notes, 25);
    assert.equal(s.acked, 25);
    assert.equal(store.writes - before, 2, 'ceil(25/20) store writes for the whole poll');
    assert.deepEqual(relay.acks.map((a) => a.length), [20, 5]);
    const onDisk = book.open().listNotes();
    assert.equal(onDisk.length, 25);
    assert.equal(new Set(onDisk.map((n) => n.note_id)).size, 25);
    assert.equal(book.open().listThreads().length, 1, 'one sender, one thread: written with the notes');
    assert.equal(relay.queued(), 0);
  } finally {
    book.done();
  }
});

test('#712 S1 order: when EACH ack request arrives (mid-poll chunk AND the last partial one), the disk already holds every note it acks', async () => {
  const [A, B] = [await mint(), await mint()];
  const book = tmpBook();
  const onDiskAtAck: number[] = [];
  const relay = mockRelay(() => onDiskAtAck.push(book.open().listNotes().length));
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 25, relay.fetchImpl);
    await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.deepEqual(relay.acks.map((a) => a.length), [20, 5]);
    assert.deepEqual(onDiskAtAck, [20, 25], 'each chunk was written before its ack went out');
  } finally {
    book.done();
  }
});

test('#712 S2 (kill BEFORE commit): mid-chunk, an accepted note is NOT on disk yet and nothing was acked', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 3, relay.fetchImpl);
    const store = book.open();
    const pre = book.hash();
    const deps = await buildHeadlessConsumeDeps(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const accept = deps.note!.accept;
    let calls = 0;
    let midHash = '';
    let midAcks = -1;
    deps.note!.accept = async (w) => {
      if (++calls === 3) {
        midHash = book.hash(); // two notes accepted in memory; a kill here loses nothing on disk and acks nothing
        midAcks = relay.acks.length;
      }
      return accept(w);
    };
    const s = await consumeInboundContactUpdates(deps);
    assert.equal(midHash, pre, 'the store file is unchanged until the chunk commit');
    assert.equal(midAcks, 0, 'no ack before the commit');
    assert.equal(s.notes, 3);
    assert.equal(book.open().listNotes().length, 3);
  } finally {
    book.done();
  }
});

test('#712 C1: kill between commit and ack -> next poll acks the envelope WITHOUT opening it; stored once, nothing dead-lettered or held', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl);
    relay.failAck(1);
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed between commit and ack/);
    assert.equal(book.open().listNotes().length, 1, 'committed before the ack');
    assert.equal(relay.queued(), 1, 'the relay still holds it');

    const s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.deduped, 1, 'recognised by its envelope id');
    assert.equal(s.opened_hybrid + s.opened_classical, 0, 'never opened a second time');
    assert.equal(s.acked, 1);
    assert.equal(s.notes, 0);
    assert.equal(s.held, 0);
    assert.equal(s.deadLettered, 0);
    assert.deepEqual(s.lost, {});
    assert.equal(relay.queued(), 0);
    assert.equal(book.open().listNotes().length, 1, 'stored exactly once');
  } finally {
    book.done();
  }
});

test('#712 C1 bound: an entry leaves the dedupe set once a later poll\'s FULL listing no longer has it (acked or expired)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl, 'first');
    await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(book.open().appliedEnvelopeCount(), 1, 'acked in the last chunk of a one-process poll: still listed until a later commit');
    await sendN(A, B, 1, relay.fetchImpl, 'second');
    await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(book.open().appliedEnvelopeCount(), 1, 'the first id was not in the second listing, so it was dropped; only the newest remains');
  } finally {
    book.done();
  }
});

test('#712 C1 TTL: an entry older than 7 days never suppresses an open (the envelope is opened and stored normally)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl);
    const raw = JSON.parse(readFileSync(book.path, 'utf8'));
    const id = relay.listIds()[0];
    raw.applied_envelopes = [{ key: envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), id), at: new Date(Date.now() - 8 * 864e5).toISOString() }];
    writeFileSync(book.path, JSON.stringify(raw));
    const s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.deduped, 0, 'a stale entry is ignored');
    assert.equal(s.notes, 1);
    assert.equal(book.open().listNotes().length, 1);
  } finally {
    book.done();
  }
});

test('#712 C1 control: a FRESH entry for a listed envelope IS acked without opening (the key the test computes = the key consume uses)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl);
    const raw = JSON.parse(readFileSync(book.path, 'utf8'));
    raw.applied_envelopes = [{ key: envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), relay.listIds()[0]), at: new Date().toISOString() }];
    writeFileSync(book.path, JSON.stringify(raw));
    const s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.deduped, 1);
    assert.equal(s.opened_hybrid + s.opened_classical, 0);
  } finally {
    book.done();
  }
});

test('#712 C2: X blocked by a concurrent writer mid-chunk -> X\'s note is NOT stored; an unrelated concurrent contact add survives', async () => {
  const [X, Y, Z, B] = [await mint(), await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    const seed = book.open();
    seed.upsertContact(asContact(X));
    seed.upsertContact(asContact(Y));
    await sendN(X, B, 1, relay.fetchImpl, 'from-x');
    await sendN(Y, B, 1, relay.fetchImpl, 'from-y');
    const store = book.open();
    const other = book.open(); // another process on the same book
    const deps = await buildHeadlessConsumeDeps(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const accept = deps.note!.accept;
    let calls = 0;
    deps.note!.accept = async (w) => {
      if (++calls === 2) {
        // X's note is already accepted in memory; now the user blocks X (and adds Z) from another process, before the commit.
        other.updateContact(asContact(X).id, { blocked: true });
        other.upsertContact(asContact(Z));
      }
      return accept(w);
    };
    const s = await consumeInboundContactUpdates(deps);
    const after = book.open();
    assert.deepEqual(after.listNotes().map((n) => n.from_fingerprint), [Y.fp], 'only Y\'s note is stored');
    assert.equal(after.listThreads().length, 1, 'no thread for the blocked sender');
    assert.equal(after.getContactByFingerprint(X.fp)?.blocked, true, 'the block survives the commit');
    assert.ok(after.getContactByFingerprint(Z.fp), 'control: the unrelated concurrent contact add survives');
    assert.equal(s.notes, 1);
    assert.equal(s.lost['verify-failed'], 1, 'same accounting as a sender blocked before the poll');
    assert.equal(s.acked, 2, 'X\'s envelope is consumed exactly like a blocked sender\'s today');
  } finally {
    book.done();
  }
});

test('#712 S1: a commit that fails sends NO ack for that chunk; the envelopes stay on the relay and arrive on the next poll', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 2, relay.fetchImpl);
    const store = book.open();
    chmodSync(book.dir, 0o500); // the lock + the atomic rename both need a writable dir: the chunk commit throws
    let s;
    try {
      s = await pollHeadlessOnce(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    } finally {
      chmodSync(book.dir, 0o700);
    }
    assert.equal(relay.acks.length, 0, 'no ack request at all');
    assert.equal(s.acked, 0);
    assert.equal(s.unrecorded, 2, 'visible: consumed but not committed, so left on the relay');
    assert.equal(relay.queued(), 2);
    assert.equal(store.listNotes().length, 0, 'the in-memory copy was rolled back to the disk');
    const again = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(again.notes, 2);
    assert.equal(relay.queued(), 0);
  } finally {
    book.done();
  }
});

test('#712 time budget: the pass stops between envelopes before the watchdog, commits + acks what it consumed; the next pass resumes there', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 25, relay.fetchImpl);
    let t = 0;
    const nowMs = () => ++t; // build reads t=1 -> deadline 24; the check before envelope i reads 1+i -> stops before the 23rd
    const store = book.open();
    const before = store.writes;
    const s1 = await pollHeadlessOnce(owner(B), store, { relayBase: RELAY, fetchImpl: relay.fetchImpl, budgetMs: 23, nowMs });
    assert.equal(s1.notes, 22);
    assert.equal(s1.acked, 22);
    assert.equal(s1.deferred, 3, 'visible: left for the next pass');
    assert.equal(store.writes - before, 2, 'the full chunk and the partial one each committed once');
    assert.equal(relay.queued(), 3);
    const s2 = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, budgetMs: 60_000 });
    assert.equal(s2.notes, 3);
    assert.equal(s2.deferred, 0);
    const notes = book.open().listNotes();
    assert.equal(notes.length, 25);
    assert.equal(new Set(notes.map((n) => n.body)).size, 25, 'no note lost, none twice');
  } finally {
    book.done();
  }
});
