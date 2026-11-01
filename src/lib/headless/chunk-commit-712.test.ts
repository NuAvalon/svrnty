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
import { consumeInboundContactUpdates, envelopeDedupeKey, envelopeDedupeScope } from '@/lib/sync/consume-mailbox';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

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
      polled.add(mid);
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
  // the backlog of the mailbox(es) under test = the ones that were polled. Layer 1 receipts go back to the SENDERS' own mailboxes, which
  // these tests never poll, so they don't count here (receipts are pinned in receipts-layer1.test.ts).
  const polled = new Set<string>();
  const queued = () => [...boxes.entries()].filter(([m]) => polled.size === 0 || polled.has(m)).reduce((n, [, q]) => n + q.length, 0);
  const listIds = () => [...boxes.values()].flat().map((e) => e.envelope_id);
  const blobOf = (id: string) => [...boxes.values()].flat().find((e) => e.envelope_id === id)!.blob; // #737: the key hashes the blob too
  /** #737: a relay that lost `oldId` (DB wipe) and REISSUES that id for the envelope now stored as `newId`. */
  const reissue = (oldId: string, newId: string) => {
    for (const [m, q] of boxes) {
      const kept = q.filter((e) => e.envelope_id !== oldId).map((e) => (e.envelope_id === newId ? { ...e, envelope_id: oldId } : e));
      boxes.set(m, kept);
    }
  };
  return { fetchImpl, acks, queued, listIds, blobOf, reissue, failAck: (n: number) => { failAcks = n; }, reply: (r: typeof queueReply) => { queueReply = r; } };
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

/** Put dedupe entries straight into the (plaintext) book file, as an earlier poll would have. */
function plant(path: string, entries: Array<{ key: string; at?: string }>): void {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  raw.applied_envelopes = entries.map((e) => ({ key: e.key, at: e.at ?? new Date().toISOString() }));
  writeFileSync(path, JSON.stringify(raw));
}
const keysOnDisk = (path: string): string[] => (JSON.parse(readFileSync(path, 'utf8')).applied_envelopes ?? []).map((e: { key: string }) => e.key);

test('#712 C1 bound (Flint #2417): an entry whose envelope IS in the listing is kept by a commit (only an absent one is pruned)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl, 'already-stored');
    const listedKey = envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), relay.listIds()[0], relay.blobOf(relay.listIds()[0]))!;
    const goneKey = envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), 'env_long_gone', 'blob-of-env_long_gone')!;
    plant(book.path, [{ key: listedKey }, { key: goneKey }]);
    await sendN(A, B, 1, relay.fetchImpl, 'new');
    relay.failAck(1); // keep the state as the commit wrote it: the ack after it dies
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed/);
    const keys = keysOnDisk(book.path);
    assert.ok(keys.includes(listedKey), 'still listed by the relay: kept');
    assert.ok(!keys.includes(goneKey), 'absent from the whole listing: pruned');
    assert.equal(keys.length, 2, 'the listed entry + the note stored now');
  } finally {
    book.done();
  }
});

test('#712 C1 bound (Flint #2417): a REFUSED (401) or UNREADABLE (200, not a list) poll prunes nothing: the book is byte-identical', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    plant(book.path, [{ key: envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), 'env_absent', 'blob-of-env_absent')! }]);
    for (const r of ['refused', 'unreadable'] as const) {
      relay.reply(r);
      const pre = book.hash();
      await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      assert.equal(book.hash(), pre, `${r}: no write, no prune`);
    }
  } finally {
    book.done();
  }
});

test('#712 C1 bound (Flint #2417): a listing prunes only ITS relay + mailbox; another mailbox\'s and another relay\'s entries survive', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    const own = envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), 'env_absent', 'blob-of-env_absent')!;
    const otherMailbox = envelopeDedupeKey(RELAY, deriveMailboxId(A.fp), 'env_absent', 'blob-of-env_absent')!;
    const otherRelay = envelopeDedupeKey('http://other.test/api/relay', deriveMailboxId(B.fp), 'env_absent', 'blob-of-env_absent')!;
    assert.ok(own.startsWith(envelopeDedupeScope(RELAY, deriveMailboxId(B.fp)) + '.'));
    plant(book.path, [{ key: own }, { key: otherMailbox }, { key: otherRelay }]);
    await sendN(A, B, 1, relay.fetchImpl);
    await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const keys = keysOnDisk(book.path);
    assert.ok(!keys.includes(own), 'own scope, absent: pruned');
    assert.ok(keys.includes(otherMailbox), 'another mailbox: untouched');
    assert.ok(keys.includes(otherRelay), 'another relay: untouched');
  } finally {
    book.done();
  }
});

test('#712 C1 bound: an entry older than 7 days in a scope NO listing covers is gone after the next real commit (Apollo #2429)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    const old = new Date(Date.now() - 8 * 864e5).toISOString();
    const staleElsewhere = envelopeDedupeKey('http://other.test/api/relay', deriveMailboxId(B.fp), 'env_old', 'blob-of-env_old')!;
    const freshElsewhere = envelopeDedupeKey('http://other.test/api/relay', deriveMailboxId(B.fp), 'env_new', 'blob-of-env_new')!;
    plant(book.path, [{ key: staleElsewhere, at: old }, { key: freshElsewhere }]);
    await sendN(A, B, 1, relay.fetchImpl);
    await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const keys = keysOnDisk(book.path);
    assert.ok(!keys.includes(staleElsewhere), 'past the TTL: gone, whatever its scope');
    assert.ok(keys.includes(freshElsewhere), 'control: a fresh entry of another scope stays');
  } finally {
    book.done();
  }
});

test('#712 C1 PIN: the relay lists a mailbox WHOLE (no LIMIT/OFFSET, no slice in /queue). If this goes red, C1 must switch to a per-poll write (Flint #2417 binding)', () => {
  const store = readFileSync(join(process.cwd(), 'src/lib/relay/mailbox-store.ts'), 'utf8');
  const fn = store.slice(store.indexOf('export function pollMailbox('), store.indexOf('export function ackDelete('));
  assert.ok(fn.includes('SELECT envelope_id, blob, expires_at FROM envelopes WHERE mailbox_id = ?'), 'found the listing query');
  assert.doesNotMatch(fn, /\bLIMIT\b|\bOFFSET\b/i, 'pollMailbox must not page or cap: #712 C1 prunes on absence from this listing');
  const route = readFileSync(join(process.cwd(), 'app/api/relay/queue/route.ts'), 'utf8');
  assert.match(route, /const list = pollMailbox\(mailboxId, Date\.now\(\)\)\.map\(/, 'the route returns the whole listing');
  assert.doesNotMatch(route, /\.slice\(|\.splice\(|\.filter\(|limit|cursor|page/i, 'the route must not page, cap or filter the listing: #712 C1');
});

/** Age every dedupe entry on disk by `days` (as if the book had sat that long since the commit that wrote them). */
function ageEntries(path: string, days: number): void {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  for (const e of raw.applied_envelopes ?? []) e.at = new Date(Date.now() - days * 864e5).toISOString();
  writeFileSync(path, JSON.stringify(raw));
}

// G-RO-5 (#326 L1): the relay's envelope TTL is configurable (RELAY_ENVELOPE_TTL_MS), so a committed-but-unacked envelope can still be
// listed after 7 days. Inside its own listing, membership decides, never age. This fixture is a hybrid note: on the old rule it was simply
// opened again (counted as a new note). For a ratchet frame, whose key the first open spent, that second open fails and records a loss
// for a message that is safely stored (consume-mailbox.ts C1 comment). The pin is the mechanism: never opened a second time. (Replaces "#712 C1 TTL: an entry older than 7 days never
// suppresses an open": that test planted an entry for a note no commit held, a state commitChunk never writes.)
test('G-RO-5 NEG: kill between commit and ack, the entry 10 DAYS old, the envelope still listed -> acked WITHOUT opening it a second time; stored once', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl);
    relay.failAck(1);
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed between commit and ack/);
    assert.equal(book.open().appliedEnvelopeCount(), 1, 'the commit wrote the entry');
    ageEntries(book.path, 10);
    assert.equal(relay.queued(), 1, 'a relay TTL > 7 d still lists it');

    const s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.deduped, 1, 'still listed: trusted, whatever its age');
    assert.equal(s.opened_hybrid + s.opened_classical, 0, 'never opened a second time');
    assert.equal(s.acked, 1);
    assert.equal(s.notes, 0);
    assert.equal(s.deadLettered, 0);
    assert.deepEqual(s.lost, {}, 'nothing recorded as lost');
    assert.equal(relay.queued(), 0);
    assert.equal(book.open().listNotes().length, 1, 'stored exactly once');
  } finally {
    book.done();
  }
});

test('G-RO-5 bound: in the listing\'s OWN scope a 10-day-old entry is KEPT while listed and PRUNED once absent; another scope\'s 10-day-old entry is pruned by age', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl, 'already-stored');
    const old = new Date(Date.now() - 10 * 864e5).toISOString();
    const listedOld = envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), relay.listIds()[0], relay.blobOf(relay.listIds()[0]))!;
    const goneOld = envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), 'env_long_gone', 'blob-of-env_long_gone')!;
    const elsewhereOld = envelopeDedupeKey('http://other.test/api/relay', deriveMailboxId(B.fp), 'env_old', 'blob-of-env_old')!;
    plant(book.path, [{ key: listedOld, at: old }, { key: goneOld, at: old }, { key: elsewhereOld, at: old }]);
    await sendN(A, B, 1, relay.fetchImpl, 'new');
    relay.failAck(1); // keep the state as the commit wrote it: the ack after it dies
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed/);
    const keys = keysOnDisk(book.path);
    assert.ok(keys.includes(listedOld), 'own scope, still listed, 10 days old: kept (membership beats age)');
    assert.ok(!keys.includes(goneOld), 'own scope, absent from the whole listing: pruned');
    assert.ok(!keys.includes(elsewhereOld), 'another scope, past the age bound: pruned (no listing speaks for it)');
    assert.equal(keys.length, 2, 'the listed old entry + the note stored now');
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
    raw.applied_envelopes = [{ key: envelopeDedupeKey(RELAY, deriveMailboxId(B.fp), relay.listIds()[0], relay.blobOf(relay.listIds()[0])), at: new Date().toISOString() }];
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
    // #332: a sender blocked before the poll is an honest 'not-in-book' loss, never 'verify-failed' (Peter→Athena 10-31); same here
    assert.equal(s.lost['not-in-book'], 1, 'same accounting as a sender blocked before the poll');
    assert.equal(s.lost['verify-failed'], undefined, 'never mislabelled as forged crypto');
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
    assert.equal(s.notes, 0, 'a chunk that was never written is not counted as stored (Apollo #2429)');
    assert.equal(relay.queued(), 2);
    assert.equal(store.listNotes().length, 0, 'the in-memory copy was rolled back to the disk');
    const again = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(again.notes, 2);
    assert.equal(relay.queued(), 0);
  } finally {
    book.done();
  }
});

test('#712 S1 two chunks (Apollo #2440 r2): chunk 1 is written, chunk 2\'s write fails -> counts keep chunk 1, chunk 2 is only `unrecorded`', async () => {
  const [A, B] = [await mint(), await mint()];
  const book = tmpBook();
  let locked = false;
  const relay = mockRelay(() => {
    if (!locked) {
      locked = true;
      chmodSync(book.dir, 0o500); // after chunk 1's ack: chunk 2's commit can neither lock nor rename
    }
  });
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 25, relay.fetchImpl);
    let s;
    try {
      s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    } finally {
      chmodSync(book.dir, 0o700);
    }
    assert.deepEqual(relay.acks.map((a) => a.length), [20], 'only chunk 1 acked');
    assert.equal(s.notes, 20, 'chunk 1 WAS written: its notes still count');
    assert.equal(s.unrecorded, 5, 'chunk 2 was never written');
    assert.equal(s.acked, 20);
    assert.equal(relay.queued(), 5);
    assert.equal(book.open().listNotes().length, 20);
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

// #737 (Archie lane:svrnty #3222, Flint #3224): the blob's hash is in the dedupe key.
test('#737 NEG: a relay that REISSUES a committed id for a NEW message: the new one is OPENED and stored, never acked unopened', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl, 'first');
    relay.failAck(1);
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed between commit and ack/);
    assert.equal(book.open().appliedEnvelopeCount(), 1, 'the commit holds "first" under its id');
    const [oldId] = relay.listIds();
    await sendN(A, B, 1, relay.fetchImpl, 'second');
    const newId = relay.listIds().find((id) => id !== oldId)!;
    relay.reissue(oldId, newId); // the relay lost "first" and hands "second" the SAME id
    assert.deepEqual(relay.listIds(), [oldId]);
    const s = await pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.deduped, 0, 'a different blob behind a known id is NOT the stored envelope');
    assert.equal(s.opened_hybrid + s.opened_classical, 1, 'opened (loud), not acked unopened (silent)');
    assert.equal(s.notes, 1);
    assert.deepEqual(book.open().listNotes().map((n) => n.body).sort(), ['first 0', 'second 0'], 'both messages are in the book');
  } finally {
    book.done();
  }
});

test('#737 upgrade window, stated: a v1-format (id-only) own-scope entry does not match, so that envelope is opened once more; the commit prunes the v1 entry', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const book = tmpBook();
  try {
    book.open().upsertContact(asContact(A));
    await sendN(A, B, 1, relay.fetchImpl, 'pre-upgrade');
    const [id] = relay.listIds();
    const mbx = deriveMailboxId(B.fp);
    const v1 = `${envelopeDedupeScope(RELAY, mbx)}.${createHash('sha256').update(`svrnty:applied-envelope:v1|${RELAY}|${mbx}|${id}`).digest('hex')}`;
    plant(book.path, [{ key: v1 }]); // what a pre-#737 commit wrote, its ack killed before the upgrade
    relay.failAck(1); // keep the state the commit writes
    await assert.rejects(pollHeadlessOnce(owner(B), book.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), /killed/);
    const keys = keysOnDisk(book.path);
    assert.ok(!keys.includes(v1), 'own scope, absent from the listing\'s (v2) keys: pruned at this commit, not 7 d later');
    assert.deepEqual(keys, [envelopeDedupeKey(RELAY, mbx, id, relay.blobOf(id))], 'only the v2 key of the envelope opened now');
  } finally {
    book.done();
  }
});
