// src/lib/headless/receipts-layer1.test.ts
// Run: npx tsx --test src/lib/headless/receipts-layer1.test.ts
//
// Layer 1 (spec v1 65bac8aa; Flint C1-C4, Hypatia, Archie): headless agents send and verify "Delivered" receipts, with the SAME MAC, wire and
// hybrid seal as the FE. Real minted identities, real hybrid seals, an in-memory relay with one box per mailbox, file-backed stores with the
// writer lock. Each spec NEG is one test below (N1-N9), plus the end-to-end round trip (E1).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
void createHash;
import { mintHeadlessAgent, serializeMintArtifact } from '@/lib/identity/headless-mint';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { consumeInboundContactUpdates } from '@/lib/sync/consume-mailbox';
import type { DeadLetterRow } from '@/lib/sync/dead-letter';
import { DEAD_LETTER_FILE } from './headless-dead-letter';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, pickReceipts, pollHeadlessOnce, receiptsPerPoll, sendHeadlessReceipts, sendNoteFromHeadless } from './headless-client';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { buildReceiptWireV1 } from '@/lib/messaging/receipt-wire-v1';
import { sealReceiptV1To } from '@/lib/messaging/seal';
import { receiptKeyToHex, newReceiptKey } from '@/lib/crypto/receipt-mac';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { HOP_TRAIL_FILE, readHopTrail, recordHop } from './hop-trail';
import { spawnSync } from 'node:child_process';
import { statSync, writeFileSync } from 'node:fs';

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


const mbox = (id: Id) => deriveMailboxId(id.fp);
/** A's persistent store (so its outbound row + receipt key survive to A's own poll). */
function agentBook() {
  const b = tmpBook();
  return { ...b, store: b.open() };
}
async function send(from: Id, to: Id, store: HeadlessStore, fetchImpl: typeof fetch, body = 'hello', extra: { noteId?: string; sentAt?: string } = {}) {
  const r = await sendNoteFromHeadless({ owner: owner(from), peerFingerprint: to.fp, peerPublicKeyArmored: to.pub, peerPqKemPublicKey: to.kem, body, store, relayBase: RELAY, fetchImpl, ...extra });
  assert.equal(r.deposited, true);
  return r;
}
/** Envelopes waiting in one mailbox (the mock lists per mailbox). */
async function inbox(relay: ReturnType<typeof mockRelay>, id: Id): Promise<Array<{ envelope_id: string; blob: string }>> {
  const res = await relay.fetchImpl(`${RELAY}/queue?mailbox_id=${encodeURIComponent(mbox(id))}`);
  return (await res.json()) as Array<{ envelope_id: string; blob: string }>;
}
async function deposit(relay: ReturnType<typeof mockRelay>, to: Id, blob: string) {
  await relay.fetchImpl(`${RELAY}/envelope`, { method: 'POST', body: JSON.stringify({ mailbox_id: mbox(to), blob }) });
}

test('E1 round trip: A→B note; B stores it and sends ONE receipt; A verifies it → delivered:true, the key gone, delivered 1; one store write', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = agentBook();
  const b = tmpBook();
  try {
    a.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(A));
    const { note_id } = await send(A, B, a.store, relay.fetchImpl, 'ping');
    const rk = a.store.findOutboundNote(A.fp, note_id)?.receipt_key;
    assert.match(rk ?? '', /^[0-9a-f]{64}$/, 'S1: our outbound row keeps the key');
    const sb = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(sb.notes, 1);
    assert.equal(sb.receipts_sent, 1);
    assert.equal((await inbox(relay, A)).length, 1, 'one receipt in A\'s mailbox');
    const before = a.store.writes;
    const sa = await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(sa.delivered, 1);
    assert.equal(sa.receipts_sent, 0, 'a receipt never earns a receipt');
    assert.equal(a.store.writes - before, 1, 'C1: the delivered rewrite rode the poll\'s ONE chunk write');
    const row = a.open().findOutboundNote(A.fp, note_id)!;
    assert.equal(row.delivered, true);
    assert.equal(row.receipt_key, undefined, 'the key dies with the confirmation');
    assert.equal(a.open().listNotes().length, 1, 'N6: a receipt is never stored as a note');
    assert.equal((await inbox(relay, A)).length, 0, 'the receipt envelope was acked');
  } finally {
    a.done();
    b.done();
  }
});

test('F-RL (Apollo #3227): a receipt the relay REFUSES (429, its per-IP deposit limit) is counted receipts_failed, never receipts_sent; not retried', async () => {
  const [A, B] = [await mint(), await mint()];
  const base = mockRelay();
  let refuse = false;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (refuse && String(url).includes('/envelope')) return new Response('{"error":"rate limited"}', { status: 429 });
    return base.fetchImpl(url, init);
  }) as unknown as typeof fetch;
  const a = agentBook();
  const b = tmpBook();
  try {
    a.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(A));
    await send(A, B, a.store, fetchImpl, 'one');
    await send(A, B, a.store, fetchImpl, 'two');
    refuse = true; // B's receipt deposits hit the limit
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl, receiptsPerPoll: 10 }); // cap out of the way: this pins the FAILED count
    assert.equal(s.notes, 2, 'the notes themselves are stored');
    assert.equal(s.receipts_sent, 0);
    assert.equal(s.receipts_failed, 2, 'both refused receipts are COUNTED, not silent');
    assert.equal(s.receipts_skipped, 0);
    refuse = false;
    const again = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl });
    assert.equal(again.receipts_sent + again.receipts_failed, 0, 'not retried (a named limit: those notes stay "Sent to the relay" for A)');
    assert.equal((await inbox({ ...base, fetchImpl }, A)).length, 0, 'no receipt reached A');
  } finally {
    a.done();
    b.done();
  }
});

test('N1 no receipt unless persisted: a stranger, a blocked sender, a FWW refusal, a failed chunk write and a C2 block each send NONE', async () => {
  const [A, B] = [await mint(), await mint()];
  // (a) stranger (not in B's book) and (b) blocked
  for (const contact of [null, { blocked: true }] as const) {
    const relay = mockRelay();
    const b = tmpBook();
    try {
      const bs = b.open();
      if (contact) bs.upsertContact(asContact(A, contact));
      await send(A, B, new HeadlessStore(), relay.fetchImpl);
      const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      assert.equal(s.notes, 0);
      assert.equal(s.receipts_sent, 0);
      assert.equal((await inbox(relay, A)).length, 0, contact ? 'blocked: no receipt' : 'stranger: no receipt (no liveness oracle)');
    } finally {
      b.done();
    }
  }
  // (c) a failed chunk write: the note is not durable → no receipt (and it stays on the relay)
  {
    const relay = mockRelay();
    const b = tmpBook();
    try {
      const bs = b.open();
      bs.upsertContact(asContact(A));
      await send(A, B, new HeadlessStore(), relay.fetchImpl);
      const deps = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      deps.chunk!.commit = () => {
        throw new Error('disk full');
      };
      await consumeInboundContactUpdates(deps);
      const r = await deps.sendReceipts();
      assert.deepEqual(r, { sent: 0, skipped: 1, failed: 0, capped: 0 });
      assert.equal((await inbox(relay, A)).length, 0);
      assert.equal((await inbox(relay, B)).length, 1, 'the note stays on the relay');
    } finally {
      b.done();
    }
  }
  // (d) C2: the sender is blocked by a concurrent writer before the chunk commit → the note is not stored → no receipt
  {
    const [X, Y] = [await mint(), await mint()];
    const relay = mockRelay();
    const b = tmpBook();
    try {
      const seed = b.open();
      seed.upsertContact(asContact(X));
      seed.upsertContact(asContact(Y));
      await send(X, B, new HeadlessStore(), relay.fetchImpl, 'x');
      await send(Y, B, new HeadlessStore(), relay.fetchImpl, 'y');
      const bs = b.open();
      const other = b.open();
      const deps = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      const accept = deps.note!.accept;
      let calls = 0;
      deps.note!.accept = async (w) => {
        if (++calls === 2) other.updateContact(asContact(X).id, { blocked: true });
        return accept(w);
      };
      await consumeInboundContactUpdates(deps);
      const r = await deps.sendReceipts();
      assert.equal(r.sent, 1, 'Y only');
      assert.equal((await inbox(relay, X)).length, 0, 'X (blocked before the commit) gets no receipt');
      assert.equal((await inbox(relay, Y)).length, 1);
    } finally {
      b.done();
    }
  }
});

test('N2 static: the headless path never builds a receipt itself and names no code but delivered (never read / seen / opened)', () => {
  // code only: comments may name the forbidden codes to explain the rule
  const src = readFileSync(join(__dirname, 'headless-client.ts'), 'utf8').split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).map((l) => l.replace(/\s\/\/ .*$/, '')).join('\n');
  assert.doesNotMatch(src, /buildReceiptWireV1\(/, 'the wire is built only inside emitDeliveredReceipt, which hard-codes delivered');
  assert.doesNotMatch(src, /['"](read|seen|opened)['"]/);
  const emit = readFileSync(join(__dirname, '../messaging/receipt-emit.ts'), 'utf8');
  assert.deepEqual([...emit.matchAll(/buildReceiptWireV1\([^)]*\)/g)].map((m) => /'delivered'\)$/.test(m[0])), [true]);
});

test('N3 no downgrade: a sender with no ML-KEM key gets no receipt', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A));
    await send(A, B, new HeadlessStore(), relay.fetchImpl);
    const deps = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const accept = deps.note!.accept;
    let wire: NoteWireV0 | undefined;
    deps.note!.accept = async (w) => {
      wire = w;
      return accept(w);
    };
    await consumeInboundContactUpdates(deps);
    assert.ok(wire);
    // the same stored, admitted note, but its (signature-bound) wire carries no kem key: emitDeliveredReceipt must refuse it
    const kemless = { ...wire!, pq_kem_public_key: undefined } as NoteWireV0;
    const r = await sendHeadlessReceipts(bs, new Map([[`${A.fp}:${kemless.note_id}`, kemless]]), { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.deepEqual(r, { sent: 0, skipped: 1, failed: 0, capped: 0 });
    assert.equal((await inbox(relay, A)).length, 0);
  } finally {
    b.done();
  }
});

test('N4 canary: the receipt key never reaches stdout/stderr, the dead-letter file, or any file in the agent dir but the store', async () => {
  const [A, B, S] = [await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const a = agentBook();
  const b = tmpBook();
  const said: string[] = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info };
  const cap = (...x: unknown[]) => void said.push(x.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join(' '));
  const outW = process.stdout.write.bind(process.stdout);
  const errW = process.stderr.write.bind(process.stderr);
  try {
    a.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(A));
    console.log = console.error = console.warn = console.info = cap;
    (process.stdout as unknown as { write: unknown }).write = (c: unknown) => (said.push(String(c)), true);
    (process.stderr as unknown as { write: unknown }).write = (c: unknown) => (said.push(String(c)), true);
    const { note_id } = await send(A, B, a.store, relay.fetchImpl, 'canary');
    const rk = a.store.findOutboundNote(A.fp, note_id)!.receipt_key!;
    await send(S, B, new HeadlessStore(), relay.fetchImpl, 'stranger'); // a loss → a dead-letter row in B's dir
    await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: join(b.dir, DEAD_LETTER_FILE) });
    await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl, deadLetterPath: join(a.dir, DEAD_LETTER_FILE) });
    Object.assign(console, orig);
    process.stdout.write = outW;
    process.stderr.write = errW;
    assert.ok(rk.length === 64);
    assert.equal(said.filter((l) => l.includes(rk)).length, 0, 'never in any output');
    for (const dir of [a.dir, b.dir]) {
      for (const f of readdirSync(dir)) {
        // store.json and its own previous copy store.json.bak: the store, the key's ONLY home (sealed at rest when a key is configured; the .bak
        // is never more exposed than the book, headless-store.ts sealBackup). Everything else in the agent dir must never hold it.
        if (f === 'store.json' || f === 'store.json.bak' || f.startsWith('.')) continue;
        assert.equal(readFileSync(join(dir, f), 'utf8').includes(rk), false, `${f} must not hold the key`);
      }
    }
    assert.ok(existsSync(join(b.dir, DEAD_LETTER_FILE)), 'control: the dead-letter file was written');
    assert.equal(readFileSync(b.path, 'utf8').includes(rk), false, 'B never stores the key (inbound rows carry none)');
    assert.equal(readFileSync(a.path, 'utf8').includes(rk), false, 'A dropped it on confirmation');
  } finally {
    Object.assign(console, orig);
    process.stdout.write = outW;
    process.stderr.write = errW;
    a.done();
    b.done();
  }
});

test('N5 forged / wrong-code / transplanted receipts never mark Delivered, and the key survives for the real one', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = agentBook();
  try {
    a.store.upsertContact(asContact(B));
    const n1 = await send(A, B, a.store, relay.fetchImpl, 'one');
    const n2 = await send(A, B, a.store, relay.fetchImpl, 'two');
    const rk1 = a.store.findOutboundNote(A.fp, n1.note_id)!.receipt_key!;
    const rk2 = a.store.findOutboundNote(A.fp, n2.note_id)!.receipt_key!;
    const forged = buildReceiptWireV1(receiptKeyToHex(newReceiptKey()), n1.note_id, 'delivered')!; // a relay-forged tag
    const wrongCode = buildReceiptWireV1(rk1, n1.note_id, 'read')!; // right key, a code this build never acts on
    const transplanted = { ...buildReceiptWireV1(rk2, n2.note_id, 'delivered')!, note_id: n1.note_id }; // note 2's tag on note 1
    for (const w of [forged, wrongCode, transplanted]) await deposit(relay, A, await sealReceiptV1To(w, A.pub, A.kem));
    const s = await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.delivered, 0);
    const row1 = a.open().findOutboundNote(A.fp, n1.note_id)!;
    assert.equal(row1.delivered, undefined);
    assert.equal(row1.receipt_key, rk1, 'the key survives');
    assert.equal(a.open().findOutboundNote(A.fp, n2.note_id)!.receipt_key, rk2);
    // the REAL receipt still lands afterwards
    await deposit(relay, A, await sealReceiptV1To(buildReceiptWireV1(rk1, n1.note_id, 'delivered')!, A.pub, A.kem));
    const s2 = await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s2.delivered, 1);
    assert.equal(a.open().findOutboundNote(A.fp, n1.note_id)!.delivered, true);
  } finally {
    a.done();
  }
});

test('N7 (C1) N receipts + M notes in one poll = ONE store write per ack chunk; no receipt POST while .writer.lock is held', async () => {
  const [A, B] = [await mint(), await mint()];
  let posts = 0;
  let underLock = 0;
  const a = agentBook();
  const base = mockRelay();
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/envelope')) {
      posts++;
      if (existsSync(join(a.dir, '.writer.lock'))) underLock++;
    }
    return base.fetchImpl(url, init);
  }) as unknown as typeof fetch;
  const relay = { ...base, fetchImpl };
  const b = tmpBook();
  try {
    a.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(A));
    // A sends 3 notes to B; B sends 4 notes to A; B polls (3 receipts out); then A polls ONE mailbox with 3 receipts + 4 notes
    const ids = [];
    for (let i = 0; i < 3; i++) ids.push((await send(A, B, a.store, fetchImpl, `a${i}`)).note_id);
    for (let i = 0; i < 4; i++) await send(B, A, new HeadlessStore(), fetchImpl, `b${i}`);
    await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl, receiptsPerPoll: 10 }); // 3 receipts in ONE poll (the cap is pinned by G-RO-9 below)
    assert.equal((await inbox(relay, A)).length, 7);
    const before = a.store.writes;
    posts = 0;
    const s = await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl, receiptsPerPoll: 10 }); // A answers 4 in one poll
    assert.equal(s.delivered, 3);
    assert.equal(s.notes, 4);
    assert.equal(a.store.writes - before, 1, '7 envelopes = one chunk = ONE write (receipt rewrites ride it)');
    assert.equal(posts, 4, 'A answers B\'s 4 notes');
    assert.equal(underLock, 0, 'no receipt POST started while the writer lock was held');
    for (const id of ids) assert.equal(a.open().findOutboundNote(A.fp, id)!.delivered, true);
  } finally {
    a.done();
    b.done();
  }
});

test('N8 (C2) a byte-identical redelivery re-emits once per poll; a different-content one (FWW refusal) emits nothing', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A));
    // the same signed note deposited twice (the sender retried): one poll → ONE receipt (dedupe per poll)
    const blob = await (async () => {
      const box = mockRelay();
      await send(A, B, new HeadlessStore(), box.fetchImpl, 'same', { noteId: 'n-same', sentAt: '2026-10-31T20:00:00.000Z' });
      return (await inbox(box, B))[0].blob;
    })();
    await deposit(relay, B, blob);
    await deposit(relay, B, blob);
    const s1 = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s1.notes, 2);
    assert.equal(s1.receipts_sent, 1, 'at most one receipt per (sender, note_id) per poll');
    // a later poll with the identical note again: re-emits ONCE (the first receipt may have been lost)
    await deposit(relay, B, blob);
    const s2 = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s2.receipts_sent, 1);
    // the same note_id with different content: refused (FWW), no receipt
    await send(A, B, new HeadlessStore(), relay.fetchImpl, 'rewritten', { noteId: 'n-same', sentAt: '2026-10-31T20:00:00.000Z' });
    const s3 = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s3.notes, 1, 'consumed as the stored note');
    assert.equal(s3.receipts_sent, 0);
    assert.equal(b.open().listNotes()[0].body, 'same');
    assert.equal((await inbox(relay, A)).length, 2);
  } finally {
    b.done();
  }
});

test('N9 (C3) the emit path re-checks admitContact itself: a candidate from a stranger or a blocked sender is refused when called directly', async () => {
  const [A, S, B] = [await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A));
    await send(A, B, new HeadlessStore(), relay.fetchImpl, 'from A');
    const deps = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const accept = deps.note!.accept;
    let wire: NoteWireV0 | undefined;
    deps.note!.accept = async (w) => ((wire = w), accept(w));
    await consumeInboundContactUpdates(deps);
    // the note is stored; now A is blocked before the emit: the same candidate is refused
    bs.updateContact(asContact(A).id, { blocked: true });
    assert.deepEqual(await sendHeadlessReceipts(bs, new Map([[`${A.fp}:${wire!.note_id}`, wire!]]), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), { sent: 0, skipped: 1, failed: 0, capped: 0 });
    // a stranger's wire, even if a note with its id were in the store: refused (S is not in the book)
    bs.putNote({ ...b.open().listNotes()[0], from_fingerprint: S.fp });
    const strangerWire = { ...wire!, from_fingerprint: S.fp, public_key: S.pub, pq_kem_public_key: S.kem };
    assert.deepEqual(await sendHeadlessReceipts(bs, new Map([[`${S.fp}:${wire!.note_id}`, strangerWire]]), { relayBase: RELAY, fetchImpl: relay.fetchImpl }), { sent: 0, skipped: 1, failed: 0, capped: 0 });
    assert.equal((await inbox(relay, A)).length + (await inbox(relay, S)).length, 0);
  } finally {
    b.done();
  }
});

test('N10 a FWW refusal (\'kept\') never becomes a receipt CANDIDATE: asserted on the candidate set itself, not only on "nothing sent"', async () => {
  // N8 sees "receipts_sent 0" for a rewrite, but that also holds if 'kept' became a candidate and the durable re-check dropped it
  // (the rewritten body != the stored one). This pins the earlier gate: a refused rewrite is never collected (skipped stays 0).
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A));
    await send(A, B, new HeadlessStore(), relay.fetchImpl, 'first', { noteId: 'n-fww', sentAt: '2026-10-31T20:00:00.000Z' });
    assert.equal((await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl })).receipts_sent, 1);
    await send(A, B, new HeadlessStore(), relay.fetchImpl, 'rewritten', { noteId: 'n-fww', sentAt: '2026-10-31T20:00:00.000Z' });
    const deps = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    const summary = await consumeInboundContactUpdates(deps);
    assert.equal(summary.notes, 1, 'the rewrite was consumed (acked) as the stored note');
    assert.deepEqual(await deps.sendReceipts(), { sent: 0, skipped: 0, failed: 0, capped: 0 }, 'the refused rewrite was never a candidate');
    assert.equal(b.open().listNotes().find((n) => n.note_id === 'n-fww')!.body, 'first');
  } finally {
    b.done();
  }
});


// ── Layer 3: the hop trail on the REAL send/poll paths (spec 65bac8aa; Flint #189024 + C4; Hypatia 6139992d) ──────────────────────
const trailText = (dir: string) => (existsSync(join(dir, HOP_TRAIL_FILE)) ? readFileSync(join(dir, HOP_TRAIL_FILE), 'utf8') : '');
const hopsFor = (dir: string, id: string) => readHopTrail(dir, id).map((r) => r.hop);

test('L3-E1 round trip: each side writes ONLY its own hops; no fingerprint, body or key in any row; only the known keys', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = tmpBook();
  const b = tmpBook();
  try {
    const as = a.open();
    as.upsertContact(asContact(B, { name: 'bee' }));
    const bs = b.open();
    bs.upsertContact(asContact(A, { name: 'ay' }));
    const sent = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'TRAIL-BODY-CANARY', store: as, relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e1', hopTrailDir: a.dir });
    assert.equal(sent.deposited, true);
    assert.deepEqual(hopsFor(a.dir, 'note_l3e1'), ['sealed', 'deposited', 'relay-accepted']);
    const envId = (await inbox(relay, B))[0].envelope_id;
    const sb = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir });
    assert.equal(sb.receipts_sent, 1);
    assert.deepEqual(hopsFor(b.dir, envId), ['polled']);
    assert.deepEqual(hopsFor(b.dir, 'note_l3e1'), ['opened', 'persisted', 'receipt-sent']);
    await pollHeadlessOnce(owner(A), a.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: a.dir });
    assert.equal(a.open().findOutboundNote(A.fp, 'note_l3e1')?.delivered, true);
    assert.deepEqual(hopsFor(a.dir, 'note_l3e1'), ['sealed', 'deposited', 'relay-accepted', 'receipt-verified']);
    // R1 (Flint #3122): production contacts carry no kind, so SENDER rows name no peer (omitted, never guessed); the RECEIVER's rows
    // take the kind from the sender's signed wire declaration (a headless sender declares 'agent'), so they name the local contact.
    assert.deepEqual(readHopTrail(a.dir, 'note_l3e1').map((r) => r.peer), [undefined, undefined, undefined, undefined]);
    assert.deepEqual(readHopTrail(b.dir, 'note_l3e1').map((r) => r.peer), ['ay', 'ay', 'ay']);
    // Hypatia NEG: a SENDER's trail never holds opened/persisted for its own note; a receiver's never holds the sender hops
    for (const h of ['opened', 'persisted', 'receipt-sent']) assert.ok(!hopsFor(a.dir, 'note_l3e1').includes(h as never), h);
    for (const h of ['sealed', 'deposited', 'relay-accepted', 'receipt-verified']) assert.ok(!hopsFor(b.dir, 'note_l3e1').includes(h as never), h);
    // Flint boundary 2: never content, a key, or any fingerprint / prefix; nothing but the known keys
    const keyHex = (as.listNotes().find((n) => n.note_id === 'note_l3e1') as { receipt_key?: string } | undefined)?.receipt_key;
    for (const t of [trailText(a.dir), trailText(b.dir)]) {
      assert.ok(t.length > 0);
      assert.doesNotMatch(t, /TRAIL-BODY-CANARY/);
      for (const fp of [A.fp, B.fp]) assert.ok(!t.toLowerCase().includes(fp.slice(0, 8).toLowerCase()), 'no fp prefix');
      if (keyHex) assert.ok(!t.includes(keyHex));
      for (const line of t.split('\n').filter(Boolean)) {
        for (const k of Object.keys(JSON.parse(line))) assert.ok(['ts', 'hop', 'note_id', 'envelope_id', 'agent', 'peer'].includes(k), k);
      }
    }
    assert.equal(statSync(join(a.dir, HOP_TRAIL_FILE)).mode & 0o777, 0o600);
  } finally {
    a.done();
    b.done();
  }
});

test('L3-E2 a stranger\'s note: decrypted, then dropped:not-in-book (recorded), never persisted, no receipt', async () => {
  const [S, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open(); // S is NOT in B's book
    await sendNoteFromHeadless({ owner: owner(S), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'hi', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e2' });
    const envId = (await inbox(relay, B))[0].envelope_id;
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir, deadLetterPath: join(b.dir, 'dead-letters.json') });
    assert.equal(s.receipts_sent, 0);
    assert.deepEqual(hopsFor(b.dir, envId), ['polled', 'dropped:not-in-book']);
    assert.ok(!hopsFor(b.dir, 'note_l3e2').includes('persisted'));
    assert.ok(!hopsFor(b.dir, 'note_l3e2').includes('receipt-sent'));
  } finally {
    b.done();
  }
});

test('L3-E3 no hopTrailDir (FE, every existing caller) = no trail file is ever created', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A, { name: 'ay' }));
    await send(A, B, new HeadlessStore(), relay.fetchImpl, 'x', { noteId: 'note_l3e3' });
    await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(existsSync(join(b.dir, HOP_TRAIL_FILE)), false);
  } finally {
    b.done();
  }
});

test('L3-E4 fail-open: a trail path that cannot be written never stops a send or a poll', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bad = join(b.dir, 'not-a-dir');
    writeFileSync(bad, 'a file where a dir should be');
    const bs = b.open();
    bs.upsertContact(asContact(A, { name: 'ay' }));
    const sent = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'still goes', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e4', hopTrailDir: bad });
    assert.equal(sent.deposited, true);
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: bad });
    assert.equal(s.notes, 1);
    assert.equal(s.receipts_sent, 1);
  } finally {
    b.done();
  }
});


test('L3-E5 a deposit the relay REFUSES: sealed + deposited (the request), but NO relay-accepted ("on the relay" would be false)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = tmpBook();
  try {
    const refusing = (async (url: string, init?: RequestInit) =>
      String(url).endsWith('/envelope') ? new Response('busy', { status: 503 }) : relay.fetchImpl(url, init)) as typeof fetch;
    const sent = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'x', store: a.open(), relayBase: RELAY, fetchImpl: refusing, noteId: 'note_l3e5', hopTrailDir: a.dir });
    assert.equal(sent.deposited, false);
    assert.deepEqual(hopsFor(a.dir, 'note_l3e5'), ['sealed', 'deposited']);
  } finally {
    a.done();
  }
});

test('L3-E6 a note from a PERSON: every receiver row says peer "person", never the contact\'s name (Flint boundary 2)', async () => {
  const [P, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(P, { name: 'peter' }));
    await sendNoteFromHeadless({ owner: owner(P), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'from a person', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e6', senderKind: 'human' }); // the REAL wire kind for a person
    await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir });
    const rows = readHopTrail(b.dir, 'note_l3e6');
    assert.deepEqual(rows.map((r) => r.hop), ['opened', 'persisted', 'receipt-sent']);
    assert.deepEqual(rows.map((r) => r.peer), ['person', 'person', 'person']);
    assert.doesNotMatch(trailText(b.dir), /peter/i);
  } finally {
    b.done();
  }
});

test('L3-E7 a FAILED chunk write: the receiver trail says decrypted, never persisted; a rolled-back receipt never says receipt-verified', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = tmpBook();
  const b = tmpBook();
  try {
    // (a) receiver: the note decrypts, but its chunk commit fails, so it is NOT durable
    const bs = b.open();
    bs.upsertContact(asContact(A, { name: 'ay' }));
    const as = a.open();
    as.upsertContact(asContact(B, { name: 'bee' }));
    await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'x', store: as, relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e7', hopTrailDir: a.dir });
    const dB = await buildHeadlessConsumeDeps(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir });
    const realCommitB = dB.chunk!.commit;
    dB.chunk!.commit = () => {
      throw new Error('disk full');
    };
    await consumeInboundContactUpdates(dB);
    await dB.sendReceipts();
    assert.deepEqual(hopsFor(b.dir, 'note_l3e7'), ['opened'], 'decrypted on this host, but never persisted or receipted');
    // the next poll commits for real → persisted + receipt-sent
    dB.chunk!.commit = realCommitB;
    await pollHeadlessOnce(owner(B), b.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir });
    assert.deepEqual(hopsFor(b.dir, 'note_l3e7').slice(-2), ['persisted', 'receipt-sent']);
    // (b) sender: the receipt verifies, but A's chunk commit fails → delivered is rolled back → NO receipt-verified row
    const dA = await buildHeadlessConsumeDeps(owner(A), a.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: a.dir });
    dA.chunk!.commit = () => {
      throw new Error('disk full');
    };
    await consumeInboundContactUpdates(dA);
    await dA.sendReceipts();
    assert.notEqual(a.open().findOutboundNote(A.fp, 'note_l3e7')?.delivered, true);
    assert.ok(!hopsFor(a.dir, 'note_l3e7').includes('receipt-verified'), 'a rolled-back Delivered never reaches the trail');
  } finally {
    a.done();
    b.done();
  }
});

test('L3-E8 R2 (Hypatia #3123): "dropped" is written only once the drop is TRUE (recorded AND acked); a failed save or ack writes none', async () => {
  const [S, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open(); // S is NOT in B's book → its note is a not-in-book loss
    await sendNoteFromHeadless({ owner: owner(S), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
      body: 'hi', store: new HeadlessStore(), relayBase: RELAY, fetchImpl: relay.fetchImpl, noteId: 'note_l3e8' });
    const envId = (await inbox(relay, B))[0].envelope_id;
    const opts = { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir, deadLetterPath: join(b.dir, 'dead-letters.json') };
    // (a) the drop is STAGED, then the store save fails: nothing is acked, the envelope stays on the relay → NO 'dropped' row
    const d1 = await buildHeadlessConsumeDeps(owner(B), bs, opts);
    d1.chunk!.commit = () => {
      throw new Error('disk full');
    };
    await consumeInboundContactUpdates(d1);
    assert.ok(relay.listIds().includes(envId), 'still on the relay');
    assert.ok(!hopsFor(b.dir, envId).some((h) => h.startsWith('dropped:')), 'a failed commit must not say dropped');
    // (b) a real save, but the ack is killed: the row is durable, the envelope is still on the relay → still NO 'dropped'
    relay.failAck(1);
    const d2 = await buildHeadlessConsumeDeps(owner(B), b.open(), opts);
    await consumeInboundContactUpdates(d2).catch(() => undefined);
    assert.ok(relay.listIds().includes(envId), 'the ack never landed');
    assert.ok(!hopsFor(b.dir, envId).some((h) => h.startsWith('dropped:')), 'an unacked drop must not say dropped');
    // (c) the next poll acks it → NOW 'dropped:not-in-book', exactly once
    await pollHeadlessOnce(owner(B), b.open(), opts);
    assert.ok(!relay.listIds().includes(envId), 'acked');
    assert.deepEqual(hopsFor(b.dir, envId).filter((h) => h.startsWith('dropped:')), ['dropped:not-in-book']);
  } finally {
    b.done();
  }
});

// G-RO-9 (b), Archie #3234: at most receiptsPerPoll receipts per poll (default 1 via SVRNTY_RECEIPTS_PER_POLL), earliest-DEPOSITED first; the
// rest are counted receipts_capped and dropped (not retried yet), so one poll can never spend the relay's shared per-IP deposit bucket.
test('G-RO-9 cap: 3 due receipts, the DEFAULT cap (1) → ONE sent, for the earliest-deposited note; 2 capped; none of the capped ones is sent later', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const a = agentBook();
  const b = tmpBook();
  const saved = process.env.SVRNTY_RECEIPTS_PER_POLL;
  delete process.env.SVRNTY_RECEIPTS_PER_POLL;
  try {
    a.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(A));
    const ids: string[] = [];
    for (const body of ['first', 'second', 'third']) {
      ids.push((await send(A, B, a.store, relay.fetchImpl, body)).note_id);
    }
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(s.notes, 3);
    assert.equal(s.receipts_sent, 1, 'the default cap is 1 per poll');
    assert.equal(s.receipts_capped, 2);
    assert.equal(s.receipts_failed + s.receipts_skipped, 0);
    const sa = await pollHeadlessOnce(owner(A), a.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(sa.delivered, 1);
    assert.deepEqual(ids.map((id) => a.open().findOutboundNote(A.fp, id)!.delivered === true), [true, false, false], 'the earliest-deposited note got the receipt');
    const again = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
    assert.equal(again.receipts_sent + again.receipts_capped, 0, 'capped receipts are dropped, not retried (named limit)');
  } finally {
    if (saved === undefined) delete process.env.SVRNTY_RECEIPTS_PER_POLL;
    else process.env.SVRNTY_RECEIPTS_PER_POLL = saved;
    a.done();
    b.done();
  }
});

test('G-RO-9 cap: receiptsPerPoll 0 sends NONE (all counted capped); 2 sends the two earliest-deposited', async () => {
  for (const [k, sent, capped] of [[0, 0, 3], [2, 2, 1]] as const) {
    const [A, B] = [await mint(), await mint()];
    const relay = mockRelay();
    const a = agentBook();
    const b = tmpBook();
    try {
      a.store.upsertContact(asContact(B));
      const bs = b.open();
      bs.upsertContact(asContact(A));
      for (const body of ['x', 'y', 'z']) await send(A, B, a.store, relay.fetchImpl, body);
      const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, receiptsPerPoll: k });
      assert.equal(s.receipts_sent, sent, `k=${k}`);
      assert.equal(s.receipts_capped, capped, `k=${k}`);
      assert.equal((await inbox(relay, A)).length, sent, `k=${k}: exactly that many receipts reached A`);
    } finally {
      a.done();
      b.done();
    }
  }
});

// G-RO-9 fairness (Flint #3242, Archie #3244): a random SENDER first (pickReceipts), then that sender's earliest-arrived note.
/** mulberry32: a small seeded PRNG, so the fairness tests are deterministic. */
const seeded = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

test('G-RO-9 fairness NEG (a): X back-dates sent_at to 1970 and it buys nothing: the RNG alone picks the sender (both outcomes shown)', async () => {
  const winners: string[] = [];
  for (const rng of [() => 0.99, () => 0]) { // 0.99: no swap (Y, arrived first, leads); 0: swap (X leads)
    const [X, Y, B] = [await mint(), await mint(), await mint()];
    const relay = mockRelay();
    const xs = agentBook();
    const ys = agentBook();
    const b = tmpBook();
    try {
      xs.store.upsertContact(asContact(B));
      ys.store.upsertContact(asContact(B));
      const bs = b.open();
      bs.upsertContact(asContact(X));
      bs.upsertContact(asContact(Y));
      const fromY = await send(Y, B, ys.store, relay.fetchImpl, 'deposited first');
      const fromX = await send(X, B, xs.store, relay.fetchImpl, 'back-dated, deposited last', { sentAt: '1970-01-01T00:00:00.000Z' });
      const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, receiptsPerPoll: 1, receiptRng: rng });
      assert.deepEqual([s.notes, s.receipts_sent, s.receipts_capped], [2, 1, 1]);
      await pollHeadlessOnce(owner(Y), ys.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      await pollHeadlessOnce(owner(X), xs.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
      const yGot = ys.open().findOutboundNote(Y.fp, fromY.note_id)!.delivered === true;
      const xGot = xs.open().findOutboundNote(X.fp, fromX.note_id)!.delivered === true;
      assert.notEqual(yGot, xGot, 'exactly one of them got the slot');
      winners.push(yGot ? 'Y' : 'X');
    } finally {
      xs.done();
      ys.done();
      b.done();
    }
  }
  assert.deepEqual(winners, ['Y', 'X'], 'the seed decides; the 1970 stamp is not an input');
});

test('G-RO-9 fairness NEG (b): X with 20 due receipts and Y with 1 → over 4,000 seeded draws Y gets the one slot ~half the time, not 1/21', () => {
  const rng = seeded(20261101);
  for (const senders of [[...Array(20).fill('X'), 'Y'], ['Y', ...Array(20).fill('X')]]) { // Y arriving last, then first
    let y = 0;
    for (let n = 0; n < 4000; n++) if (senders[pickReceipts(senders, 1, rng)[0]] === 'Y') y++;
    assert.ok(y > 0.45 * 4000 && y < 0.55 * 4000, `Y won ${y}/4000`);
  }
});

test('G-RO-9 fairness NEG (c): every sender gets one before anyone gets a second; within a sender, earliest-ARRIVED first', () => {
  const senders = ['X', 'X', 'Y', 'X', 'Z']; // arrival order
  for (let seed = 1; seed <= 50; seed++) {
    const rng = seeded(seed);
    const two = pickReceipts(senders, 2, rng).map((i) => senders[i]);
    assert.equal(new Set(two).size, 2, `k=2: two DIFFERENT senders (seed ${seed})`);
    const three = pickReceipts(senders, 3, seeded(seed)).map((i) => senders[i]).sort();
    assert.deepEqual(three, ['X', 'Y', 'Z'], `k=3 with 3 senders: one each (seed ${seed})`);
    const four = pickReceipts(senders, 4, seeded(seed));
    assert.deepEqual(four.filter((i) => senders[i] === 'X'), [0, 1], `k=4: X's second slot is its next arrival (seed ${seed})`);
    assert.deepEqual(pickReceipts(senders, 10, seeded(seed)).sort((a, b) => a - b), [0, 1, 2, 3, 4], 'k > due: every receipt, once');
  }
  assert.deepEqual(pickReceipts(senders, 0, seeded(1)), [], 'k=0: none');
  assert.deepEqual(pickReceipts([], 3, seeded(1)), [], 'nothing due: none');
  assert.deepEqual(pickReceipts(['X', 'Y'], 1, () => 1), [0], 'an rng returning 1 is clamped to j = i (no swap, no out-of-range index)');
});

test('G-RO-9 fairness (c) end-to-end: k=2, X has 2 due and Y has 1 → one receipt to each sender', async () => {
  const [X, Y, B] = [await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const xs = agentBook();
  const ys = agentBook();
  const b = tmpBook();
  try {
    xs.store.upsertContact(asContact(B));
    ys.store.upsertContact(asContact(B));
    const bs = b.open();
    bs.upsertContact(asContact(X));
    bs.upsertContact(asContact(Y));
    await send(X, B, xs.store, relay.fetchImpl, 'x1');
    await send(X, B, xs.store, relay.fetchImpl, 'x2');
    await send(Y, B, ys.store, relay.fetchImpl, 'y1');
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, receiptsPerPoll: 2 });
    assert.deepEqual([s.receipts_sent, s.receipts_capped], [2, 1]);
    assert.equal((await pollHeadlessOnce(owner(X), xs.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl })).delivered, 1, 'X: one');
    assert.equal((await pollHeadlessOnce(owner(Y), ys.store, { relayBase: RELAY, fetchImpl: relay.fetchImpl })).delivered, 1, 'Y: one');
  } finally {
    xs.done();
    ys.done();
    b.done();
  }
});

test('G-RO-9 env: SVRNTY_RECEIPTS_PER_POLL is digits only, 0-10; unset, empty or anything else → 1', () => {
  const at = (v: string | undefined) => receiptsPerPoll(v === undefined ? {} : { SVRNTY_RECEIPTS_PER_POLL: v });
  assert.equal(at(undefined), 1);
  for (const [v, n] of [['0', 0], ['1', 1], ['7', 7], ['10', 10], ['05', 5]] as const) assert.equal(at(v), n, v);
  for (const v of ['', '11', '99', '-1', '1.5', ' 2', '2 ', 'abc', '1e1', '0x2', '100']) assert.equal(at(v), 1, JSON.stringify(v));
});

// Apollo #3227 test gaps, riding G-RO-9 (Archie #3229).
test('R3 (Apollo): findOutboundNote matches ONLY our outbound row: an inbound row with the same id never matches, even one holding a key', () => {
  const store = new HeadlessStore();
  const me = 'f'.repeat(64);
  const other = 'e'.repeat(64);
  const row = (over: Record<string, unknown>) => ({
    note_id: 'note_shared', thread_id: 't1', direction: 'inbound', from_fingerprint: other, to_fingerprints: [me],
    sent_at: '2026-11-01T00:00:00.000Z', body: 'x', participant_kind: 'agent', retention: { expires_at: null },
    receipt_key: receiptKeyToHex(newReceiptKey()), ...over,
  }) as unknown as Parameters<HeadlessStore['putNote']>[0];
  store.putNote(row({})); // inbound, from them, WITH a key (a state the code never writes; the guard must not rely on that)
  assert.equal(store.findOutboundNote(me, 'note_shared'), null, 'inbound from them: no match');
  store.putNote(row({ note_id: 'note_mine_in', from_fingerprint: me })); // inbound, but stamped with OUR fingerprint
  assert.equal(store.findOutboundNote(me, 'note_mine_in'), null, 'direction inbound: no match, whoever it is from');
  store.putNote(row({ note_id: 'note_theirs_out', direction: 'outbound' })); // outbound, but not ours
  assert.equal(store.findOutboundNote(me, 'note_theirs_out'), null, 'outbound from another identity: no match');
  store.putNote(row({ note_id: 'note_ours', direction: 'outbound', from_fingerprint: me }));
  assert.equal(store.findOutboundNote(me, 'note_ours')?.note_id, 'note_ours', 'control: our outbound row matches');
});

test('R8 (Apollo): a note that was NEVER deposited keeps no receipt key (no peer KEM key: fail-closed; or the relay refused the deposit)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const refusing = (async (url: string, init?: RequestInit) =>
    String(url).includes('/envelope') ? new Response('{"error":"no"}', { status: 500 }) : relay.fetchImpl(url, init)) as unknown as typeof fetch;
  const store = new HeadlessStore();
  const noKem = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: '', body: 'no kem', store, relayBase: RELAY, fetchImpl: relay.fetchImpl });
  const refused = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'refused', store, relayBase: RELAY, fetchImpl: refusing });
  const ok = await sendNoteFromHeadless({ owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem, body: 'ok', store, relayBase: RELAY, fetchImpl: relay.fetchImpl });
  assert.deepEqual([noKem.deposited, refused.deposited, ok.deposited], [false, false, true]);
  assert.equal(store.findOutboundNote(A.fp, noKem.note_id)?.receipt_key, undefined, 'fail-closed copy: no key');
  assert.equal(store.findOutboundNote(A.fp, refused.note_id)?.receipt_key, undefined, 'refused deposit: no key');
  assert.match(store.findOutboundNote(A.fp, ok.note_id)?.receipt_key ?? '', /^[0-9a-f]{64}$/, 'control: a deposited note keeps its key');
});

// G-RO-9 R-a (Apollo #3268, Flint #3271, Archie #3272): the receipt-sent hop must name the note whose receipt was ACTUALLY sent. A hop on
// another note would be a false status line ("delivery receipt sent to the relay" for a receipt never sent).
test('G-RO-9 R-a: cap 1, 3 due from 3 senders, the RNG picks the 2nd → the receipt-sent hop names THAT note; the other two have none', async () => {
  const [X, Y, Z, B] = [await mint(), await mint(), await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    for (const p of [X, Y, Z]) bs.upsertContact(asContact(p));
    for (const [p, id] of [[X, 'n_x'], [Y, 'n_y'], [Z, 'n_z']] as const) await send(p, B, new HeadlessStore(), relay.fetchImpl, id, { noteId: id });
    // Fisher-Yates over [X, Y, Z]: i=2 draws 0.99 (j=2, no swap), i=1 draws 0 (j=0, swap) → [Y, X, Z]: Y (the 2nd arrival) gets the slot
    const seq = [0.99, 0];
    let k = 0;
    const s = await pollHeadlessOnce(owner(B), bs, { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir, receiptsPerPoll: 1, receiptRng: () => seq[k++ % seq.length] });
    assert.deepEqual([s.notes, s.receipts_sent, s.receipts_capped], [3, 1, 2]);
    assert.ok(hopsFor(b.dir, 'n_y').includes('receipt-sent'), 'the picked (2nd) note carries the hop');
    assert.ok(!hopsFor(b.dir, 'n_x').includes('receipt-sent'), 'the 1st note: no receipt was sent, so no hop');
    assert.ok(!hopsFor(b.dir, 'n_z').includes('receipt-sent'), 'the 3rd note: no hop');
    assert.equal((await inbox(relay, Y)).length, 1, 'and the receipt really went to Y');
  } finally {
    b.done();
  }
});

// G-RO-9 R-b: pickReceipts must TERMINATE. A slip in its loop condition is a synchronous infinite loop, which node:test's own timeout cannot
// interrupt (it blocks the event loop), so the cases run in a child process with a hard kill: a hang FAILS here instead of hanging a poll.
test('G-RO-9 R-b: pickReceipts terminates (cap == due, cap > due, cap 0, empty, many rounds), enforced by a hard child-process timeout', () => {
  const code = `const { pickReceipts } = require('./src/lib/headless/headless-client.ts');
    if (typeof pickReceipts !== 'function') throw new Error('pickReceipts not loaded');
    const rng = () => 0.5;
    const s = ['X', 'X', 'Y', 'Z', 'Z', 'Z'];
    const many = Array.from({ length: 1000 }, (_, i) => 'p' + (i % 200));
    const out = [pickReceipts(s, s.length, rng).length, pickReceipts(s, 50, rng).length, pickReceipts(s, 0, rng).length, pickReceipts([], 3, rng).length, pickReceipts(many, 1000, rng).length,
      pickReceipts(['X', 'X', 'X'], 3, rng).length, pickReceipts(['X', 'X', 'X', 'Y'], 4, rng).length];
    console.log(JSON.stringify(out));`;
  const r = spawnSync(process.execPath, ['--import', 'tsx', '-e', code], { cwd: join(__dirname, '..', '..', '..'), timeout: 20_000, encoding: 'utf8' });
  assert.equal(r.signal, null, `pickReceipts did not terminate (killed by ${r.signal})`);
  assert.equal(r.status, 0, r.stderr);
  // the last two pin the bound's QUANTITY (Archie #3277/#3278, Flint #3280): ONE sender with 3 due at k=3 sends all 3, and 3 + 1 at k=4 sends
  // all 4. The bound counts DUE RECEIPTS (senders has one entry per receipt), never unique senders, or k>1 would silently cut a run short.
  assert.deepEqual(JSON.parse(r.stdout.trim().split('\n').pop()!), [6, 6, 0, 0, 1000, 3, 4], 'each case picks exactly min(cap, due)');
});

test('L3-E9 G-RO-1 (Apollo #3155 F-A): 100 polls of a 1,100-envelope backlog keep a STALLED note\'s own rows (polled once per id)', async () => {
  const [B] = [await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    // the stalled note: sealed + deposited were written first, then the backlog is listed on every poll
    assert.equal(recordHop(b.dir, 'sealed', { note_id: 'note_stalled' }), true);
    assert.equal(recordHop(b.dir, 'deposited', { note_id: 'note_stalled' }), true);
    for (let p = 0; p < 100; p++) {
      const deps = await buildHeadlessConsumeDeps(owner(B), b.open(), { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir });
      for (let i = 1; i <= 1100; i++) deps.onHop!('polled', `env_backlog_${i}`);
    }
    assert.deepEqual(hopsFor(b.dir, 'note_stalled'), ['sealed', 'deposited'], 'the stalled note keeps its own history');
    const polled = trailText(b.dir).split('\n').filter((l) => l.includes('"hop":"polled"')).length;
    assert.equal(polled, 1100, 'one polled row per envelope id, not one per poll');
  } finally {
    b.done();
  }
});

test('L3-E10 G-RO-1 n-b (Apollo): a redelivered, already-stored note writes "persisted" ONCE', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const b = tmpBook();
  try {
    const bs = b.open();
    bs.upsertContact(asContact(A, { name: 'ay' }));
    const opts = { relayBase: RELAY, fetchImpl: relay.fetchImpl, hopTrailDir: b.dir };
    for (let k = 0; k < 2; k++) {
      await send(A, B, new HeadlessStore(), relay.fetchImpl, 'same body', { noteId: 'note_l3e10', sentAt: '2026-11-01T05:00:00.000Z' });
      await pollHeadlessOnce(owner(B), b.open(), opts);
    }
    assert.equal(hopsFor(b.dir, 'note_l3e10').filter((h) => h === 'persisted').length, 1);
  } finally {
    b.done();
  }
});

test('L3-E11 Hypatia #3158: `trail <id>` with no rows never reads as "never happened" (the caveat says rows may have been pruned)', async () => {
  const d = mkdtempSync(join(tmpdir(), 'trail-empty-'));
  try {
    writeFileSync(join(d, 'mint.json'), JSON.stringify(serializeMintArtifact(await mintHeadlessAgent({ throwaway: true }))), { mode: 0o600 }); // the CLI needs a mint
    const r = spawnSync(process.execPath, ['--import', 'tsx', join(__dirname, '../../../scripts/devin-comm.ts'), 'trail', 'note_pruned'], {
      env: { ...process.env, SVRNTY_AGENT_DIR: d }, encoding: 'utf8', timeout: 120_000,
    });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /^no hop rows for that id on this host \(the trail keeps up to 14 days or 5 MB, so older rows may have been pruned\)$/m);
    assert.doesNotMatch(r.stdout, /^no hop rows for that id on this host$/m, 'never a bare "no rows"');
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
