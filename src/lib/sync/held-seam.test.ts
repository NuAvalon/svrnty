// src/lib/sync/held-seam.test.ts: Freeze keep at the live NOTE SEAM (buildNoteSeam): what it asks the book, what it returns for a HELD note, and when a receipt may
// leave. Same harness shape as note-seam-receipt-order.test.ts; `accept` is injected so a creation and a stored record can be faked.
// Run: npx tsx --test src/lib/sync/held-seam.test.ts
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildNoteSeam, type NoteSeamDeps } from './live-book-poll';
import { lockSession } from '@/lib/identity/client-store';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0, NoteRecord } from '@/lib/messaging/types';

beforeEach(() => lockSession()); // the receipt outbox is module state: every case starts clean (the REAL clear-on-lock path)

const OWNER = { fingerprint: 'ab'.repeat(32), publicKeyArmored: 'x', privateKeyArmored: 'y', passphrase: 'z' };
const SENDER = 'cd'.repeat(32);
const WIRE: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: SENDER, sent_at: '2026-10-30T12:00:00.000Z', body: 'hi', participant_kind: 'human', receipt_key: 'ab'.repeat(32) } as NoteWireV0;
const REC = { note_id: 'n1', thread_id: 't1', from_fingerprint: SENDER } as NoteRecord;
const HELD_REC = { ...REC, held: true } as NoteRecord;
const settle = () => new Promise((r) => setTimeout(r, 20));
const createdBy = (rec: NoteRecord, pre?: () => Promise<void>) => (async (a: { onCreated?: () => void }) => { await pre?.(); a.onCreated?.(); return rec; }) as never;

type Spy = { args: unknown[][]; fn: NonNullable<NoteSeamDeps['receiptAllowed']> };
const allowSpy = (answer: boolean): Spy => {
  const args: unknown[][] = [];
  return { args, fn: (async (...a: unknown[]) => { args.push(a); return answer; }) as never };
};
function seam(accept: NoteSeamDeps['accept'], sendReceipt: (w: NoteWireV0) => Promise<void>, over: Partial<NoteSeamDeps> = {}) {
  const deps: NoteSeamDeps = { openOwner: () => OWNER.fingerprint, accept, ...over } as NoteSeamDeps;
  return buildNoteSeam(OWNER, deps, undefined, sendReceipt);
}

test('HS1 a HELD note comes back as a distinct stored-in-hold result: the usual handles plus held: true', async () => {
  const s = seam(createdBy(HELD_REC), async () => {}, { receiptAllowed: allowSpy(true).fn });
  const r = await s.accept(WIRE);
  assert.deepEqual(r, { note_id: 'n1', thread_id: 't1', from_fingerprint: SENDER, held: true });
});

test('HS2 an ORDINARY note has no held key at all', async () => {
  const s = seam(createdBy(REC), async () => {}, { receiptAllowed: allowSpy(true).fn });
  const r = await s.accept(WIRE);
  assert.deepEqual(r, { note_id: 'n1', thread_id: 't1', from_fingerprint: SENDER });
  assert.equal(r && 'held' in r, false);
});

test('HS3 D7 the HELD path asks the receipt gate WITH frozenStaged: true (and only that option)', async () => {
  const spy = allowSpy(true);
  const s = seam(createdBy(HELD_REC), async () => {}, { receiptAllowed: spy.fn });
  await s.accept(WIRE); await settle();
  assert.equal(spy.args.length, 1);
  assert.deepEqual(spy.args[0], [OWNER.fingerprint, SENDER, undefined, { frozenStaged: true }]);
});

test('HS4 D7 an ORDINARY note asks the gate with NO options: frozenStaged is never passed for it', async () => {
  const spy = allowSpy(true);
  const s = seam(createdBy(REC), async () => {}, { receiptAllowed: spy.fn });
  await s.accept(WIRE); await settle();
  assert.equal(spy.args.length, 1);
  assert.deepEqual(spy.args[0], [OWNER.fingerprint, SENDER], 'exactly two arguments: no third, no fourth');
});

test('HS5 a held note\'s receipt leaves exactly once, and only AFTER accept (the durable stage) has returned', async () => {
  const log: string[] = [];
  const s = seam(createdBy(HELD_REC, async () => { await new Promise((r) => setTimeout(r, 20)); log.push('staged'); }), async () => { log.push('receipt'); }, { receiptAllowed: allowSpy(true).fn });
  await s.accept(WIRE); await settle();
  assert.deepEqual(log, ['staged', 'receipt']);
});

test('HS6 a REDELIVERED held note (no creation reported) sends NO receipt', async () => {
  const log: string[] = [];
  const s = seam((async () => HELD_REC) as never, async () => { log.push('receipt'); }, { receiptAllowed: allowSpy(true).fn });
  const r = await s.accept(WIRE); await settle();
  assert.ok(r && 'held' in r, 'still acked as held');
  assert.deepEqual(log, []);
});

test('HS7 when the gate says NO (Delivery Off, unknown default, the sender removed since) a held note gets no receipt', async () => {
  const log: string[] = [];
  const s = seam(createdBy(HELD_REC), async () => { log.push('receipt'); }, { receiptAllowed: allowSpy(false).fn });
  await s.accept(WIRE); await settle();
  assert.deepEqual(log, []);
});

test('HS8 a receipt hook that THROWS never fails a held note: it is still returned held', async () => {
  const origErr = console.error; console.error = () => {};
  try {
    const s = seam(createdBy(HELD_REC), async () => { throw new Error('relay down'); }, { receiptAllowed: allowSpy(true).fn });
    const r = await s.accept(WIRE); await settle();
    assert.deepEqual(r, { note_id: 'n1', thread_id: 't1', from_fingerprint: SENDER, held: true });
  } finally { console.error = origErr; }
});

// ── D1: isAdmitted and isFrozen answer from ONE read of the book per accept ──
function bookProbe(contact: unknown) {
  const reads: string[] = [];
  let seen: { isAdmitted: (fp: string) => Promise<boolean>; isFrozen?: (fp: string) => Promise<boolean> } | undefined;
  const deps: Partial<NoteSeamDeps> = {
    getContact: (async (_o: string, fp: string) => { reads.push(fp); return contact; }) as never,
    receiptAllowed: allowSpy(true).fn,
  };
  const s = seam((async (a: never) => { seen = a; return null; }) as never, async () => {}, deps);
  return { reads, s, probe: async () => { await s.accept(WIRE); return seen!; } };
}

test('HS9 a BLOCKED contact in the book: not admitted, frozen; read ONCE for both questions', async () => {
  const b = bookProbe({ blocked: true });
  const a = await b.probe();
  assert.equal(await a.isAdmitted(SENDER), false);
  assert.equal(await a.isFrozen!(SENDER), true);
  assert.deepEqual(b.reads, [SENDER], 'one read of the book answered both');
});

test('HS10 an UNBLOCKED contact: admitted, not frozen', async () => {
  const b = bookProbe({});
  const a = await b.probe();
  assert.equal(await a.isAdmitted(SENDER), true);
  assert.equal(await a.isFrozen!(SENDER), false);
});

test('HS11 a STRANGER or a REMOVED contact (no row): not admitted AND not frozen (so it can never reach the hold path)', async () => {
  for (const none of [null, undefined]) {
    const b = bookProbe(none);
    const a = await b.probe();
    assert.equal(await a.isAdmitted(SENDER), false);
    assert.equal(await a.isFrozen!(SENDER), false);
  }
});

test('HS12 asking the same question twice, in either order, still reads the book once for that accept; the NEXT accept reads fresh (no stale snapshot across notes)', async () => {
  const b = bookProbe({ blocked: true });
  const a1 = await b.probe();
  await a1.isFrozen!(SENDER); await a1.isAdmitted(SENDER); await a1.isFrozen!(SENDER);
  assert.equal(b.reads.length, 1);
  await b.probe().then((a2) => a2.isAdmitted(SENDER));
  assert.equal(b.reads.length, 2, 'a new accept is a new snapshot');
});

test('HS14 the snapshot is keyed on the fingerprint: asking about a DIFFERENT sender in the same accept reads the book again and is answered from THAT row', async () => {
  const OTHER = 'ef'.repeat(32);
  const reads: string[] = [];
  let seen: { isAdmitted: (fp: string) => Promise<boolean>; isFrozen?: (fp: string) => Promise<boolean> } | undefined;
  const s = seam((async (a: never) => { seen = a; return null; }) as never, async () => {}, {
    getContact: (async (_o: string, fp: string) => { reads.push(fp); return fp === SENDER ? { blocked: true } : {}; }) as never,
    receiptAllowed: allowSpy(true).fn,
  });
  await s.accept(WIRE);
  assert.equal(await seen!.isFrozen!(SENDER), true);
  assert.equal(await seen!.isFrozen!(OTHER), false, 'not answered from the first sender\'s row');
  assert.equal(await seen!.isAdmitted(OTHER), true);
  assert.deepEqual(reads, [SENDER, OTHER]);
});

// ── the consume mapping is pinned in consume-mailbox-blocked.test.ts; these two pin the source that makes it ──
const SRC = (f: string) => readFileSync(join(process.cwd(), f), 'utf8');
test('HS13 consume-mailbox maps a held result to the benign terminal BEFORE the ordinary note return, by exactly true', () => {
  const c = SRC('src/lib/sync/consume-mailbox.ts');
  const held = c.indexOf("accepted.held === true");
  const note = c.indexOf("{ kind: 'note', event: { note_id: accepted.note_id");
  assert.ok(held > 0 && note > 0 && held < note, 'the held branch comes first');
  assert.match(c, /\{ kind: 'terminal', cls: \{ benign: 'note-frozen-stored' \} \}/);
});
