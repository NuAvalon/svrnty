// src/lib/sync/consume-mailbox-epoch.test.ts
// The epoch-note seam in the consume pipeline: it is routed after the other seams and before the contact-update path, an absent seam changes
// nothing, a package that is not an epoch note falls through unharmed, and each result of the receive logic has exactly one outcome.
// Run: npx tsx --test src/lib/sync/consume-mailbox-epoch.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps, type EpochNoteSeam, type NoteResponseSeam } from './consume-mailbox';
import type { EpochReceiveResult } from '@/lib/trust/psi-epoch-receive';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { lockSession } from '@/lib/identity/client-store';
import type { DeadLetterRow } from './dead-letter';

let owner: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'ed25519Legacy', userIDs: [{ name: 'alice', email: 'a@t.test' }], passphrase, format: 'armored' });
  owner = { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

function relay(initial: Array<{ envelope_id: string; blob: string }>, acks: string[][]) {
  let queue = [...initial];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(queue), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/ack')) {
      const ids: string[] = JSON.parse(String(init?.body ?? '{}')).envelope_ids;
      acks.push(ids);
      queue = queue.filter((e) => !ids.includes(e.envelope_id));
      return new Response(JSON.stringify({ deleted: ids.length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, left: () => queue.map((e) => e.envelope_id) };
}

function sink() {
  const rows: DeadLetterRow[] = [];
  return { rows, deadLetter: { record: async (r: DeadLetterRow) => { rows.push(r); return r; }, clear: async () => {} } as unknown as NonNullable<ConsumeDeps['deadLetter']> };
}

const PLAIN = Uint8Array.from([0x45, 0x01, 9, 9, 9]);
function seam(result: EpochReceiveResult | (() => Promise<EpochReceiveResult>), spy?: { opened: string[]; received: number }): EpochNoteSeam {
  return {
    open: async (blob) => { spy?.opened.push(blob); return blob === 'EPOCH' ? PLAIN : null; },
    receive: async () => { if (spy) spy.received++; return typeof result === 'function' ? result() : result; },
  };
}

function deps(over: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay', now: () => '2026-11-07T00:00:00.000Z', ...over,
  };
}

async function run(result: EpochReceiveResult) {
  const s = sink();
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  const summary = await consumeInboundContactUpdates(deps({ epoch: seam(result), deadLetter: s.deadLetter, fetchImpl: r.fetchImpl }));
  return { summary, rows: s.rows, acks, left: r.left() };
}

test('the benign results are acked with NO record: F1 off, an adopted note, an epoch the book did not take (three ways), and a blocked sender', async () => {
  for (const kind of ['benign-ack', 'adopted', 'already-held', 'conflict', 'out-of-range', 'blocked-drop'] as const) {
    const o = await run({ kind });
    assert.deepEqual(o.acks, [['e1']], kind);
    assert.deepEqual(o.left, [], kind);
    assert.equal(o.rows.length, 0, `${kind}: no record at all`);
    assert.equal(o.summary.deadLettered, 0, kind);
  }
});

test('an unverified result (malformed, unknown sender, no way to verify) is the existing unverified-frame record, acked, WITH NO fingerprint', async () => {
  const o = await run({ kind: 'unverified' });
  assert.deepEqual(o.acks, [['e1']]);
  assert.equal(o.rows.length, 1);
  assert.equal(o.rows[0].reason, 'unverified-frame');
  assert.equal(o.rows[0].fp, undefined, 'the claimed sender is not authenticated, so it is never kept');
});

test('a bad MAC is a record WITHOUT the fingerprint, acked', async () => {
  const o = await run({ kind: 'bad-mac' });
  assert.deepEqual(o.acks, [['e1']]);
  assert.equal(o.rows.length, 1);
  assert.equal(o.rows[0].reason, 'verify-failed');
  assert.equal(o.rows[0].fp, undefined);
});

test('retry: the envelope is NOT acked and stays on the relay, with no record', async () => {
  const o = await run({ kind: 'retry' });
  assert.deepEqual(o.acks, []);
  assert.deepEqual(o.left, ['e1']);
  assert.equal(o.rows.length, 0);
});

test('a receive that throws is left for retry (no ack, no record), and does not escape the poll', async () => {
  const s = sink();
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  const quiet = console.error;
  console.error = () => {};
  try {
    await consumeInboundContactUpdates(deps({ epoch: seam(async () => { throw new Error('boom'); }), deadLetter: s.deadLetter, fetchImpl: r.fetchImpl }));
  } finally {
    console.error = quiet;
  }
  assert.deepEqual(acks, []);
  assert.deepEqual(r.left(), ['e1']);
  assert.equal(s.rows.length, 0);
});

test('not-epoch falls through to the contact-update path unharmed (its decryptor runs and takes its usual outcome)', async () => {
  let decrypted = 0;
  const s = sink();
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  await consumeInboundContactUpdates(deps({ epoch: seam({ kind: 'not-epoch' }), decrypt: async () => { decrypted++; return null; }, deadLetter: s.deadLetter, fetchImpl: r.fetchImpl }));
  assert.equal(decrypted, 1);
  assert.equal(s.rows.length, 1, 'the existing record for an undecryptable blob');
  assert.notEqual(s.rows[0].reason, 'unverified-frame');
});

test('a package the seam cannot open (open answers null) falls through to the contact-update path and receive is never asked', async () => {
  let decrypted = 0;
  let asked = 0;
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'OTHER' }], acks);
  await consumeInboundContactUpdates(deps({
    epoch: { open: async () => null, receive: async () => { asked++; return { kind: 'adopted' }; } },
    decrypt: async () => { decrypted++; return null; }, fetchImpl: r.fetchImpl,
  }));
  assert.equal(decrypted, 1);
  assert.equal(asked, 0);
});

test('an open that THROWS (the seam cannot tell: a locked or ended cycle) is left for retry: no ack, the contact-update path is NOT tried, receive is never asked', async () => {
  let decrypted = 0;
  let asked = 0;
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  const quiet = console.error;
  console.error = () => {};
  try {
    await consumeInboundContactUpdates(deps({
      epoch: { open: async () => { throw new Error('cycle ended'); }, receive: async () => { asked++; return { kind: 'adopted' }; } },
      decrypt: async () => { decrypted++; return null; }, fetchImpl: r.fetchImpl,
    }));
  } finally {
    console.error = quiet;
  }
  assert.equal(decrypted, 0, 'an epoch package must not fall through to the contact-update path');
  assert.equal(asked, 0);
  assert.deepEqual(acks, []);
  assert.deepEqual(r.left(), ['e1']);
});

test('with no epoch seam nothing changes: the package takes the contact-update path exactly as before', async () => {
  let decrypted = 0;
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  await consumeInboundContactUpdates(deps({ decrypt: async () => { decrypted++; return null; }, fetchImpl: r.fetchImpl }));
  assert.equal(decrypted, 1);
});

test('ORDER: a note is taken by the note seam first (the epoch seam never sees it); a blob the note seam does not claim reaches the epoch seam', async () => {
  const spy = { opened: [] as string[], received: 0 };
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? ({ type: 'x', note_id: 'n', thread_id: 't', from_fingerprint: 'F', sent_at: 's', body: 'b', participant_kind: 'human' } as never) : null),
    accept: async (w) => ({ note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }),
  };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'n1', blob: 'NOTE' }, { envelope_id: 'e1', blob: 'EPOCH' }], acks);
  const summary = await consumeInboundContactUpdates(deps({ note, epoch: seam({ kind: 'adopted' }, spy), fetchImpl: r.fetchImpl }));
  assert.equal(summary.notes, 1, 'the note was stored by the note seam');
  assert.deepEqual(spy.opened, ['EPOCH'], 'the epoch seam was asked about the epoch blob only');
  assert.equal(spy.received, 1);
  assert.deepEqual(acks.flat().sort(), ['e1', 'n1']);
});

test('N10 shape: a lock that lands AFTER the package opened and BEFORE the decision is asked leaves the envelope alone: receive is never called, nothing is acked', async () => {
  const cycle = makeUnlockCycle(owner.privateKeyArmored, owner.passphrase);
  const spy = { opened: [] as string[], received: 0 };
  const locking: EpochNoteSeam = {
    open: async (blob) => { const p = await seam({ kind: 'adopted' }, spy).open(blob); lockSession(); return p; },
    receive: async (plain) => seam({ kind: 'adopted' }, spy).receive(plain),
  };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  await consumeInboundContactUpdates(deps({ owner: { ...owner, cycle }, epoch: locking, fetchImpl: r.fetchImpl }));
  assert.equal(spy.received, 0);
  assert.deepEqual(acks, []);
  assert.deepEqual(r.left(), ['e1']);
});

test('N10 control: with no lock the same flow asks the decision and acks', async () => {
  const cycle = makeUnlockCycle(owner.privateKeyArmored, owner.passphrase);
  const spy = { opened: [] as string[], received: 0 };
  const acks: string[][] = [];
  const r = relay([{ envelope_id: 'e1', blob: 'EPOCH' }], acks);
  await consumeInboundContactUpdates(deps({ owner: { ...owner, cycle }, epoch: seam({ kind: 'adopted' }, spy), fetchImpl: r.fetchImpl }));
  assert.equal(spy.received, 1);
  assert.deepEqual(acks, [['e1']]);
});
