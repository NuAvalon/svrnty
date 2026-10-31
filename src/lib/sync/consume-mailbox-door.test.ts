// src/lib/sync/consume-mailbox-door.test.ts
// #720 R1/R2/R9 + contract v3 "ONE ACK DOOR": an envelope that did not become a stored message is acked ONLY after a metadata-only
// record of it was committed. Failure to commit keeps it on the relay. Benign terminals (named list) are acked with no record.
// NEG-first: on dev there is no `deadLetter` dep, so none of these records exist.
// Run: npx tsx --test src/lib/sync/consume-mailbox-door.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { generateKey, readKey } from 'openpgp';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { consumeInboundContactUpdates, type ConsumeDeps, type DeadLetterSink, type DroppedNote, type NoteResponseSeam } from './consume-mailbox';
import { isMessageReason, parseDeadLetterRow, recordKeyFor, type DeadLetterRow } from './dead-letter';
import { createHoldBackoff } from './hold-backoff';

let OWNER: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-door';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'door', email: 'door@x.test' }],
    passphrase,
    format: 'armored',
  });
  OWNER = { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

const HYBRID = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });
const NOW = '2026-10-30T12:00:00.000Z';
const DAY = 24 * 60 * 60 * 1000;
type Ev = { t: 'record'; id: string; row: DeadLetterRow } | { t: 'clear'; id: string } | { t: 'ack'; ids: string[] };

/** Relay + sink sharing ONE ordered event log, so "record before ack" is asserted on the real sequence. */
function world(envs: Array<{ envelope_id: string; blob: string; expires_at?: unknown }>, sinkOpts: { failRecord?: (id: string) => boolean; failClear?: boolean; known?: Map<string, string> } = {}) {
  const events: Ev[] = [];
  const known = sinkOpts.known ?? new Map<string, string>();
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(envs), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/ack')) {
      const ids = JSON.parse(String(init?.body ?? '{}')).envelope_ids as string[];
      events.push({ t: 'ack', ids });
      return new Response(JSON.stringify({ deleted: ids.length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  const sink: DeadLetterSink = {
    record: async (row) => {
      if (sinkOpts.failRecord?.(row.envelope_id)) throw new Error('store locked');
      const prev = known.get(row.envelope_id);
      const first_seen = prev && Date.parse(prev) < Date.parse(row.first_seen) ? prev : row.first_seen;
      known.set(row.envelope_id, first_seen);
      const saved = { ...row, first_seen };
      events.push({ t: 'record', id: row.envelope_id, row: saved });
      return saved;
    },
    clear: async (id) => {
      if (sinkOpts.failClear) throw new Error('clear failed');
      events.push({ t: 'clear', id });
    },
  };
  return { events, fetchImpl, sink, known };
}
const acked = (events: Ev[]) => events.flatMap((e) => (e.t === 'ack' ? e.ids : []));
const recorded = (events: Ev[]) => events.flatMap((e) => (e.t === 'record' ? [e.row] : []));

function deps(over: Partial<ConsumeDeps>): ConsumeDeps {
  return { owner: OWNER, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} }, relayBase: 'http://relay.test/api/relay', now: () => NOW, ...over };
}

const noteSeam = (byBlob: Record<string, ReturnType<NoteResponseSeam['accept']> extends Promise<infer R> ? R : never>): NoteResponseSeam => ({
  verify: async (blob) => (blob in byBlob ? ({ type: NOTE_WIRE_TYPE, note_id: `n-${blob}`, thread_id: 't1', from_fingerprint: 'CLAIMED', sent_at: NOW, body: 'x', participant_kind: 'human' } as never) : null),
  accept: async (w) => byBlob[w.note_id.slice(2)] as never,
});

test('C1 done_when 2: an unknown-format blob gets its record committed BEFORE the ack; the row is metadata only', async () => {
  const SENTINEL = 'ATTACKER-TEXT-7f3a';
  const w = world([{ envelope_id: 'e1', blob: SENTINEL }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(w.events.map((e) => e.t), ['record', 'ack'], 'record first, then ack');
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'unknown-format');
  assert.equal(row.blob_kind, 'other');
  assert.equal(JSON.stringify(row).includes(SENTINEL), false, 'no blob text in the record');
  assert.equal(parseDeadLetterRow(row) !== null, true);
  assert.equal(s.deadLettered, 1); assert.equal(s.acked, 1); assert.equal(s.unrecorded, 0);
});

test('C2 a record that cannot be committed keeps the envelope ON THE RELAY (never acked); other envelopes are unaffected', async () => {
  const w = world([{ envelope_id: 'bad', blob: 'junk-1' }, { envelope_id: 'ok', blob: 'junk-2' }], { failRecord: (id) => id === 'bad' });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['ok']);
  assert.equal(s.unrecorded, 1); assert.equal(s.deadLettered, 1);
});

const derivedKey = (id: string) => `x:${createHash('sha256').update(Buffer.from(id, 'utf8')).digest('hex').slice(0, 32)}`; // independent of the code under test
const UNSAFE_IDS = ['../x', 'a/b', '', 'x'.repeat(101), 'é', 'a b', '<script>alert(1)</script>', 'e\u0000z'];

test('C3 E1 (Flint #2029): an UNSAFE envelope id is recorded under a DERIVED key, then the ORIGINAL id is acked: never lost, never kept forever', async () => {
  for (const id of UNSAFE_IDS) {
    const w = world([{ envelope_id: id, blob: 'junk' }]);
    const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
    const rows = recorded(w.events);
    assert.equal(rows.length, 1, JSON.stringify(id));
    assert.equal(rows[0].envelope_id, derivedKey(id), JSON.stringify(id));
    assert.notEqual(parseDeadLetterRow(rows[0]), null, 'the stored row passes the strict parser');
    if (id) assert.equal(JSON.stringify(rows[0]).includes(id), false, 'the hostile id text is never stored');
    assert.deepEqual(acked(w.events), [id], 'the ORIGINAL id is what the relay is told to delete');
    assert.deepEqual(w.events.map((e) => e.t), ['record', 'ack'], 'record first');
    assert.equal(s.unrecorded, 0); assert.equal(s.deadLettered, 1); assert.equal(s.acked, 1);
  }
});

test('C3b E1 mailbox-fill NEG: 30 junk envelopes with unsafe ids leave the mailbox EMPTY after one poll (not parked until the TTL)', async () => {
  const envs = Array.from({ length: 30 }, (_, i) => ({ envelope_id: `a/${i}`, blob: `junk-${i}` }));
  const w = world(envs);
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  const left = envs.map((e) => e.envelope_id).filter((id) => !acked(w.events).includes(id));
  assert.deepEqual(left, []);
  assert.equal(new Set(recorded(w.events).map((r) => r.envelope_id)).size, 30, 'thirty distinct derived keys');
});

test('C3c E1 derived keys: a safe id keys as itself, the same hostile id always maps to the same key, a failed record keeps the unsafe id on the relay', async () => {
  const w = world([{ envelope_id: 'safe-1', blob: 'j1' }, { envelope_id: 'a/b', blob: 'j2' }]);
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(recorded(w.events).map((r) => r.envelope_id).sort(), ['safe-1', derivedKey('a/b')].sort());
  const w2 = world([{ envelope_id: 'a/b', blob: 'j2' }], { failRecord: () => true });
  const s2 = await consumeInboundContactUpdates(deps({ deadLetter: w2.sink, fetchImpl: w2.fetchImpl }));
  assert.deepEqual(acked(w2.events), [], 'record-before-ack still holds for a derived key');
  assert.equal(s2.unrecorded, 1);
});

test('C3d E1 held path: an unsafe-id HELD envelope is recorded under its derived key, bounded like any other, and released by its ORIGINAL id', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 60 }, (_, i) => ({ envelope_id: `h/${String(i).padStart(2, '0')}`, blob: HYBRID, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  envs.forEach((e, i) => known.set(derivedKey(e.envelope_id), new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString())); // h/00 is the OLDEST
  const w = world(envs, { known });
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events).sort(), Array.from({ length: 10 }, (_, i) => `h/${String(i).padStart(2, '0')}`));
  assert.equal(s.released, 10); assert.equal(s.held, 50);
  for (const id of acked(w.events)) {
    const recIdx = w.events.findIndex((e) => e.t === 'record' && e.id === derivedKey(id));
    const ackIdx = w.events.findIndex((e) => e.t === 'ack' && e.ids.includes(id));
    assert.ok(recIdx >= 0 && recIdx < ackIdx, `${id}: record before ack`);
  }
});

test('C4 BENIGN terminals (joiner already known, receipt with no match) are acked with NO record', async () => {
  const w = world([{ envelope_id: 'j1', blob: 'JOINER' }, { envelope_id: 'r1', blob: 'RECEIPT' }]);
  const s = await consumeInboundContactUpdates(deps({
    deadLetter: w.sink,
    joiner: { verify: async (b) => (b === 'JOINER' ? ({ fingerprint: 'F' } as never) : null), accept: async () => null },
    receipt: { verify: async (b) => (b === 'RECEIPT' ? ({ type: 'svrnty-receipt-v0' } as never) : null), accept: async () => null },
    fetchImpl: w.fetchImpl,
  }));
  assert.deepEqual(recorded(w.events), [], 'no records for consumed, non-lost frames');
  assert.deepEqual(acked(w.events).sort(), ['j1', 'r1']);
  assert.equal(s.deadLettered, 0);
});

test('C5 note drops carry their honest reason; a fingerprint only for the AUTHENTICATED ones; legacy null = verify-failed', async () => {
  const FP = 'cd'.repeat(32);
  const w = world([
    { envelope_id: 'u', blob: 'U' }, { envelope_id: 'b', blob: 'B' }, { envelope_id: 'r', blob: 'R' }, { envelope_id: 'l', blob: 'L' },
  ]);
  await consumeInboundContactUpdates(deps({
    deadLetter: w.sink,
    note: noteSeam({
      U: { dropped: 'unverified', fp: FP } as DroppedNote, // even if a seam hands one over, an unauthenticated drop must not store it
      B: { dropped: 'not-in-book', fp: FP } as DroppedNote,
      R: { dropped: 'ratchet-unopenable', fp: FP } as DroppedNote,
      L: null as never,
    }),
    fetchImpl: w.fetchImpl,
  }));
  const by = Object.fromEntries(recorded(w.events).map((r) => [r.envelope_id, r]));
  assert.equal(by.u.reason, 'verify-failed'); assert.equal('fp' in by.u, false, 'unverified: no fingerprint (F3)');
  assert.equal(by.b.reason, 'not-in-book'); assert.equal(by.b.fp, FP);
  assert.equal(by.r.reason, 'ratchet-unopenable'); assert.equal(by.r.fp, FP);
  assert.equal(by.l.reason, 'verify-failed'); assert.equal('fp' in by.l, false);
  assert.deepEqual(acked(w.events).sort(), ['b', 'l', 'r', 'u']);
});

test('C5b ruling (b): a note seam whose accept() THROWS (store write failed) is RETRYABLE: no record, not acked, still on the relay; a sibling still goes through', async () => {
  const w = world([{ envelope_id: 'boom', blob: 'BOOM' }, { envelope_id: 'junk', blob: 'plain-junk' }]);
  const seam: NoteResponseSeam = {
    verify: async (blob) => (blob === 'BOOM' ? ({ type: NOTE_WIRE_TYPE } as never) : null),
    accept: async () => {
      throw new Error('IndexedDB write failed');
    },
  };
  const origErr = console.error;
  console.error = () => {};
  let s;
  try {
    s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seam, fetchImpl: w.fetchImpl }));
  } finally {
    console.error = origErr;
  }
  assert.deepEqual(recorded(w.events).map((r) => r.envelope_id), ['junk'], 'the thrown one is NOT recorded as a verify-failed verdict');
  assert.deepEqual(acked(w.events), ['junk'], 'and NOT acked: it stays on the relay');
  assert.equal(s.dropped >= 1, true);
});

test('C6 ruling (a): a stranger contact-update (sender NOT authenticated) is recorded as unverified-frame (a NON-message class) with NO fingerprint, even though the blob names one', async () => {
  const ATTACKER_FP = 'ee'.repeat(32);
  const w = world([{ envelope_id: 's1', blob: HYBRID }]);
  await consumeInboundContactUpdates(deps({
    deadLetter: w.sink,
    decrypt: async () => ({ envelope: { fingerprint: ATTACKER_FP } }) as never,
    store: { lookup: async () => null, persist: async () => {} },
    fetchImpl: w.fetchImpl,
  }));
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'unverified-frame');
  assert.equal(isMessageReason(row.reason), false, 'it can never feed an "N messages" count');
  assert.equal(JSON.stringify(row).includes(ATTACKER_FP), false, 'attacker-controlled fingerprint never stored');
  assert.deepEqual(acked(w.events), ['s1']);
});

test('C6b ruling (a): a contact-update from a KNOWN fingerprint whose verification fails is the same non-message class, not a message verdict', async () => {
  const w = world([{ envelope_id: 's2', blob: HYBRID }]);
  await consumeInboundContactUpdates(deps({
    deadLetter: w.sink,
    decrypt: async () => ({ envelope: { fingerprint: 'ab'.repeat(32) } }) as never,
    store: { lookup: async () => ({ known: {}, current: { id: 'c1' } }) as never, persist: async () => {} },
    fetchImpl: w.fetchImpl,
  }));
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'unverified-frame');
  assert.equal(row.fp, undefined);
  assert.deepEqual(acked(w.events), ['s2']);
});

test('C7 an envelope that OPENS clears its earlier record before the ack; if the clear fails it is NOT acked (retried, applied idempotently)', async () => {
  const note = noteSeam({ N: { note_id: 'n-N', thread_id: 't1', from_fingerprint: 'BOB' } as never });
  const ok = world([{ envelope_id: 'e1', blob: 'N' }]);
  await consumeInboundContactUpdates(deps({ deadLetter: ok.sink, note, fetchImpl: ok.fetchImpl }));
  assert.deepEqual(ok.events.map((e) => e.t), ['clear', 'ack']);
  const bad = world([{ envelope_id: 'e1', blob: 'N' }], { failClear: true });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: bad.sink, note, fetchImpl: bad.fetchImpl }));
  assert.deepEqual(acked(bad.events), []);
  assert.equal(s.unrecorded, 1);
});

test('C7b E1: an envelope with an UNSAFE id that opens as a note clears its record under the DERIVED key (a raw id would throw in the real store and park it), then acks the ORIGINAL id', async () => {
  const w = world([{ envelope_id: 'a/b', blob: 'N1' }]);
  const note: NoteResponseSeam = {
    verify: async () => ({ type: NOTE_WIRE_TYPE, note_id: 'n-1', thread_id: 't', from_fingerprint: 'ab'.repeat(32), sent_at: NOW, body: 'x', participant_kind: 'human' }) as never,
    accept: async (wire) => ({ note_id: wire.note_id, thread_id: wire.thread_id, from_fingerprint: wire.from_fingerprint }) as never,
  };
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note, fetchImpl: w.fetchImpl }));
  assert.deepEqual(w.events.filter((e) => e.t === 'clear').map((e) => (e as { id: string }).id), [derivedKey('a/b')]);
  assert.deepEqual(acked(w.events), ['a/b']);
});

test('C8 without a sink (headless) behaviour is unchanged: terminal envelopes are acked, nothing throws', async () => {
  const w = world([{ envelope_id: 'e1', blob: 'junk' }]);
  const s = await consumeInboundContactUpdates(deps({ fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['e1']);
  assert.equal(s.deadLettered, 0);
});

test('C9 done_when 8: 60 held envelopes -> 50 stay on the relay, the 10 OLDEST get their record then are acked; the count reported is 50', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 60 }, (_, i) => ({ envelope_id: `h${String(i).padStart(2, '0')}`, blob: HYBRID, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString())); // h00 is the OLDEST
  const w = world(envs, { known });
  const reports: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, emitHeld: (n) => reports.push(n), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events).sort(), Array.from({ length: 10 }, (_, i) => `h${String(i).padStart(2, '0')}`));
  assert.equal(s.released, 10); assert.equal(s.held, 50); assert.deepEqual(reports, [50]);
  for (const id of acked(w.events)) {
    const recIdx = w.events.findIndex((e) => e.t === 'record' && e.id === id);
    const ackIdx = w.events.findIndex((e) => e.t === 'ack' && e.ids.includes(id));
    assert.ok(recIdx >= 0 && recIdx < ackIdx, `${id}: record before ack`);
  }
});

test('C10 a held envelope older than 7 days (from its FIRST sighting) is released; one at exactly 7 days is kept', async () => {
  const known = new Map([['old', new Date(Date.parse(NOW) - 7 * DAY - 1).toISOString()], ['edge', new Date(Date.parse(NOW) - 7 * DAY).toISOString()]]);
  const w = world([{ envelope_id: 'old', blob: HYBRID }, { envelope_id: 'edge', blob: HYBRID }], { known });
  await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['old']);
});

test('C11 held envelopes are recorded every poll with the EARLIEST first_seen kept, and a first sighting is NOT released', async () => {
  const w = world([{ envelope_id: 'h1', blob: HYBRID }]);
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.equal(recorded(w.events)[0].reason, 'missing-key');
  assert.equal(recorded(w.events)[0].first_seen, NOW);
  assert.deepEqual(acked(w.events), []);
  assert.equal(s.held, 1);
});

test('C12 an unlock cycle that ends mid-tick: NOTHING is acked, and nothing is decided or recorded AFTER the lock (an envelope decided under the live cycle may keep its record, but stays on the relay)', async () => {
  const cycle = makeUnlockCycle(OWNER.privateKeyArmored, OWNER.passphrase);
  const w = world([{ envelope_id: 'e1', blob: 'junk' }, { envelope_id: 'h1', blob: HYBRID }, { envelope_id: 'e2', blob: 'junk-2' }]);
  const reports: number[] = [];
  const s = await consumeInboundContactUpdates(deps({
    owner: { ...OWNER, cycle }, deadLetter: w.sink, fetchImpl: w.fetchImpl, emitHeld: (n) => reports.push(n),
    hybridSecretMissing: async () => { cycle.drop(); return true; }, // the lock lands while h1 is being examined
  }));
  assert.deepEqual(acked(w.events), [], 'no ack once the cycle ended (it cannot be signed, and nothing was decided under another identity)');
  assert.deepEqual(recorded(w.events).map((r) => r.envelope_id).filter((id) => id !== 'e1'), [], 'h1 and e2 (examined at/after the lock) get no record');
  assert.equal(s.acked, 0);
  assert.deepEqual(reports, [], 'and the held notice is neither raised nor cleared: the state of the mailbox is unknown');
});

/** done_when 5 as restated by Archie (#2037, contract v5): every id the relay is told to delete was FIRST persisted as a note, consumed as a named benign terminal, or had a dead-letter record committed (under its record key). */
function assertAckInvariant(events: Ev[], persisted: ReadonlySet<string>, benign: ReadonlySet<string>) {
  const recordedKeys = new Set<string>();
  for (const e of events) {
    if (e.t === 'record') recordedKeys.add(e.id);
    if (e.t === 'ack') {
      for (const id of e.ids) {
        const ok = persisted.has(id) || benign.has(id) || recordedKeys.has(recordKeyFor(id) ?? '');
        assert.ok(ok, `acked ${JSON.stringify(id)} with no prior persist, benign verdict or committed record`);
      }
    }
  }
}

test('C13 done_when 5 (v5 invariant, static half): toAck is only ever filled inside the ack door, never in the consume loop', () => {
  const src = readFileSync(new URL('./consume-mailbox.ts', import.meta.url), 'utf8');
  const door = src.indexOf('THE ACK DOOR');
  assert.ok(door > 0);
  assert.equal(src.slice(0, door).includes('toAck.push('), false, 'no toAck.push before the door');
  assert.equal((src.match(/toAck\.push\(/g) ?? []).length, 4, 'exactly four places add to toAck: no-record, cleared, recorded, released');
});

test('C13b done_when 5 (v5 invariant, behavioural half): over a mixed batch every acked id was persisted, benign or recorded first; an id whose record failed is NOT acked', async () => {
  const persisted = new Set<string>();
  const benign = new Set<string>(['ben']);
  const w = world(
    [
      { envelope_id: 'n1', blob: 'N1' }, { envelope_id: 'ben', blob: 'BEN' }, { envelope_id: 'j', blob: 'junk' }, { envelope_id: 'a/b', blob: 'junk-2' },
      { envelope_id: 'nofail', blob: 'junk-3' }, { envelope_id: 'h', blob: HYBRID },
    ],
    { failRecord: (id) => id === 'nofail' },
  );
  const note: NoteResponseSeam = {
    verify: async (b) => (b === 'N1' ? ({ type: NOTE_WIRE_TYPE, note_id: 'n-1', thread_id: 't', from_fingerprint: 'ab'.repeat(32), sent_at: NOW, body: 'x', participant_kind: 'human' } as never) : null),
    accept: async (wire) => {
      persisted.add('n1'); // the durable store write happens inside accept, before the door sees the outcome
      return { note_id: wire.note_id, thread_id: wire.thread_id, from_fingerprint: wire.from_fingerprint } as never;
    },
  };
  const joiner = { verify: async (b: string) => (b === 'BEN' ? ({ fingerprint: 'ff'.repeat(32) } as never) : null), accept: async () => null as never };
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note, joiner: joiner as never, hybridSecretMissing: true, fetchImpl: w.fetchImpl }));
  assertAckInvariant(w.events, persisted, benign);
  assert.deepEqual(acked(w.events).sort(), ['a/b', 'ben', 'j', 'n1'].sort(), 'and nothing else: nofail stays (record failed), h stays (held)');
});

test('C13c done_when 5 NEG: the invariant checker itself goes RED for an id acked with no prior persist/record, or acked BEFORE its record', () => {
  const row = { envelope_id: 'x', first_seen: NOW, reason: 'unknown-format', blob_kind: 'other' } as DeadLetterRow;
  assert.throws(() => assertAckInvariant([{ t: 'ack', ids: ['x'] }], new Set(), new Set()), /no prior persist/);
  assert.throws(() => assertAckInvariant([{ t: 'ack', ids: ['x'] }, { t: 'record', id: 'x', row }], new Set(), new Set()), /no prior persist/, 'record AFTER ack does not count');
  assert.doesNotThrow(() => assertAckInvariant([{ t: 'record', id: 'x', row }, { t: 'ack', ids: ['x'] }], new Set(), new Set()));
  assert.doesNotThrow(() => assertAckInvariant([{ t: 'record', id: recordKeyFor('a/b')!, row }, { t: 'ack', ids: ['a/b'] }], new Set(), new Set()), 'an unsafe id is covered by its DERIVED key');
});

test('C14 the reason for an unopenable blob depends on its SHAPE on both paths (decrypt returns null, and decrypt THROWS)', async () => {
  const cases: Array<{ blob: string; reason: string }> = [
    { blob: 'not-json-at-all', reason: 'unknown-format' },
    { blob: JSON.stringify({ v: 2, hello: 'x' }), reason: 'decrypt-failed' },
    { blob: '-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----', reason: 'decrypt-failed' },
  ];
  for (const how of ['null', 'throw'] as const) {
    for (const c of cases) {
      const w = world([{ envelope_id: 'e1', blob: c.blob }]);
      await consumeInboundContactUpdates(deps({
        deadLetter: w.sink,
        decrypt: how === 'null' ? async () => null : async () => { throw new Error('cannot decrypt'); },
        fetchImpl: w.fetchImpl,
      }));
      assert.equal(recorded(w.events)[0].reason, c.reason, `${how}: ${c.blob.slice(0, 20)}`);
    }
  }
});

test('C15 the reported held deadline comes ONLY from envelopes still held; a released one with an earlier deadline does not set it', async () => {
  const known = new Map<string, string>([['old', new Date(Date.parse(NOW) - 8 * DAY).toISOString()]]); // past 7 days: released
  const w = world([
    { envelope_id: 'old', blob: HYBRID, expires_at: '2026-10-31T00:00:00.000Z' },   // earliest deadline, but it is being released
    { envelope_id: 'keep', blob: HYBRID, expires_at: '2026-11-04T00:00:00.000Z' },
  ], { known });
  const seen: Array<{ n: number; expiresAt?: string }> = [];
  await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, emitHeld: (n, info) => seen.push({ n, expiresAt: info?.expiresAt }), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['old']);
  assert.deepEqual(seen, [{ n: 1, expiresAt: '2026-11-04T00:00:00.000Z' }]);
});

test('C16 settle() runs ONCE per poll when records were written, not otherwise, and a failing settle never changes what is acked', async () => {
  let settled = 0;
  const base = world([{ envelope_id: 'e1', blob: 'junk-1' }, { envelope_id: 'e2', blob: 'junk-2' }]);
  await consumeInboundContactUpdates(deps({ deadLetter: { ...base.sink, settle: async () => { settled++; } }, fetchImpl: base.fetchImpl }));
  assert.equal(settled, 1);
  const none = world([]);
  await consumeInboundContactUpdates(deps({ deadLetter: { ...none.sink, settle: async () => { settled++; } }, fetchImpl: none.fetchImpl }));
  assert.equal(settled, 1, 'empty mailbox: nothing written, no settle');
  const failing = world([{ envelope_id: 'e1', blob: 'junk-1' }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: { ...failing.sink, settle: async () => { throw new Error('prune failed'); } }, fetchImpl: failing.fetchImpl }));
  assert.deepEqual(acked(failing.events), ['e1']);
  assert.equal(s.deadLettered, 1);
});

test('C17 ruling (c): summary.lost counts each consumed LOSS per reason, with a sink AND without one (headless); benign terminals and opened notes count nothing', async () => {
  const FP = 'cd'.repeat(32);
  const envs = [{ envelope_id: 'u', blob: 'U' }, { envelope_id: 'b', blob: 'B' }, { envelope_id: 'r1', blob: 'R1' }, { envelope_id: 'r2', blob: 'R2' }, { envelope_id: 'j1', blob: 'junk-1' }, { envelope_id: 'j2', blob: 'junk-2' }];
  const note = () => noteSeam({
    U: { dropped: 'unverified' } as DroppedNote,
    B: { dropped: 'not-in-book', fp: FP } as DroppedNote,
    R1: { dropped: 'ratchet-unopenable', fp: FP } as DroppedNote,
    R2: { dropped: 'ratchet-unopenable', fp: FP } as DroppedNote,
  });
  const expected = { 'verify-failed': 1, 'not-in-book': 1, 'ratchet-unopenable': 2, 'unknown-format': 2 };
  const withSink = world(envs);
  assert.deepEqual((await consumeInboundContactUpdates(deps({ deadLetter: withSink.sink, note: note(), fetchImpl: withSink.fetchImpl }))).lost, expected);
  const headless = world(envs);
  const s = await consumeInboundContactUpdates(deps({ note: note(), fetchImpl: headless.fetchImpl })); // no sink: nothing recorded, still counted
  assert.deepEqual(s.lost, expected);
  assert.deepEqual(recorded(headless.events), []);
});

test('C17b a failed record is NOT counted as lost that poll; the retry that finally commits counts it exactly once; benign terminals count nothing', async () => {
  let fail = true;
  const w = world([{ envelope_id: 'j', blob: 'junk' }, { envelope_id: 'ben', blob: 'BEN' }], { failRecord: () => fail });
  const seam: NoteResponseSeam = { verify: async () => null, accept: async () => null };
  const joiner = { verify: async (b: string) => (b === 'BEN' ? ({ fingerprint: 'ff'.repeat(32) } as never) : null), accept: async () => null as never };
  const d = () => deps({ deadLetter: w.sink, note: seam, joiner: joiner as never, fetchImpl: w.fetchImpl });
  const first = await consumeInboundContactUpdates(d());
  assert.deepEqual(first.lost, {}); assert.equal(first.unrecorded, 1);
  fail = false;
  const second = await consumeInboundContactUpdates(d());
  assert.deepEqual(second.lost, { 'unknown-format': 1 });
});

test('C17c held envelopes count as lost ("missing-key") ONLY when released past the bound, never while kept', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 52 }, (_, i) => ({ envelope_id: `h${String(i).padStart(2, '0')}`, blob: HYBRID, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (52 - i)).toISOString()));
  const w = world(envs, { known });
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.deepEqual(s.lost, { 'missing-key': 2 }); assert.equal(s.released, 2); assert.equal(s.held, 50);
});

// ── contract v5.3 (Flint #2052): a ratchet frame THIS DEVICE could not open is HELD (kept, recorded at first sight, bounded), not acked ──
const FPC = 'cd'.repeat(32);
const seamOf = (byBlob: Record<string, () => Promise<unknown> | unknown>): NoteResponseSeam => ({
  verify: async (b) => (b in byBlob ? ({ type: NOTE_WIRE_TYPE, note_id: `n-${b}`, thread_id: 't1', from_fingerprint: 'CLAIMED', sent_at: NOW, body: 'x', participant_kind: 'human' } as never) : null),
  accept: async (w) => (await byBlob[w.note_id.slice(2)]()) as never,
});

test('C18 v5.3: a ratchet-LOCAL frame is HELD: not acked, a NAMED record (reason + fp) exists from the FIRST sighting, nothing counted as lost yet, the held count says 1', async () => {
  const w = world([{ envelope_id: 'loc1', blob: 'L1', expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }]);
  const reports: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, emitHeld: (n) => reports.push(n), note: seamOf({ L1: () => ({ dropped: 'ratchet-local', fp: FPC }) }), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), [], 'kept on the relay: this device may open it later');
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'ratchet-local'); assert.equal(row.fp, FPC);
  assert.equal(s.held, 1); assert.deepEqual(s.lost, {}); assert.deepEqual(reports, [1]);
});

test('C19 v5.3: a ratchet VERDICT frame is recorded and acked now, and counts as lost.ratchet-unopenable ONLY (the ward\'s sender-side counter), never as held', async () => {
  const w = world([{ envelope_id: 'ver1', blob: 'V1' }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ V1: () => ({ dropped: 'ratchet-unopenable', fp: FPC }) }), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['ver1']);
  assert.equal(recorded(w.events)[0].reason, 'ratchet-unopenable');
  assert.deepEqual(s.lost, { 'ratchet-unopenable': 1 }); assert.equal(s.held, 0);
});

test('C20 v5.3: 60 LOCAL frames from one contact => the 50 NEWEST stay, the 10 OLDEST are recorded then acked by their original ids, and they count as lost[ratchet-local] (not ratchet-unopenable)', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 60 }, (_, i) => ({ envelope_id: `l${String(i).padStart(2, '0')}`, blob: `L${i}`, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const w = world(envs, { known });
  const byBlob = Object.fromEntries(envs.map((_, i) => [`L${i}`, () => ({ dropped: 'ratchet-local', fp: FPC })]));
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf(byBlob), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events).sort(), Array.from({ length: 10 }, (_, i) => `l${String(i).padStart(2, '0')}`));
  assert.equal(s.released, 10); assert.equal(s.held, 50);
  assert.deepEqual(s.lost, { 'ratchet-local': 10 });
  for (const id of acked(w.events)) {
    const recIdx = w.events.findIndex((e) => e.t === 'record' && e.id === id);
    const ackIdx = w.events.findIndex((e) => e.t === 'ack' && e.ids.includes(id));
    assert.ok(recIdx >= 0 && recIdx < ackIdx, `${id}: record before ack`);
  }
});

test('C21 v5.3: a held LOCAL frame that OPENS on a later poll clears its record and is then acked (the message replaces its flag)', async () => {
  const known = new Map<string, string>();
  const w = world([{ envelope_id: 'heal1', blob: 'H1', expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }], { known });
  let healed = false;
  const note: NoteResponseSeam = seamOf({ H1: () => (healed ? { note_id: 'n-H1', thread_id: 't1', from_fingerprint: FPC } : { dropped: 'ratchet-local', fp: FPC }) });
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note, fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), []);
  healed = true; // the key came back / the row became readable
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note, fetchImpl: w.fetchImpl }));
  assert.deepEqual(w.events.filter((e) => e.t === 'clear').map((e) => (e as { id: string }).id), ['heal1']);
  assert.deepEqual(acked(w.events), ['heal1']);
});

test('C22 #307 x door: 45 consumed losses drain in ack chunks of <= 20 (incremental), every chunk\'s ids were recorded BEFORE that chunk, and the v5 invariant holds across all chunks', async () => {
  const envs = Array.from({ length: 45 }, (_, i) => ({ envelope_id: `j${String(i).padStart(2, '0')}`, blob: `junk-${i}` }));
  const w = world(envs);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  const chunks = w.events.filter((e): e is Extract<Ev, { t: 'ack' }> => e.t === 'ack').map((e) => e.ids.length);
  assert.deepEqual(chunks, [20, 20, 5]);
  assert.equal(s.acked, 45); assert.equal(s.deadLettered, 45);
  assert.equal(w.events.findIndex((e) => e.t === 'ack'), 20, 'the first chunk goes out right after the 20th record: incremental, not at the end, and never before its records');
  assertAckInvariant(w.events, new Set(), new Set());
});

test('C22b #307 x door: a record that fails mid-backlog keeps ONLY that envelope on the relay; the chunks around it still drain', async () => {
  const envs = Array.from({ length: 25 }, (_, i) => ({ envelope_id: `j${String(i).padStart(2, '0')}`, blob: `junk-${i}` }));
  const w = world(envs, { failRecord: (id) => id === 'j07' });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
  assert.equal(acked(w.events).includes('j07'), false);
  assert.equal(acked(w.events).length, 24);
  assert.equal(s.unrecorded, 1);
  assertAckInvariant(w.events, new Set(), new Set());
});

test('C23 a lock that lands AFTER a note was accepted but BEFORE the door runs: no clear, no ack (the stored note redelivers and re-applies idempotently)', async () => {
  const cycle = makeUnlockCycle(OWNER.privateKeyArmored, OWNER.passphrase);
  const w = world([{ envelope_id: 'n1', blob: 'N1' }]);
  const note: NoteResponseSeam = {
    verify: async () => ({ type: NOTE_WIRE_TYPE, note_id: 'n-1', thread_id: 't', from_fingerprint: 'ab'.repeat(32), sent_at: NOW, body: 'x', participant_kind: 'human' }) as never,
    accept: async (wire) => { cycle.drop(); return { note_id: wire.note_id, thread_id: wire.thread_id, from_fingerprint: wire.from_fingerprint } as never; },
  };
  await consumeInboundContactUpdates(deps({ owner: { ...OWNER, cycle }, deadLetter: w.sink, note, fetchImpl: w.fetchImpl }));
  assert.deepEqual(w.events, [], 'nothing cleared, nothing acked once the identity locked');
});

test('C24 r2-1: ONE contact whose fingerprint arrives in two letter cases is still ONE hold group: 55 frames (30 upper-case fp, 25 lower-case fp) release the 5 OLDEST, not none', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 55 }, (_, i) => ({ envelope_id: `m${String(i).padStart(2, '0')}`, blob: `M${i}`, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (55 - i)).toISOString())); // m00 oldest
  const byBlob = Object.fromEntries(envs.map((_, i) => [`M${i}`, () => ({ dropped: 'ratchet-local', fp: i < 30 ? FPC.toUpperCase() : FPC })]));
  const w = world(envs, { known });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf(byBlob), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events).sort(), ['m00', 'm01', 'm02', 'm03', 'm04']);
  assert.equal(s.released, 5); assert.equal(s.held, 50);
});

// ── T2 (Flint #186298): a RATCHET DESYNC on an authenticated contact's frame is HELD (kept, recorded at first sight, bounded), never acked as a verdict ──
test('C25 T2: a ratchet-DESYNC frame is HELD: not acked, a NAMED record (ratchet-desync + fp) exists from the first sighting, nothing counted as lost yet', async () => {
  const w = world([{ envelope_id: 'des1', blob: 'D1', expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ D1: () => ({ dropped: 'ratchet-desync', fp: FPC }) }), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), []);
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'ratchet-desync'); assert.equal(row.fp, FPC);
  assert.equal(s.held, 1); assert.deepEqual(s.lost, {});
});

test('C26 T2: desync and local holds from ONE contact are bounded SEPARATELY (50 each); 55 desync release the 5 oldest as lost[ratchet-desync]; the contact\'s 5 local frames are untouched', async () => {
  const known = new Map<string, string>();
  const desync = Array.from({ length: 55 }, (_, i) => ({ envelope_id: `d${String(i).padStart(2, '0')}`, blob: `DS${i}`, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  const local = Array.from({ length: 5 }, (_, i) => ({ envelope_id: `l${i}`, blob: `LC${i}`, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  desync.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const byBlob = { ...Object.fromEntries(desync.map((_, i) => [`DS${i}`, () => ({ dropped: 'ratchet-desync', fp: FPC })])), ...Object.fromEntries(local.map((_, i) => [`LC${i}`, () => ({ dropped: 'ratchet-local', fp: FPC })])) };
  const w = world([...desync, ...local], { known });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf(byBlob), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events).sort(), ['d00', 'd01', 'd02', 'd03', 'd04']);
  assert.deepEqual(s.lost, { 'ratchet-desync': 5 }); assert.equal(s.released, 5); assert.equal(s.held, 55);
});

test('C27 T2: a malformed ratchet frame (typed VERDICT) is still recorded and acked at once, apart from the held desync class', async () => {
  const w = world([{ envelope_id: 'v1', blob: 'V1' }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ V1: () => ({ dropped: 'ratchet-unopenable', fp: FPC }) }), fetchImpl: w.fetchImpl }));
  assert.deepEqual(acked(w.events), ['v1']);
  assert.deepEqual(s.lost, { 'ratchet-unopenable': 1 }); assert.equal(s.held, 0);
});

test('C28 T2 B1-for-holds (Flint #2185, M3): outsiders can fill the missing-key group; 60 junk missing-key holds do NOT push an admitted contact\'s OLDER held ratchet-desync frame out (desync is its own per-contact group)', async () => {
  const known = new Map<string, string>();
  const exp = new Date(Date.parse(NOW) + 6 * DAY).toISOString();
  const desync = { envelope_id: 'dsx', blob: 'DSX', expires_at: exp };
  const junk = Array.from({ length: 60 }, (_, i) => ({ envelope_id: `mk${String(i).padStart(2, '0')}`, blob: HYBRID, expires_at: exp }));
  known.set(desync.envelope_id, new Date(Date.parse(NOW) - 1000 * 1000).toISOString()); // the desync frame is the OLDEST hold of all
  junk.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const w = world([desync, ...junk], { known });
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, note: seamOf({ DSX: () => ({ dropped: 'ratchet-desync', fp: FPC }) }), fetchImpl: w.fetchImpl }));
  assert.equal(acked(w.events).includes('dsx'), false, 'the held desync frame is NOT released by an outsider-fillable group');
  assert.deepEqual(acked(w.events).sort(), Array.from({ length: 10 }, (_, i) => `mk${String(i).padStart(2, '0')}`), 'only the 10 oldest missing-key holds are released (bounded against their own group)');
  assert.equal(s.released, 10); assert.equal(s.held, 51); assert.deepEqual(s.lost, { 'missing-key': 10 });
});

// ── T2b (Flint #186298 T2): a held ratchet-DESYNC envelope is retried on every poll for its first hour, then hourly ──
const MIN = 60_000;
/** One held desync envelope on a relay that keeps returning it; a clock the test moves; a seam that counts how often the ratchet was actually tried. */
function backoffRig(opts: { kind?: 'ratchet-desync' | 'ratchet-local' } = {}) {
  const t0 = Date.parse(NOW);
  const clock = { ms: t0 };
  const known = new Map<string, string>();
  const calls = { n: 0 };
  const env = { envelope_id: 'bo1', blob: 'BO1', expires_at: new Date(t0 + 6 * DAY).toISOString() };
  const w = world([env], { known });
  const hb = createHoldBackoff();
  const seam = (healed: () => boolean): NoteResponseSeam =>
    seamOf({ BO1: () => { calls.n++; return healed() ? { note_id: 'n-BO1', thread_id: 't1', from_fingerprint: FPC } : { dropped: opts.kind ?? 'ratchet-desync', fp: FPC }; } });
  const poll = (at: number, healed = () => false, withBackoff = true) => {
    clock.ms = t0 + at * MIN;
    return consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seam(healed), fetchImpl: w.fetchImpl, now: () => new Date(clock.ms).toISOString(), ...(withBackoff ? { holdBackoff: hb } : {}) }));
  };
  return { w, hb, calls, poll };
}

test('C29 T2b: in the first hour a held desync frame is tried on EVERY poll', async () => {
  const r = backoffRig();
  for (const at of [0, 1, 20, 59]) await r.poll(at);
  assert.equal(r.calls.n, 4);
  assert.deepEqual(acked(r.w.events), [], 'held, never acked');
});

test('C30 T2b: after the first hour it is tried hourly: skipped in between (the ratchet is not touched), tried again an hour after the last try', async () => {
  const r = backoffRig();
  await r.poll(0); await r.poll(59); // 2 tries, the last at +59m
  const before = r.calls.n;
  await r.poll(61); await r.poll(90); await r.poll(118);
  assert.equal(r.calls.n, before, 'no try at +61, +90, +118 min: not due');
  await r.poll(119);
  assert.equal(r.calls.n, before + 1, 'an hour after the last try (+59m) it is tried again');
  await r.poll(150);
  assert.equal(r.calls.n, before + 1, 'and the hour restarts from that try');
});

test('C31 T2b: a SKIPPED poll still counts it as held with its recorded reason + fp: the record is refreshed, the held count is 1, nothing is acked or counted lost', async () => {
  const r = backoffRig();
  await r.poll(0); await r.poll(59);
  const recordsBefore = recorded(r.w.events).length;
  const s = await r.poll(90); // skipped
  assert.equal(s.held, 1); assert.deepEqual(s.lost, {}); assert.equal(s.released, 0);
  assert.deepEqual(acked(r.w.events), []);
  const rows = recorded(r.w.events);
  assert.ok(rows.length > recordsBefore, 'the skipped poll still goes through the record path');
  const last = rows[rows.length - 1];
  assert.equal(last.reason, 'ratchet-desync'); assert.equal(last.fp, FPC);
});

test('C32 T2b: when the frame finally opens it is stored + acked, and the schedule is forgotten', async () => {
  const r = backoffRig();
  await r.poll(0); await r.poll(59);
  assert.equal(r.hb.size(), 1);
  const s = await r.poll(119, () => true);
  assert.equal(s.notes, 1);
  assert.deepEqual(acked(r.w.events), ['bo1']);
  assert.equal(r.hb.size(), 0, 'forgotten once it opened');
});

test('C33 T2b: an envelope that is gone from the relay is pruned from the schedule (the map stays as small as the mailbox)', async () => {
  const r = backoffRig();
  await r.poll(0);
  assert.equal(r.hb.size(), 1);
  const empty = world([]);
  await consumeInboundContactUpdates(deps({ deadLetter: empty.sink, note: seamOf({}), fetchImpl: empty.fetchImpl, holdBackoff: r.hb }));
  assert.equal(r.hb.size(), 0);
});

test('C34 T2b: only DESYNC is backed off: a ratchet-LOCAL hold is still tried on every poll, even two hours in', async () => {
  const r = backoffRig({ kind: 'ratchet-local' });
  for (const at of [0, 61, 90, 125, 126]) await r.poll(at);
  assert.equal(r.calls.n, 5);
  assert.equal(r.hb.size(), 0, 'a local hold never enters the schedule');
});

test('C35 T2b: without a holdBackoff in deps nothing changes: tried on every poll', async () => {
  const r = backoffRig();
  for (const at of [0, 61, 90, 125]) await r.poll(at, () => false, false);
  assert.equal(r.calls.n, 4);
});

// ── T4 (Flint #186298): a held frame never blocks a newer frame from the same peer that opens; a stored note heals that peer's held frames in the SAME poll ──
const OTHER = 'ef'.repeat(32);
const exp6 = () => new Date(Date.parse(NOW) + 6 * DAY).toISOString();
const okNote = (id: string, fp = FPC) => ({ note_id: id, thread_id: 't1', from_fingerprint: fp });
const desync = (fp = FPC) => ({ dropped: 'ratchet-desync', fp });

test('C36 T4: a held desync frame does not block a NEWER note from the same peer: the note is stored and acked, the held frame stays held', async () => {
  const calls = { d: 0 };
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf({ D1: () => { calls.d++; return desync(); }, N1: () => okNote('n-N1') }) }));
  assert.deepEqual(acked(w.events), ['n1']);
  assert.equal(s.notes, 1); assert.equal(s.held, 1); assert.equal(s.dropped, 1, 'the still-held frame is counted once, not twice');
  assert.equal(calls.d, 2, 'tried at first sight and again after the peer\'s note was stored (T4), and still held');
});

test('C37 T4: a frame that only opens AFTER a later note from its peer was stored is healed in the SAME poll (and counted as a note, not as dropped)', async () => {
  let stored = false;
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const note = seamOf({ D1: () => (stored ? okNote('n-D1') : desync()), N1: () => { stored = true; return okNote('n-N1'); } });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note }));
  assert.deepEqual(acked(w.events).sort(), ['d1', 'n1']);
  assert.equal(s.notes, 2); assert.equal(s.held, 0); assert.equal(s.dropped, 0); assert.deepEqual(s.lost, {});
});

test('C38 T4 x T2b: the retry is FORCED: a desync frame that is not due yet (backed off) is still tried when its peer\'s note is stored', async () => {
  const t0 = Date.parse(NOW);
  const hb = createHoldBackoff();
  hb.attempted('d1', FPC, t0 - 120 * MIN); hb.attempted('d1', FPC, t0 - 30 * MIN); // past the first hour, last try 30 min ago: NOT due
  assert.equal(hb.due('d1', t0), false);
  let stored = false; const calls = { d: 0 };
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const note = seamOf({ D1: () => { calls.d++; return stored ? okNote('n-D1') : desync(); }, N1: () => { stored = true; return okNote('n-N1'); } });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note, holdBackoff: hb }));
  assert.equal(calls.d, 1, 'skipped at first (not due), then tried once by the T4 retry');
  assert.deepEqual(acked(w.events).sort(), ['d1', 'n1']); assert.equal(s.held, 0);
  assert.equal(hb.size(), 0, 'healed: the schedule is forgotten');
});

test('C39 T4: only THAT peer\'s held frames are retried: a note from someone else does not touch them', async () => {
  const calls = { d: 0 };
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf({ D1: () => { calls.d++; return desync(FPC); }, N1: () => okNote('n-N1', OTHER) }) }));
  assert.equal(calls.d, 1, 'not retried');
  assert.equal(s.held, 1); assert.deepEqual(acked(w.events), ['n1']);
});

test('C40 T4: a retry that opens can heal the NEXT held frame: rounds run until one frees nothing (D2 needs D1, D1 needs N1)', async () => {
  const done = new Set<string>();
  const w = world([{ envelope_id: 'd2', blob: 'D2', expires_at: exp6() }, { envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const note = seamOf({
    D2: () => (done.has('D1') ? (done.add('D2'), okNote('n-D2')) : desync()),
    D1: () => (done.has('N1') ? (done.add('D1'), okNote('n-D1')) : desync()),
    N1: () => (done.add('N1'), okNote('n-N1')),
  });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note }));
  assert.deepEqual(acked(w.events).sort(), ['d1', 'd2', 'n1']);
  assert.equal(s.notes, 3); assert.equal(s.held, 0); assert.equal(s.dropped, 0);
});

test('C41 T4: the peer match ignores letter case (the same contact\'s fingerprint can arrive in either case)', async () => {
  let stored = false;
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const note = seamOf({ D1: () => (stored ? okNote('n-D1', FPC) : desync(FPC.toUpperCase())), N1: () => { stored = true; return okNote('n-N1', FPC); } });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note }));
  assert.deepEqual(acked(w.events).sort(), ['d1', 'n1']); assert.equal(s.held, 0);
});

test('C42 T4: a held frame is NOT retried when no note from its peer was stored (no spurious second try, no change in the held count)', async () => {
  const calls = { d: 0 };
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf({ D1: () => { calls.d++; return desync(); } }) }));
  assert.equal(calls.d, 1); assert.equal(s.held, 1); assert.equal(s.dropped, 1);
});

test('C43 T4: the case-insensitive match holds on BOTH sides: a note whose fingerprint arrives upper-case heals a held frame recorded lower-case', async () => {
  let stored = false;
  const w = world([{ envelope_id: 'd1', blob: 'D1', expires_at: exp6() }, { envelope_id: 'n1', blob: 'N1', expires_at: exp6() }]);
  const note = seamOf({ D1: () => (stored ? okNote('n-D1', FPC) : desync(FPC)), N1: () => { stored = true; return okNote('n-N1', FPC.toUpperCase()); } });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note }));
  assert.deepEqual(acked(w.events).sort(), ['d1', 'n1']); assert.equal(s.held, 0);
});

// ── T5 / F5 (behavioural half; the structural half is consume-cells-tripwire.test.ts) ──
test('C44 T5: a cell-shaped blob (constant size, random pad) on the receive path is never HELD, never raises a held notice, never becomes a note or a receipt, and never gets a ratchet reason', async () => {
  const bytes = Uint8Array.from({ length: 2048 }, (_, i) => (i * 131 + 17) & 0xff);
  const cell = Buffer.from(bytes).toString('base64');
  const w = world([{ envelope_id: 'cell1', blob: cell, expires_at: exp6() }]);
  const heldReports: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf({}), emitHeld: (n) => heldReports.push(n) }));
  assert.equal(s.held, 0); assert.equal(s.notes, 0); assert.equal(s.delivered, 0);
  assert.deepEqual(heldReports.filter((n) => n > 0), [], 'no held notice');
  assert.equal(recorded(w.events).some((r) => r.reason === 'ratchet-desync' || r.reason === 'ratchet-local' || r.reason === 'session-reset'), false, 'no ratchet reason: it is not an authenticated contact\'s frame');
  assert.equal(Object.keys(s.lost).some((k) => k.startsWith('ratchet') || k === 'session-reset'), false);
});

// ── reset step 2(i): the PHASE of a held row ──
test('C45 phase: a held frame\'s row says HELD from the first sighting (desync, local and missing-key alike)', async () => {
  const w = world([{ envelope_id: 'p1', blob: 'P1', expires_at: exp6() }, { envelope_id: 'p2', blob: 'P2', expires_at: exp6() }, { envelope_id: 'p3', blob: HYBRID, expires_at: exp6() }]);
  await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf({ P1: () => desync(), P2: () => ({ dropped: 'ratchet-local', fp: FPC }) }) }));
  const rows = recorded(w.events);
  assert.deepEqual(rows.map((r) => `${r.reason}:${r.phase}`).sort(), ['missing-key:held', 'ratchet-desync:held', 'ratchet-local:held']);
});

test('C46 phase: a frame released past the bound is RE-RECORDED as recorded BEFORE its ack; the 50 that stay are still held', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 55 }, (_, i) => ({ envelope_id: `r${String(i).padStart(2, '0')}`, blob: `R${i}`, expires_at: exp6() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const w = world(envs, { known });
  const byBlob = Object.fromEntries(envs.map((_, i) => [`R${i}`, () => desync()]));
  const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl, note: seamOf(byBlob) }));
  assert.equal(s.released, 5);
  const lastPhase = new Map<string, string | undefined>();
  for (const r of recorded(w.events)) lastPhase.set(r.envelope_id, r.phase);
  for (const id of ['r00', 'r01', 'r02', 'r03', 'r04']) {
    assert.equal(lastPhase.get(id), 'recorded', `${id} is recorded now`);
    const rec = w.events.map((e, i) => (e.t === 'record' && e.id === id && e.row.phase === 'recorded' ? i : -1)).filter((i) => i >= 0)[0];
    const ack = w.events.findIndex((e) => e.t === 'ack' && e.ids.includes(id));
    assert.ok(rec >= 0 && rec < ack, `${id}: the recorded row is committed before the ack`);
  }
  for (let i = 5; i < 55; i++) assert.equal(lastPhase.get(`r${String(i).padStart(2, '0')}`), 'held');
});

test('C47 phase: if the RECORDED re-write fails, the frame is NOT acked and stays held (released on a later poll); nothing is lost', async () => {
  const known = new Map<string, string>();
  const envs = Array.from({ length: 51 }, (_, i) => ({ envelope_id: `q${String(i).padStart(2, '0')}`, blob: `Q${i}`, expires_at: exp6() }));
  envs.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const w = world(envs, { known });
  const sink = { ...w.sink, record: async (row: DeadLetterRow) => { if (row.phase === 'recorded') throw new Error('store locked'); return w.sink.record(row); } };
  const byBlob = Object.fromEntries(envs.map((_, i) => [`Q${i}`, () => desync()]));
  const s = await consumeInboundContactUpdates(deps({ deadLetter: sink, fetchImpl: w.fetchImpl, note: seamOf(byBlob) }));
  assert.deepEqual(acked(w.events), [], 'the oldest was due for release, but its recorded row could not be written: no ack');
  assert.equal(s.released, 0); assert.equal(s.unrecorded, 1); assert.equal(s.held, 51, 'it is still counted as held');
});

// ── R2: a frame the user's session reset released is recorded as session-reset and acked WITHOUT being opened ──
const relSink = (w: ReturnType<typeof world>, released: Map<string, string> | (() => Promise<Map<string, string>>)): DeadLetterSink => ({
  ...w.sink,
  releasedByReset: async () => (typeof released === 'function' ? released() : released),
});

test('C48 R2: a reset-released envelope is acked WITHOUT being opened, recorded as session-reset with the contact\'s fp, and counted as lost[session-reset]', async () => {
  const calls = { n: 0 };
  const w = world([{ envelope_id: 'rs1', blob: 'RS1', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: relSink(w, new Map([['rs1', FPC]])), fetchImpl: w.fetchImpl, note: seamOf({ RS1: () => { calls.n++; return desync(); } }) }));
  assert.equal(calls.n, 0, 'never opened');
  assert.deepEqual(acked(w.events), ['rs1']);
  const rows = recorded(w.events);
  assert.equal(rows.length, 1); assert.equal(rows[0].reason, 'session-reset'); assert.equal(rows[0].fp, FPC); assert.equal(rows[0].phase, undefined);
  assert.deepEqual(s.lost, { 'session-reset': 1 }); assert.equal(s.held, 0);
  assert.ok(w.events.findIndex((e) => e.t === 'record') < w.events.findIndex((e) => e.t === 'ack'), 'record before ack');
});

test('C49 R2: only the LISTED envelopes are released: another held frame from the same contact is still tried and still held', async () => {
  const calls = { n: 0 };
  const w = world([{ envelope_id: 'rs1', blob: 'RS1', expires_at: exp6() }, { envelope_id: 'keep', blob: 'KP', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: relSink(w, new Map([['rs1', FPC]])), fetchImpl: w.fetchImpl, note: seamOf({ RS1: () => desync(), KP: () => { calls.n++; return desync(); } }) }));
  assert.deepEqual(acked(w.events), ['rs1']);
  assert.equal(calls.n, 1); assert.equal(s.held, 1);
});

test('C50 R2: if releasedByReset THROWS the poll carries on: nothing is released, the frame is tried like any held frame and stays held', async () => {
  const calls = { n: 0 };
  const w = world([{ envelope_id: 'rs1', blob: 'RS1', expires_at: exp6() }]);
  const s = await consumeInboundContactUpdates(deps({ deadLetter: relSink(w, async () => { throw new Error('store locked'); }), fetchImpl: w.fetchImpl, note: seamOf({ RS1: () => { calls.n++; return desync(); } }) }));
  assert.equal(calls.n, 1); assert.deepEqual(acked(w.events), []); assert.equal(s.held, 1);
});

test('C51 R2: a released envelope whose RECORD cannot be written is NOT acked (record-before-ack holds for resets too)', async () => {
  const w = world([{ envelope_id: 'rs1', blob: 'RS1', expires_at: exp6() }], { failRecord: () => true });
  const s = await consumeInboundContactUpdates(deps({ deadLetter: relSink(w, new Map([['rs1', FPC]])), fetchImpl: w.fetchImpl, note: seamOf({ RS1: () => desync() }) }));
  assert.deepEqual(acked(w.events), []); assert.equal(s.unrecorded, 1); assert.deepEqual(s.lost, {});
});

// ── #720 cause-on-row: WHY a ratchet frame did not open travels onto the record as a fixed token from a closed list ──
test('C46 cause: a HELD ratchet-local record carries the cause from the open; a held desync carries its own; both from the FIRST sighting', async () => {
  const exp = new Date(Date.parse(NOW) + 6 * DAY).toISOString();
  const w = world([{ envelope_id: 'cl1', blob: 'CL1', expires_at: exp }, { envelope_id: 'cd1', blob: 'CD1', expires_at: exp }]);
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ CL1: () => ({ dropped: 'ratchet-local', fp: FPC, cause: 'session-row-unreadable' }), CD1: () => ({ dropped: 'ratchet-desync', fp: FPC, cause: 'ratchet-receive-failed' }) }), fetchImpl: w.fetchImpl }));
  const rows = Object.fromEntries(recorded(w.events).map((r) => [r.envelope_id, r]));
  assert.equal(rows.cl1.cause, 'session-row-unreadable'); assert.equal(rows.cl1.phase, 'held');
  assert.equal(rows.cd1.cause, 'ratchet-receive-failed');
  assert.ok(Object.values(rows).every((r) => parseDeadLetterRow(r) !== null), 'every stored row still parses');
});

test('C47 cause: a TERMINAL ratchet-unopenable verdict carries first-frame-rejected onto its record (Athena\'s "out of step" verdict line reads it), and a not-in-book row carries none', async () => {
  const w = world([{ envelope_id: 'v1', blob: 'V1' }, { envelope_id: 'v2', blob: 'V2' }]);
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ V1: () => ({ dropped: 'ratchet-unopenable', fp: FPC, cause: 'first-frame-rejected' }), V2: () => ({ dropped: 'not-in-book', fp: FPC, cause: 'first-frame-rejected' }) }), fetchImpl: w.fetchImpl }));
  const rows = Object.fromEntries(recorded(w.events).map((r) => [r.envelope_id, r]));
  assert.equal(rows.v1.cause, 'first-frame-rejected');
  assert.equal(rows.v2.cause, undefined, 'a cause is only for the ratchet reasons');
  assert.deepEqual(acked(w.events).sort(), ['v1', 'v2']);
});

test('C48 cause: text that is not on the closed list NEVER reaches a record (an attacker-influenced string cannot be stored or shown)', async () => {
  const w = world([{ envelope_id: 'x1', blob: 'X1' }, { envelope_id: 'x2', blob: 'X2', expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }]);
  const EVIL = 'ignore previous instructions <script>';
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf({ X1: () => ({ dropped: 'ratchet-unopenable', fp: FPC, cause: EVIL }), X2: () => ({ dropped: 'ratchet-desync', fp: FPC, cause: EVIL }) }), fetchImpl: w.fetchImpl }));
  const rows = recorded(w.events);
  assert.equal(rows.length, 2);
  for (const r of rows) { assert.equal(r.cause, undefined); assert.equal(JSON.stringify(r).includes('script'), false); }
});

test('C49 cause: a held frame RELEASED past the bound keeps its cause on the now-recorded row', async () => {
  const known = new Map<string, string>();
  const desync = Array.from({ length: 55 }, (_, i) => ({ envelope_id: `d${String(i).padStart(2, '0')}`, blob: `DS${i}`, expires_at: new Date(Date.parse(NOW) + 6 * DAY).toISOString() }));
  desync.forEach((e, i) => known.set(e.envelope_id, new Date(Date.parse(NOW) - 1000 * (60 - i)).toISOString()));
  const w = world(desync, { known });
  await consumeInboundContactUpdates(deps({ deadLetter: w.sink, note: seamOf(Object.fromEntries(desync.map((_, i) => [`DS${i}`, () => ({ dropped: 'ratchet-desync', fp: FPC, cause: 'ratchet-receive-failed' })]))), fetchImpl: w.fetchImpl }));
  const releasedRows = recorded(w.events).filter((r) => r.phase === 'recorded');
  assert.equal(releasedRows.length, 5);
  assert.ok(releasedRows.every((r) => r.cause === 'ratchet-receive-failed' && r.reason === 'ratchet-desync'));
});

test('C50 cause: a desync frame SKIPPED by the backoff still refreshes its record WITH the desync cause (the record path does not lose it)', async () => {
  const r = backoffRig();
  await r.poll(0); await r.poll(59);
  await r.poll(90); // skipped
  const rows = recorded(r.w.events);
  assert.equal(rows[rows.length - 1].cause, 'ratchet-receive-failed');
  assert.ok(r.calls.n >= 2);
});
