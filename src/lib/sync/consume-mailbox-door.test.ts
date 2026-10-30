// src/lib/sync/consume-mailbox-door.test.ts
// #720 R1/R2/R9 + contract v3 "ONE ACK DOOR": an envelope that did not become a stored message is acked ONLY after a metadata-only
// record of it was committed. Failure to commit keeps it on the relay. Benign terminals (named list) are acked with no record.
// NEG-first: on dev there is no `deadLetter` dep, so none of these records exist.
// Run: npx tsx --test src/lib/sync/consume-mailbox-door.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { generateKey, readKey } from 'openpgp';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { consumeInboundContactUpdates, type ConsumeDeps, type DeadLetterSink, type DroppedNote, type NoteResponseSeam } from './consume-mailbox';
import { parseDeadLetterRow, type DeadLetterRow } from './dead-letter';

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

test('C3 an unsafe envelope id (the relay lets a depositor choose it) gets NO row and is NEVER acked', async () => {
  for (const id of ['../x', 'a/b', '', 'x'.repeat(101), 'é', 'a b']) {
    const w = world([{ envelope_id: id, blob: 'junk' }]);
    const s = await consumeInboundContactUpdates(deps({ deadLetter: w.sink, fetchImpl: w.fetchImpl }));
    assert.deepEqual(recorded(w.events), [], JSON.stringify(id));
    assert.deepEqual(acked(w.events), [], JSON.stringify(id));
    assert.equal(s.unrecorded, 1);
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

test('C6 a stranger contact-update (sender NOT authenticated) is recorded as verify-failed with NO fingerprint, even though the blob names one', async () => {
  const ATTACKER_FP = 'ee'.repeat(32);
  const w = world([{ envelope_id: 's1', blob: HYBRID }]);
  await consumeInboundContactUpdates(deps({
    deadLetter: w.sink,
    decrypt: async () => ({ envelope: { fingerprint: ATTACKER_FP } }) as never,
    store: { lookup: async () => null, persist: async () => {} },
    fetchImpl: w.fetchImpl,
  }));
  const row = recorded(w.events)[0];
  assert.equal(row.reason, 'verify-failed');
  assert.equal(JSON.stringify(row).includes(ATTACKER_FP), false, 'attacker-controlled fingerprint never stored');
  assert.deepEqual(acked(w.events), ['s1']);
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

test('C12 an unlock cycle that ended mid-tick records nothing and acks nothing', async () => {
  const cycle = makeUnlockCycle(OWNER.privateKeyArmored, OWNER.passphrase);
  const w = world([{ envelope_id: 'e1', blob: 'junk' }, { envelope_id: 'h1', blob: HYBRID }]);
  const s = await consumeInboundContactUpdates(deps({
    owner: { ...OWNER, cycle }, deadLetter: w.sink, fetchImpl: w.fetchImpl,
    hybridSecretMissing: async () => { cycle.drop(); return true; },
  }));
  assert.deepEqual(w.events, [], 'no record, no ack');
  assert.equal(s.deadLettered, 0);
});

test('C13 done_when 5 (static): toAck is only ever filled inside the ack door, never in the consume loop', () => {
  const src = readFileSync(new URL('./consume-mailbox.ts', import.meta.url), 'utf8');
  const door = src.indexOf('THE ACK DOOR');
  assert.ok(door > 0);
  assert.equal(src.slice(0, door).includes('toAck.push('), false, 'no toAck.push before the door');
  assert.equal((src.match(/toAck\.push\(/g) ?? []).length, 4, 'exactly four places add to toAck: no-record, cleared, recorded, released');
  assert.equal((src.match(/\/ack`/g) ?? []).length, 1, 'one ack call');
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
