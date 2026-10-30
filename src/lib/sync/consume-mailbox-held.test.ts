// src/lib/sync/consume-mailbox-held.test.ts
// #720 Cut 1 (Peter 15:17Z "don't delete, FLAG"): a blob the owner could not open YET (a hybrid package while the
// kem secret is not derivable) is already LEFT on the relay by the ③ loud gate; this pins that it is also COUNTED
// (summary.held) and REPORTED (deps.emitHeld) so the UI can say so. Only the "can't open yet, kept" case counts:
// a terminal drop is not "held". NEG-first: on the commit before this change `held` / `emitHeld` do not exist.
//
// Run: npx tsx --test src/lib/sync/consume-mailbox-held.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps, type NoteResponseSeam } from './consume-mailbox';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';

let OWNER: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-held';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'held', email: 'held@x.test' }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  OWNER = { fingerprint, publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

// A hybrid-package-SHAPED blob (the ③ gate is a shape check; nothing is opened before it).
const HYBRID_BLOB = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });

function relay(envs: Array<{ envelope_id: string; blob: string }>, opts: { queueStatus?: number } = {}) {
  const acks: string[][] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) {
      if (opts.queueStatus && opts.queueStatus !== 200) return new Response('no', { status: opts.queueStatus });
      return new Response(JSON.stringify(envs), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).includes('/ack')) { acks.push(JSON.parse(String(init?.body ?? '{}')).envelope_ids); return new Response(JSON.stringify({ deleted: 1 }), { status: 200 }); }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, acks };
}

function deps(over: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: OWNER, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay', now: () => '2026-10-30T15:00:00.000Z', ...over,
  };
}

test('H1 a hybrid package the owner cannot open YET is KEPT on the relay, COUNTED, and REPORTED (not deleted)', async () => {
  const { fetchImpl, acks } = relay([{ envelope_id: 'e1', blob: HYBRID_BLOB }]); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.held, 1, 'counted');
  assert.deepEqual(held, [1], 'reported once with the count');
  assert.equal(s.acked, 0); assert.deepEqual(acks, [], 'NOT acked: still on the relay');
  assert.equal(s.notes, 0);
});

test('H2 control: when the secret IS derivable the same blob is a genuine terminal drop, NOT "held" (no false flag)', async () => {
  const { fetchImpl } = relay([{ envelope_id: 'e1', blob: HYBRID_BLOB }]); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: false, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.held, 0); assert.deepEqual(held, [0], 'reported as zero so a stale notice clears');
});

test('H3 an empty mailbox reports 0 (this is what clears the notice once the blobs open or expire)', async () => {
  const { fetchImpl } = relay([]); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.held, 0); assert.deepEqual(held, [0]);
});

test('H4 a REJECTED poll (401) reports nothing: an unknown state must neither raise nor clear the notice', async () => {
  const { fetchImpl } = relay([], { queueStatus: 401 }); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.rejected, 401); assert.deepEqual(held, []);
});

test('H5 mixed mailbox: 2 held hybrids + 1 openable note: held=2, the note is persisted + acked, the hybrids are not', async () => {
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: 'BOB', sent_at: '2026-10-30T14:00:00.000Z', body: 'hi', participant_kind: 'human' } as never : null),
    accept: async (w) => ({ note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }),
  };
  const { fetchImpl, acks } = relay([{ envelope_id: 'h1', blob: HYBRID_BLOB }, { envelope_id: 'n1', blob: 'NOTE' }, { envelope_id: 'h2', blob: HYBRID_BLOB }]); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, note, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.held, 2); assert.equal(s.notes, 1); assert.deepEqual(held, [2]); assert.deepEqual(acks, [['n1']]);
});

test('H6 not a package: JSON that is not a hybrid package is not "held" even when the secret is missing (shape check)', async () => {
  const { fetchImpl } = relay([{ envelope_id: 'e1', blob: JSON.stringify({ v: 2, hello: 'x' }) }]); const held: number[] = [];
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.equal(s.held, 0); assert.deepEqual(held, [0]);
});

test('H7 a throwing emitHeld never breaks consume or the ack of the other envelopes', async () => {
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: 'BOB', sent_at: '2026-10-30T14:00:00.000Z', body: 'hi', participant_kind: 'human' } as never : null),
    accept: async (w) => ({ note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }),
  };
  const { fetchImpl, acks } = relay([{ envelope_id: 'h1', blob: HYBRID_BLOB }, { envelope_id: 'n1', blob: 'NOTE' }]);
  const s = await consumeInboundContactUpdates(deps({ hybridSecretMissing: true, note, emitHeld: () => { throw new Error('ui exploded'); }, fetchImpl }));
  assert.equal(s.held, 1); assert.equal(s.notes, 1); assert.deepEqual(acks, [['n1']]);
});

test('H8 a cycle that ends DURING the tick reports nothing (the lock is not a verdict on the mailbox)', async () => {
  const { fetchImpl, acks } = relay([{ envelope_id: 'e1', blob: HYBRID_BLOB }]); const held: number[] = [];
  const cycle = makeUnlockCycle(OWNER.privateKeyArmored, OWNER.passphrase);
  // The lock lands while the hybrid blob is being judged (the lazy check is where the FE derives the kem secret).
  const lockMidBlob = async () => { cycle.drop(); return true; };
  const s = await consumeInboundContactUpdates(deps({ owner: { ...OWNER, cycle }, hybridSecretMissing: lockMidBlob, emitHeld: (n) => held.push(n), fetchImpl }));
  assert.deepEqual(held, [], 'no report: neither raises nor clears the notice');
  assert.deepEqual(acks, [], 'and nothing was acked');
  assert.equal(s.polled, 1);
});

test('H9 control for H8: the same flow with a live cycle DOES report (so H8 is not passing for the wrong reason)', async () => {
  const { fetchImpl } = relay([{ envelope_id: 'e1', blob: HYBRID_BLOB }]); const held: number[] = [];
  const cycle = makeUnlockCycle(OWNER.privateKeyArmored, OWNER.passphrase);
  const s = await consumeInboundContactUpdates(deps({ owner: { ...OWNER, cycle }, hybridSecretMissing: async () => true, emitHeld: (n) => held.push(n), fetchImpl }));
  cycle.drop();
  assert.equal(s.held, 1); assert.deepEqual(held, [1]);
});
