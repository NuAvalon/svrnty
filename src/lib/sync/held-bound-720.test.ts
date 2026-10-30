// src/lib/sync/held-bound-720.test.ts
// #720 r2 (Flint): the HELD keep bound (50 / 7 days) must not be one budget shared by every held envelope. A 'ratchet-local' frame is an
// ADMITTED contact's message this device could not open yet (held so it can open later). With one shared count, 50 newer held envelopes from
// ANYONE else release it (record + ack: a recoverable message becomes a loss): another contact's crafted frames (a throw in the open is LOCAL),
// or hybrid packages an outsider deposits while this device has no kem secret ('missing-key'). Same rule as B1 for records: a group may only
// push out its own. NEG-first: on b250f6d both tests fail (the older frame is released).
// Run: npx tsx --test src/lib/sync/held-bound-720.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { consumeInboundContactUpdates, type ConsumeDeps, type DeadLetterSink, type DroppedNote, type NoteResponseSeam } from './consume-mailbox';

let OWNER: ConsumeDeps['owner'];
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
  OWNER = { fingerprint: (await readKey({ armoredKey: publicKey })).getFingerprint(), publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

const NOW = '2026-10-30T12:00:00.000Z';
const ago = (ms: number) => new Date(Date.parse(NOW) - ms).toISOString();
const HYBRID = JSON.stringify({ v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', mailbox_fp: 'ab'.repeat(32), epk: 'e', kem_ct: 'k', nonce: 'n', ct: 'c' });
const FP_A = 'aa'.repeat(32);
const FP_B = 'bb'.repeat(32);

function run(envs: Array<{ envelope_id: string; blob: string }>, firstSeen: Map<string, string>, drops: Record<string, DroppedNote>, extra: Partial<ConsumeDeps> = {}) {
  const acked: string[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify(envs), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/ack')) {
      const ids = JSON.parse(String(init?.body ?? '{}')).envelope_ids as string[];
      acked.push(...ids);
      return new Response(JSON.stringify({ deleted: ids.length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  const sink: DeadLetterSink = {
    record: async (row) => {
      const prev = firstSeen.get(row.envelope_id);
      const first_seen = prev && Date.parse(prev) < Date.parse(row.first_seen) ? prev : row.first_seen;
      firstSeen.set(row.envelope_id, first_seen);
      return { ...row, first_seen };
    },
    clear: async () => {},
  };
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob in drops ? ({ type: NOTE_WIRE_TYPE, note_id: `n-${blob}`, thread_id: 't', from_fingerprint: 'CLAIMED', sent_at: NOW, body: 'x', participant_kind: 'human' } as never) : null),
    accept: async (w) => drops[w.note_id.slice(2)],
  };
  const deps: ConsumeDeps = {
    owner: OWNER, decrypt: async () => null, store: { lookup: async () => null, persist: async () => {} }, relayBase: 'http://relay.test/api/relay',
    now: () => NOW, deadLetter: sink, note, fetchImpl, ...extra,
  };
  return consumeInboundContactUpdates(deps).then((s) => ({ s, acked }));
}

test('H1 a contact\'s held LOCAL frame is not released by 51 newer LOCAL frames from ANOTHER contact (that contact\'s own oldest goes)', async () => {
  const firstSeen = new Map<string, string>([['a-old', ago(2 * 24 * 3600_000)]]);
  const envs = [{ envelope_id: 'a-old', blob: 'A0' }];
  const drops: Record<string, DroppedNote> = { A0: { dropped: 'ratchet-local', fp: FP_A } };
  for (let i = 0; i < 51; i++) {
    const id = `b-${String(i).padStart(2, '0')}`;
    envs.push({ envelope_id: id, blob: `B${i}` });
    drops[`B${i}`] = { dropped: 'ratchet-local', fp: FP_B };
    firstSeen.set(id, ago(3600_000 - i * 1000)); // b-00 is B's oldest, all newer than a-old
  }
  const { s, acked } = await run(envs, firstSeen, drops);
  assert.ok(!acked.includes('a-old'), 'A\'s held frame must stay on the relay: only B\'s own frames may count against B');
  assert.deepEqual(acked, ['b-00'], 'control: the bound still holds inside B\'s group (its oldest is released)');
  assert.equal(s.held, 51);
});

test('H1b a contact\'s held LOCAL frame is not released by 50 newer MISSING-KEY holds (outsider-depositable while this device has no kem secret)', async () => {
  const firstSeen = new Map<string, string>([['a-old', ago(2 * 24 * 3600_000)]]);
  const envs = [{ envelope_id: 'a-old', blob: 'A0' }];
  for (let i = 0; i < 51; i++) {
    const id = `j-${String(i).padStart(2, '0')}`;
    envs.push({ envelope_id: id, blob: HYBRID });
    firstSeen.set(id, ago(3600_000 - i * 1000));
  }
  const { acked } = await run(envs, firstSeen, { A0: { dropped: 'ratchet-local', fp: FP_A } }, { hybridSecretMissing: true });
  assert.ok(!acked.includes('a-old'), 'junk the device cannot open must not push out an admitted contact\'s held frame');
  assert.deepEqual(acked, ['j-00'], 'control: the missing-key group keeps its own bound');
});
