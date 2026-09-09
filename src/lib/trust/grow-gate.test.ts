import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  GATE_COPY,
  arrivalFromPendingJoiner,
  acceptJoinerAtGate,
  buildAdmitRecord,
  clampArrivalName,
  isGrowGateRecord,
  joinerPersistPlan,
  parseTagList,
  matchGateQuery,
  starsOnly,
} from './grow-gate';
import type { GateArrival } from '@/lib/identity/client-store';
import type { PendingJoiner } from '@/lib/trust/joiner-response';
import type { ContactRecord, IssuedCodeMap } from '@/lib/identity/client-store';

const arrival = (over: Partial<GateArrival> = {}): GateArrival => ({
  fingerprint: 'aa'.repeat(20),
  displayName: 'Bob',
  publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----',
  epoch: 0,
  inviteNonce: 'CODE1',
  mintChannel: 'remote',
  arrivedAt: '2026-09-09T00:00:00.000Z',
  direction: 'inbound_joiner',
  ...over,
});

test('clampArrivalName strips controls and bounds length', () => {
  assert.equal(clampArrivalName('  Bob\n'), 'Bob');
  assert.equal(clampArrivalName('x'.repeat(200)).length, 80);
  assert.equal(clampArrivalName(1), '');
});

test('parseTagList splits, trims, dedups, caps', () => {
  assert.deepEqual(parseTagList('core, Core, builders'), ['core', 'builders']);
  assert.equal(parseTagList(Array.from({ length: 20 }, (_, i) => `g${i}`).join(',')).length, 12);
});

test('matchGateQuery matches name, fingerprint, or invite nonce', () => {
  assert.equal(matchGateQuery(arrival(), ''), true);
  assert.equal(matchGateQuery(arrival(), 'bob'), true);
  assert.equal(matchGateQuery(arrival(), 'CODE1'), true);
  assert.equal(matchGateQuery(arrival(), 'zzzz'), false);
});

test('starsOnly drops grow_gate records', () => {
  const rows = [
    { id: '1', metadata: { grow_gate: true } },
    { id: '2', metadata: {} },
    { id: '3' },
  ];
  assert.deepEqual(starsOnly(rows).map((r) => r.id), ['2', '3']);
  assert.equal(isGrowGateRecord({ metadata: { grow_gate: true } }), true);
  assert.equal(isGrowGateRecord({ metadata: { grow_gate: false } }), false);
});

test('buildAdmitRecord is Known, not trusted; provenance is owner-local', () => {
  const rec = buildAdmitRecord(arrival({ mintChannel: 'in_person' }), {
    name: 'Robert',
    tags: ['core'],
    notes: 'met at the market',
    verify: 'in_person',
  });
  assert.equal(rec.trust_level, 'known');
  assert.equal(rec.trusted, undefined);
  assert.equal(rec.name, 'Robert');
  assert.equal(rec.owner_verify?.method, 'in_person');
  assert.equal((rec.metadata as { grow_invite_nonce?: string }).grow_invite_nonce, 'CODE1');
  assert.equal((rec.metadata as { grow_mint_channel?: string }).grow_mint_channel, 'in_person');
  assert.deepEqual(rec.tags, ['core']);
});

test('buildAdmitRecord without verify does not write owner_verify', () => {
  const rec = buildAdmitRecord(arrival());
  assert.equal(rec.owner_verify, undefined);
  assert.equal(rec.trust_level, 'known');
});

test('joinerPersistPlan: in-person admits+verifies; remote gates; missing presence waits', () => {
  assert.equal(joinerPersistPlan('in_person', false), 'admit-verified');
  assert.equal(joinerPersistPlan('remote', false), 'enqueue-gate');
  assert.equal(joinerPersistPlan(null, false), 'need-presence');
  assert.equal(joinerPersistPlan('remote', true), 'already-known');
});

test('arrivalFromPendingJoiner copies nonce + names and never upgrades channel', () => {
  const pj: PendingJoiner = {
    fingerprint: 'ff'.repeat(20),
    epoch: 0,
    publicKeyArmored: 'PUB',
    displayName: 'Ada',
    inviteNonce: 'abc',
    ts: '2026-09-09T00:00:00.000Z',
  };
  const a = arrivalFromPendingJoiner(pj, 'remote');
  assert.equal(a.inviteNonce, 'abc');
  assert.equal(a.mintChannel, 'remote');
  assert.equal(a.direction, 'inbound_joiner');
  assert.equal(a.displayName, 'Ada');
});

test('acceptJoinerAtGate enqueues instead of addContact; consumes the code slot', async () => {
  const codes: IssuedCodeMap = {
    alice: {
      CODE1: { acceptUntil: Date.now() + 60_000, accepted: [], cap: 1, channel: 'remote' },
    },
  };
  const enqueued: GateArrival[] = [];
  const accepted: string[] = [];
  const pj: PendingJoiner = {
    fingerprint: 'bobfp',
    epoch: 0,
    publicKeyArmored: 'BOBPUB',
    displayName: 'Bob',
    inviteNonce: 'CODE1',
    ts: '2026-09-09T00:00:00.000Z',
  };
  const res = await acceptJoinerAtGate('alice', pj, codes, {
    getContactByFingerprint: async () => null,
    getGateArrival: async () => null,
    enqueueGateArrival: async (_owner, a) => {
      enqueued.push(a);
    },
    recordAcceptedJoiner: async (_o, _c, fp) => {
      accepted.push(fp);
    },
  });
  assert.deepEqual(res, { ignited: true });
  assert.equal(enqueued.length, 1);
  assert.equal(enqueued[0].fingerprint, 'bobfp');
  assert.equal(enqueued[0].mintChannel, 'remote');
  assert.deepEqual(accepted, ['bobfp']);
  assert.deepEqual(codes.alice.CODE1.accepted, ['bobfp']);
});

test('acceptJoinerAtGate skips enqueue when already a contact (no second Known)', async () => {
  const codes: IssuedCodeMap = {
    alice: {
      CODE1: { acceptUntil: Date.now() + 60_000, accepted: [], cap: 1, channel: 'in_person' },
    },
  };
  let enq = 0;
  const res = await acceptJoinerAtGate(
    'alice',
    {
      fingerprint: 'bobfp',
      epoch: 0,
      publicKeyArmored: 'BOBPUB',
      displayName: 'Bob',
      inviteNonce: 'CODE1',
      ts: '2026-09-09T00:00:00.000Z',
    },
    codes,
    {
      getContactByFingerprint: async () => ({ id: 'c1' }) as ContactRecord,
      getGateArrival: async () => null,
      enqueueGateArrival: async () => {
        enq++;
      },
      recordAcceptedJoiner: async () => {},
    },
  );
  assert.equal(res, null);
  assert.equal(enq, 0);
  assert.deepEqual(codes.alice.CODE1.accepted, ['bobfp']);
});

test('in-person mint channel follows the issued code, not the joiner claim', async () => {
  const codes: IssuedCodeMap = {
    alice: {
      CODE1: { acceptUntil: Date.now() + 60_000, accepted: [], cap: 1, channel: 'in_person' },
    },
  };
  let channel: string | undefined;
  await acceptJoinerAtGate(
    'alice',
    {
      fingerprint: 'bobfp',
      epoch: 0,
      publicKeyArmored: 'BOBPUB',
      displayName: 'Bob',
      inviteNonce: 'CODE1',
      ts: '2026-09-09T00:00:00.000Z',
    },
    codes,
    {
      getContactByFingerprint: async () => null,
      getGateArrival: async () => null,
      enqueueGateArrival: async (_o, a) => {
        channel = a.mintChannel;
      },
      recordAcceptedJoiner: async () => {},
    },
  );
  assert.equal(channel, 'in_person');
});

test('Gate copy does not claim a public verified badge or Trust', () => {
  assert.match(GATE_COPY.joinTogetherHint, /does not prove who they are/i);
  assert.match(GATE_COPY.remoteHint, /Verify stays yours/);
  assert.equal(GATE_COPY.admit, 'Admit as Known');
  assert.match(GATE_COPY.latticeRemote, /arc on Galaxy/i);
  assert.match(GATE_COPY.sphereHint, /known sphere/i);
});
