// A card's authority pin (identity.next_authority_commitment) must survive the Gate: the waiting arrival keeps it, Admit copies it onto the new
// contact, and the first pin wins. Same canonical rule as the Contacts import (64 lowercase hex).
//   npx tsx --test src/lib/trust/grow-gate-pin.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildAdmitRecord, mergeArrivalPin } from './grow-gate';
import { normalizeArrival, type GateArrival } from '@/lib/identity/client-store';

const PIN1 = 'a1'.repeat(32);
const PIN2 = 'b2'.repeat(32);
const arrival = (over: Record<string, unknown> = {}): GateArrival => ({
  fingerprint: 'aa'.repeat(32),
  displayName: 'Gabe',
  publicKeyArmored: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----',
  epoch: 0,
  inviteNonce: 'CODE1',
  mintChannel: 'remote',
  arrivedAt: '2026-11-09T00:00:00.000Z',
  direction: 'scanned_giver',
  ...over,
}) as GateArrival;

test('P1 mergeArrivalPin: nothing held and a pin offered -> the pin; nothing offered -> none', () => {
  assert.deepEqual(mergeArrivalPin(null, PIN1), { pin: PIN1, conflict: false });
  assert.deepEqual(mergeArrivalPin(arrival(), PIN1), { pin: PIN1, conflict: false });
  assert.deepEqual(mergeArrivalPin(null, null), { pin: null, conflict: false });
});
test('P2 mergeArrivalPin: a held pin is never erased by a card with none, and the same pin is not a conflict', () => {
  const held = arrival({ nextAuthorityCommitment: PIN1 });
  assert.deepEqual(mergeArrivalPin(held, null), { pin: PIN1, conflict: false });
  assert.deepEqual(mergeArrivalPin(held, PIN1), { pin: PIN1, conflict: false });
});
test('P3 mergeArrivalPin: a DIFFERENT pin is a conflict and the first pin stays', () => {
  assert.deepEqual(mergeArrivalPin(arrival({ nextAuthorityCommitment: PIN1 }), PIN2), { pin: PIN1, conflict: true });
});
test('P4 mergeArrivalPin: a non-canonical offer counts as none (never stored, never a conflict)', () => {
  const held = arrival({ nextAuthorityCommitment: PIN1 });
  for (const bad of ['A1'.repeat(32), 'a1'.repeat(31), 'a1'.repeat(33), '', 7, {}, undefined, 'a1'.repeat(32) + '\n']) {
    assert.deepEqual(mergeArrivalPin(held, bad), { pin: PIN1, conflict: false }, String(bad));
    assert.deepEqual(mergeArrivalPin(null, bad), { pin: null, conflict: false }, String(bad));
  }
});

test('N1 normalizeArrival keeps a canonical pin through the settings JSON round trip, and drops anything else', () => {
  const roundTrip = (a: unknown) => normalizeArrival(JSON.parse(JSON.stringify(a)));
  assert.equal(roundTrip(arrival({ nextAuthorityCommitment: PIN1 }))?.nextAuthorityCommitment, PIN1);
  for (const bad of ['A1'.repeat(32), 'a1'.repeat(31), 12345, null, ['a1'.repeat(32)]]) {
    const n = roundTrip(arrival({ nextAuthorityCommitment: bad }));
    assert.ok(n, 'the arrival itself is still kept');
    assert.equal('nextAuthorityCommitment' in (n as object), false, String(bad));
  }
  assert.equal('nextAuthorityCommitment' in (roundTrip(arrival()) as object), false);
});

test('B1 buildAdmitRecord puts a canonical pin on the contact, and none when the arrival has none or a bad one', () => {
  assert.equal(buildAdmitRecord(arrival({ nextAuthorityCommitment: PIN1 })).next_authority_commitment, PIN1);
  assert.equal('next_authority_commitment' in buildAdmitRecord(arrival()), false);
  assert.equal('next_authority_commitment' in buildAdmitRecord(arrival({ nextAuthorityCommitment: 'ZZ' })), false);
});

test('J1 [static] on the join link the gate branch checks the pin conflict BEFORE it enqueues, returns on a conflict, and passes the merged pin', () => {
  const s = readFileSync('src/components/JoinerCeremony.tsx', 'utf8');
  const merge = s.indexOf('mergeArrivalPin(');
  const enqueue = s.indexOf('await enqueueGateArrival(ownerFp, {');
  assert.ok(merge > 0 && enqueue > 0);
  assert.ok(merge < enqueue, 'the merge (and its conflict check) comes first');
  const between = s.slice(merge, enqueue);
  assert.match(between, /pinMerge\.conflict/);
  assert.match(between, /authorityPinConflictMessage\(peer\.name\)/);
  assert.match(between, /return;/, 'a conflict returns before the enqueue');
  assert.match(s.slice(enqueue, enqueue + 900), /nextAuthorityCommitment: pinMerge\.pin/, 'the arrival carries the MERGED pin (a held pin is never dropped)');
});

test('S1 [static] the storage layer takes no signing code for the pin: client-store does not import identity-card-sign, and the pin module has no imports', () => {
  const store = readFileSync('src/lib/identity/client-store.ts', 'utf8');
  assert.doesNotMatch(store, /from '\.\/identity-card-sign'/);
  assert.match(store, /import \{ canonicalAuthorityPin \} from '\.\/authority-pin';/);
  assert.doesNotMatch(readFileSync('src/lib/identity/authority-pin.ts', 'utf8'), /^\s*import\s/m);
});
