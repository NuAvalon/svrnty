import { test } from 'node:test';
import assert from 'node:assert/strict';
import { livingEdgeStatus, livingStatusChip } from './living-edge-status';
import type { TrustEdge } from './types';

function edge(p: Partial<TrustEdge> & { peer_fingerprint: string }): TrustEdge {
  return {
    id: p.peer_fingerprint,
    peer_fingerprint: p.peer_fingerprint,
    peer_name: p.peer_name || p.peer_fingerprint,
    peer_email: '',
    peer_public_key: p.peer_public_key ?? 'PUB',
    trusted: false,
    trusted_since: null,
    last_interaction: new Date().toISOString(),
    decay_days: 730,
    trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: [],
    notes: '',
    connection_channels: [],
    added_at: new Date().toISOString(),
    ...p,
  };
}

test('classical hollow cannot communicate', () => {
  const s = livingEdgeStatus(
    edge({ peer_fingerprint: 'c1', peer_public_key: '', fingerprint: '' } as any),
  );
  // without pubkey — force empty
  const classical = livingEdgeStatus({
    ...edge({ peer_fingerprint: 'c1', peer_public_key: '' }),
    peer_public_key: '',
  });
  assert.equal(classical.connection, 'classical');
  assert.equal(classical.canCommunicate, false);
  assert.equal(livingStatusChip(classical), 'Classical');
});

test('pending living cannot communicate', () => {
  const s = livingEdgeStatus(
    edge({
      peer_fingerprint: 'p1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      connection_status: 'pending',
    } as TrustEdge),
  );
  assert.equal(s.connection, 'pending');
  assert.equal(s.canCommunicate, false);
});

test('linked known can communicate; own-trust reads outbound — a device-bit reciprocal no longer renders mutual (#593)', () => {
  const outbound = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      trusted: true,
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
      connection_status: 'accepted',
    } as TrustEdge),
  );
  assert.equal(outbound.connection, 'linked');
  assert.equal(outbound.canCommunicate, true);
  assert.equal(outbound.trust, 'outbound');
  assert.equal(livingStatusChip(outbound), 'Trusted');

  // #593 REMOVAL PROOF: a device-held mutual.{reciprocal,they_trust_me} is NO LONGER trusted as a mutual
  // signal (affirm-wire removed — a device bit is false security). Even with reciprocal:true on the device,
  // the edge reads 'outbound' (the owner's own sovereign trust), NOT 'mutual'. Mutual is PSI-discovered (#588).
  const deviceReciprocal = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      trusted: true,
      mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
      connection_status: 'accepted',
    } as TrustEdge),
  );
  assert.equal(deviceReciprocal.trust, 'outbound', 'device-bit reciprocal does NOT produce mutual (#593)');
  assert.notEqual(deviceReciprocal.trust, 'mutual', 'mutual is PSI-only now (#588)');
  assert.equal(livingStatusChip(deviceReciprocal), 'Trusted');
});

test('#593: a one-way (own-trust) edge reads "Trusted", NEVER "awaiting mutual" (no affirm-wire in flight)', () => {
  // The affirm-wire is removed, so a trusted one-way edge reads the honest "Trusted" (its own device
  // trust) + the device-local reciprocity detail — never "awaiting mutual" (there is no affirm wire that
  // could land). Mutual is discovered via the blind PSI intersection (#588), not an affirm wait.
  const outbound = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      trusted: true,
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
      connection_status: 'accepted',
    } as TrustEdge),
  );
  assert.equal(outbound.trust, 'outbound', 'phase is the owner own-trust outbound');
  assert.equal(outbound.statusLine, 'Trusted', 'status is "Trusted", NOT "Trusted · awaiting mutual"');
  assert.equal(outbound.detailLine, 'Trust is on your device · reciprocity probe is fleet-owned');
  assert.ok(!/awaiting mutual/i.test(outbound.statusLine), 'never implies a transient mutual wait');
});

test('undelivered method update surfaces on detail', () => {
  const s = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      connection_status: 'accepted',
      metadata: { method_delivery: 'undelivered' },
    } as TrustEdge),
  );
  assert.equal(s.methodDelivery, 'undelivered');
  assert.ok(s.detailLine?.includes('ack'));
});
