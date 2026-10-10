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

test('linked known can communicate; trust outbound distinct from mutual', () => {
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
  assert.equal(livingStatusChip(outbound), 'Trust sent');

  const mutual = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      trusted: true,
      mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
      connection_status: 'accepted',
    } as TrustEdge),
  );
  assert.equal(mutual.trust, 'mutual');
  assert.equal(livingStatusChip(mutual), 'Mutual');
});

test('PRE-WIRE (isMutualTrustWireLive false): a one-way edge reads the roadmap copy, NEVER "awaiting mutual"', () => {
  // The mutual-trust wire is not yet live end-to-end (deposit-hook + two-seat e2e). While the gate is
  // false, a trusted one-way edge must NOT imply a transient "awaiting mutual" wait for a state that
  // cannot arrive (built≠wired). It reads the honest roadmap copy instead (Hypatia v1). The phase stays
  // 'outbound' (the dashed/muted PR#215 affordance is unchanged); only the copy is gated.
  const outbound = livingEdgeStatus(
    edge({
      peer_fingerprint: 'a3aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      peer_public_key: 'PK',
      trusted: true,
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
      connection_status: 'accepted',
    } as TrustEdge),
  );
  assert.equal(outbound.trust, 'outbound', 'phase unchanged — affordance still one-way');
  assert.equal(outbound.statusLine, 'Trusted', 'pre-wire status is "Trusted", NOT "Trusted · awaiting mutual"');
  assert.equal(outbound.detailLine, 'Mutual confirmation coming', 'pre-wire detail is the roadmap line');
  assert.ok(!/awaiting mutual/i.test(outbound.statusLine), 'never implies a transient mutual wait pre-wire');
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
