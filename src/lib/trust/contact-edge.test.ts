// src/lib/trust/contact-edge.test.ts
// The projection carries pq to the edge — the end-to-end half of Peter's "PQ-keys-dropped-on-every-edge".
// Run: npx tsx --test src/lib/trust/contact-edge.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contactRecordToEdge } from './contact-edge';

const kem = 'AAAA-ml-kem-pubkey-b64';
const sig = 'BBBB-ml-dsa-pubkey-b64';

test('carries pq from a ContactRecord (pq_*_public_key) → edge.peer_pq_*_public_key', () => {
  const edge = contactRecordToEdge({
    id: 'x', fingerprint: 'fp1', name: 'Bob', public_key: 'PK',
    pq_kem_public_key: kem, pq_sig_public_key: sig,
  });
  assert.equal(edge.peer_pq_kem_public_key, kem);
  assert.equal(edge.peer_pq_sig_public_key, sig);
  assert.equal(edge.peer_fingerprint, 'fp1');
  assert.equal(edge.peer_public_key, 'PK');
});

test('carries pq from an already-edge-shaped source (peer_pq_*) unchanged', () => {
  const edge = contactRecordToEdge({
    id: 'y', peer_fingerprint: 'fp2', peer_name: 'Ada', peer_public_key: 'PK2',
    peer_pq_kem_public_key: kem, peer_pq_sig_public_key: sig,
  });
  assert.equal(edge.peer_pq_kem_public_key, kem);
  assert.equal(edge.peer_pq_sig_public_key, sig);
});

test('carries owner_verify from metadata for the trust prereq', () => {
  const edge = contactRecordToEdge({
    id: 'v',
    fingerprint: 'fp4',
    name: 'Eli',
    public_key: 'PK4',
    metadata: { owner_verify: { owner_verified_at: '2026-01-01T00:00:00.000Z', method: 'in_person' } },
  });
  assert.equal(edge.owner_verify?.method, 'in_person');
});

test('carries inbound distress as a witnessed receipt', () => {
  const edge = contactRecordToEdge({
    id: 'd',
    fingerprint: 'fp5',
    name: 'Ada',
    public_key: 'PK5',
    metadata: { distress_inbound: true },
  });
  assert.equal(edge.distress_inbound, true);
});

test('a contact with no pq → edge pq is undefined (no crash, classical-only edge)', () => {
  const edge = contactRecordToEdge({ id: 'z', fingerprint: 'fp3', name: 'Cy', public_key: 'PK3' });
  assert.equal(edge.peer_pq_kem_public_key, undefined);
  assert.equal(edge.peer_pq_sig_public_key, undefined);
  assert.equal(edge.peer_fingerprint, 'fp3');
});
