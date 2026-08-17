// src/lib/contacts/dedup.test.ts
// 9.1 dedup engine — cluster detection. Run: npx tsx --test src/lib/contacts/dedup.test.ts
// dedup.ts imports only the TrustEdge TYPE (no crypto runtime deps) → runs standalone.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clusterByExactChannel, sharesChannel, type DedupCluster } from './dedup';
import type { TrustEdge } from '../trust/types';

/** Minimal TrustEdge for dedup tests — only the fields clustering reads matter; rest cast away. */
function mkEdge(over: Partial<TrustEdge> & { id: string }): TrustEdge {
  return {
    peer_fingerprint: '',
    peer_email: '',
    trusted: false,
    contact_info: undefined,
    ...over,
  } as TrustEdge;
}

const ids = (c: DedupCluster) => c.members.map((m) => m.id).sort();

test('exact: two edges sharing a phone (differently formatted) form one cluster of 2', () => {
  const a = mkEdge({ id: 'a', contact_info: { phones: ['+15551234567'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['+1 555 123 4567'] } }); // same number, spaced
  const clusters = clusterByExactChannel([a, b]);
  assert.equal(clusters.length, 1);
  assert.deepEqual(ids(clusters[0]), ['a', 'b']);
  assert.deepEqual(clusters[0].sharedKeys, ['phone:+15551234567']);
  assert.equal(clusters[0].matchType, 'exact');
});

test('no shared channel → no clusters', () => {
  const a = mkEdge({ id: 'a', peer_email: 'alice@x.com' });
  const b = mkEdge({ id: 'b', peer_email: 'bob@y.com' });
  assert.deepEqual(clusterByExactChannel([a, b]), []);
});

test('transitive: A~B (phone), B~C (email) → one cluster {A,B,C}', () => {
  const a = mkEdge({ id: 'a', contact_info: { phones: ['+15550000001'] } });
  const b = mkEdge({ id: 'b', peer_email: 'shared@x.com', contact_info: { phones: ['+15550000001'] } });
  const c = mkEdge({ id: 'c', peer_email: 'shared@x.com' });
  const clusters = clusterByExactChannel([a, b, c]);
  assert.equal(clusters.length, 1);
  assert.deepEqual(ids(clusters[0]), ['a', 'b', 'c']);
  assert.deepEqual(clusters[0].sharedKeys, ['email:shared@x.com', 'phone:+15550000001']);
});

test('order-independent: shuffled input → identical clustering + stable survivor', () => {
  const a = mkEdge({ id: 'a', contact_info: { phones: ['+15550000002'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['+15550000002'] } });
  const c = mkEdge({ id: 'c', contact_info: { phones: ['+15550000002'] } });
  const r1 = clusterByExactChannel([a, b, c]);
  const r2 = clusterByExactChannel([c, a, b]);
  assert.deepEqual(r1.map(ids), r2.map(ids));
  assert.equal(r1[0].survivor.id, r2[0].survivor.id);
});

test('living-wins: trusted living beats gray import as survivor', () => {
  const gray = mkEdge({ id: 'gray', peer_fingerprint: '', trusted: false, contact_info: { phones: ['+15550000003'] } });
  const living = mkEdge({ id: 'living', peer_fingerprint: 'FP', trusted: true, contact_info: { phones: ['+15550000003'] } });
  const [cluster] = clusterByExactChannel([gray, living]);
  assert.equal(cluster.survivor.id, 'living');
});

test('garbage/unnormalizable values never bind a cluster', () => {
  // bare national phone (no +) → unnormalizable → dedupKey null → not a match
  const a = mkEdge({ id: 'a', contact_info: { phones: ['5551234567'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['5551234567'] } });
  assert.deepEqual(clusterByExactChannel([a, b]), []);
  // empty email likewise (two strangers with no real channel must not collapse)
  const c = mkEdge({ id: 'c', peer_email: '' });
  const d = mkEdge({ id: 'd', peer_email: '' });
  assert.deepEqual(clusterByExactChannel([c, d]), []);
});

test('singletons excluded; independent pairs → 2 clusters ordered by survivor id', () => {
  const a = mkEdge({ id: 'a', contact_info: { phones: ['+15550000004'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['+15550000004'] } });
  const lonely = mkEdge({ id: 'lonely', peer_email: 'solo@x.com' });
  const x = mkEdge({ id: 'x', contact_info: { emails: ['pair2@x.com'] } });
  const y = mkEdge({ id: 'y', contact_info: { emails: ['pair2@x.com'] } });
  const clusters = clusterByExactChannel([a, b, lonely, x, y]);
  assert.equal(clusters.length, 2);
  assert.ok(!clusters.some((c) => c.members.some((m) => m.id === 'lonely')));
  const survivorIds = clusters.map((c) => c.survivor.id);
  assert.deepEqual(survivorIds, [...survivorIds].sort());
});

test('idempotent: re-clustering unique-channel survivors yields no merges', () => {
  // post-merge state: each person has a distinct channel → no cluster
  const p1 = mkEdge({ id: 'p1', contact_info: { phones: ['+15550000010'] } });
  const p2 = mkEdge({ id: 'p2', contact_info: { phones: ['+15550000011'] } });
  assert.deepEqual(clusterByExactChannel([p1, p2]), []);
});

test('sanity: sharesChannel agrees with cluster membership', () => {
  const a = mkEdge({ id: 'a', contact_info: { phones: ['+15550000005'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['+15550000005'] } });
  assert.ok(sharesChannel(a, b));
  assert.equal(clusterByExactChannel([a, b]).length, 1);
});
