// src/lib/contacts/dedup.test.ts
// 9.1 dedup engine — cluster detection. Run: npx tsx --test src/lib/contacts/dedup.test.ts
// dedup.ts imports only the TrustEdge TYPE (no crypto runtime deps) → runs standalone.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clusterByExactChannel, foldLivingWins, mergeCluster, sharesChannel, type DedupCluster } from './dedup';
import { livingWinsMerge } from './import-dedup';
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

// ─── foldLivingWins / mergeCluster (the field-union the cluster defers to) ────────────────

test('foldLivingWins: single member returned as-is', () => {
  const a = mkEdge({ id: 'a', peer_name: 'Solo', contact_info: { phones: ['+15550001000'] } });
  assert.equal(foldLivingWins([a]), a);
});

test('foldLivingWins: rank-winner scalars win + multi-value UNIONed (lossless)', () => {
  const trusted = mkEdge({ id: 't', peer_fingerprint: 'FP', trusted: true, peer_name: 'Alice',
    peer_email: 'alice@real.com', contact_info: { phones: ['+15550001111'], emails: ['alice@real.com'] } });
  const gray = mkEdge({ id: 'g', peer_name: 'Al', peer_email: 'al@old.com',
    contact_info: { phones: ['+15550002222'], emails: ['al@old.com'], urls: ['https://al.example'] } });
  const s = foldLivingWins([gray, trusted]); // input order must not matter
  assert.equal(s.peer_name, 'Alice');            // rank-winner (trusted) scalar wins
  assert.equal(s.peer_email, 'alice@real.com');  // trusted's non-empty email wins
  assert.deepEqual(s.contact_info?.phones, ['+15550001111', '+15550002222']); // union, living first
  assert.deepEqual([...(s.contact_info?.emails ?? [])].sort(), ['al@old.com', 'alice@real.com']);
  assert.deepEqual(s.contact_info?.urls, ['https://al.example']); // gray's url unioned in (base had none)
});

test('foldLivingWins: THE subtle bug — rank-winner is the base REGARDLESS of input order (not reduce-order)', () => {
  // A naive members.reduce(livingWinsMerge) would take members[0] (gray) as base → 'Wrong' scalar sticks.
  // The correct 2-step selects the rank-winner (trusted) as base → 'Right' wins even though gray is first.
  const gray = mkEdge({ id: 'g', peer_name: 'Wrong', contact_info: { phones: ['+15550003333'] } });
  const trusted = mkEdge({ id: 't', peer_fingerprint: 'FP', trusted: true, peer_name: 'Right',
    contact_info: { phones: ['+15550003333'] } });
  assert.equal(foldLivingWins([gray, trusted]).peer_name, 'Right');
  assert.equal(foldLivingWins([trusted, gray]).peer_name, 'Right'); // symmetric
});

test('foldLivingWins: order-independent (survivor + unioned fields identical under reorder)', () => {
  const a = mkEdge({ id: 'a', peer_fingerprint: 'FA', trusted: true, peer_name: 'A', contact_info: { phones: ['+15550004001'] } });
  const b = mkEdge({ id: 'b', peer_name: 'B', contact_info: { phones: ['+15550004002'] } });
  const c = mkEdge({ id: 'c', peer_name: 'C', contact_info: { phones: ['+15550004003'] } });
  const r1 = foldLivingWins([a, b, c]);
  const r2 = foldLivingWins([c, a, b]);
  assert.equal(r1.peer_name, r2.peer_name);
  assert.deepEqual([...(r1.contact_info?.phones ?? [])].sort(), [...(r2.contact_info?.phones ?? [])].sort());
});

test('mergeCluster: wraps foldLivingWins over cluster.members', () => {
  const a = mkEdge({ id: 'a', peer_fingerprint: 'FA', trusted: true, peer_name: 'A', contact_info: { phones: ['+15550005000'] } });
  const b = mkEdge({ id: 'b', contact_info: { phones: ['+15550005000'] } });
  const [cluster] = clusterByExactChannel([a, b]);
  assert.deepEqual(mergeCluster(cluster), foldLivingWins(cluster.members));
});

test('build-once: foldLivingWins([existing,incoming]) ≡ livingWinsMerge(existing,incoming) for the import case', () => {
  // when existing outranks incoming (import path: existing=living, incoming=gray), the 2-step
  // reduces to Apollo's pairwise merge exactly → import ≡ cluster (Hypatia build-once #115891).
  const existing = mkEdge({ id: 'e', peer_fingerprint: 'FE', trusted: true, peer_name: 'Existing',
    contact_info: { phones: ['+15550006000'], emails: ['e@x.com'] } });
  const incoming = mkEdge({ id: 'i', peer_name: 'Imported', contact_info: { phones: ['+15550006001'] } });
  assert.deepEqual(foldLivingWins([existing, incoming]), livingWinsMerge(existing, incoming));
});

test('foldLivingWins: empty member set throws (guard — clusters never produce this)', () => {
  assert.throws(() => foldLivingWins([]), /empty member set/);
});
