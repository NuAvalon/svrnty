// Run: npx tsx --test src/lib/trust/trust-map-browse-layout.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeBrowseClusters, collectGroupTags } from './trust-map-browse-layout';
import type { TrustEdge } from './types';

let seq = 0;
function makeEdge(partial: Partial<TrustEdge> = {}): TrustEdge {
  seq += 1;
  return {
    id: `edge-${seq}`,
    peer_fingerprint: `fp-${seq}`,
    peer_name: `Peer ${seq}`,
    peer_email: `peer${seq}@example.com`,
    peer_public_key: 'PUBKEY',
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
    ...partial,
  } as TrustEdge;
}

test('browse clusters bucket by first tag and surface trust/mutual counts', () => {
  const contacts = [
    makeEdge({
      tags: ['Family'],
      trusted: true,
      mutual: { they_trust_me: true, last_sync: null, reciprocal: true },
    }),
    makeEdge({ tags: ['Family'], trusted: false }),
    makeEdge({ tags: ['Work'], trusted: true }),
    makeEdge({ tags: [] }),
  ];
  const clusters = computeBrowseClusters(contacts, 400, 400);
  assert.equal(clusters.length, 3);
  const family = clusters.find((c) => c.tag === 'Family');
  assert.ok(family);
  assert.equal(family!.trustedCount, 1);
  assert.equal(family!.knownCount, 1);
  assert.equal(family!.mutualCount, 1);
  assert.ok(family!.members.some((m) => m.mutual));
});

test('browse layout stays inside the view (non-egocentric pack)', () => {
  const contacts = Array.from({ length: 12 }, (_, i) =>
    makeEdge({
      tags: [i % 3 === 0 ? 'A' : i % 3 === 1 ? 'B' : 'C'],
      trusted: i % 2 === 0,
      mutual: {
        they_trust_me: i % 4 === 0,
        last_sync: null,
        reciprocal: i % 4 === 0,
      },
    }),
  );
  const W = 400;
  const H = 400;
  const clusters = computeBrowseClusters(contacts, W, H);
  for (const cl of clusters) {
    for (const m of cl.members) {
      assert.ok(m.x >= -24 && m.x <= W + 24, `x out of bounds: ${m.x}`);
      assert.ok(m.y >= -24 && m.y <= H + 24, `y out of bounds: ${m.y}`);
    }
  }
});

test('collectGroupTags sorts unique labels', () => {
  const tags = collectGroupTags([
    makeEdge({ tags: ['zeta', 'alpha'] }),
    makeEdge({ tags: ['alpha'] }),
    makeEdge({ tags: [] }),
  ]);
  assert.deepEqual(tags, ['alpha', 'zeta']);
});
