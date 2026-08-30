// src/lib/trust/trust-map-layout.test.ts
// Run: npx tsx --test src/lib/trust/trust-map-layout.test.ts
//
// The load-bearing test is "no node escapes the frame" — that is the structural
// proof the mobile "only-center-shows" bug is dead. The old canvas used absolute
// radii that exceeded a phone's half-width; this asserts positions stay inside the
// viewBox for ANY contact count and ANY viewBox size, so scaling to 100% width can
// never push a node off-screen.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeTrustLayout,
  disclosureDepth,
  trustStateOf,
  NODE_RADIUS,
} from './trust-map-layout';
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
    last_interaction: new Date().toISOString(), // recent → not decayed by default
    decay_days: 730,
    trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: [],
    notes: '',
    connection_channels: [],
    added_at: new Date().toISOString(),
    ...partial,
  };
}

const trustedEdge = (p: Partial<TrustEdge> = {}) =>
  makeEdge({ trusted: true, trusted_since: new Date().toISOString(), ...p });
const knownEdge = (p: Partial<TrustEdge> = {}) => makeEdge({ trusted: false, ...p });
const decayedEdge = (p: Partial<TrustEdge> = {}) =>
  makeEdge({
    trusted: true,
    trusted_since: '2000-01-01T00:00:00.000Z',
    last_interaction: '2000-01-01T00:00:00.000Z', // far past + decay_days 730 → decayed
    decay_days: 730,
    ...p,
  });

// ── THE mobile-fix invariant ────────────────────────────────────────────────
test('no node escapes the frame — for any count, any viewBox size', () => {
  const counts = [0, 1, 2, 3, 5, 12, 25, 60];
  const sizes = [400, 360, 320, 240, 200, 800]; // incl. narrow-phone widths
  for (const size of sizes) {
    for (const count of counts) {
      const contacts = Array.from({ length: count }, (_, i) =>
        i % 3 === 0 ? trustedEdge() : i % 3 === 1 ? knownEdge() : decayedEdge(),
      );
      const layout = computeTrustLayout('owner-fp', 'Me', contacts, {
        width: size,
        height: size,
      });
      const all = [layout.self, ...layout.nodes];
      for (const n of all) {
        // Center of every node — plus its own radius — stays inside the box.
        assert.ok(
          n.x - n.radius >= 0 && n.x + n.radius <= size,
          `x out of bounds: ${n.x}±${n.radius} in ${size} (count=${count})`,
        );
        assert.ok(
          n.y - n.radius >= 0 && n.y + n.radius <= size,
          `y out of bounds: ${n.y}±${n.radius} in ${size} (count=${count})`,
        );
      }
      assert.equal(layout.nodes.length, count, 'every contact is placed');
    }
  }
});

test('self sits exactly at center', () => {
  const layout = computeTrustLayout('owner-fp', 'Me', [trustedEdge(), knownEdge()], {
    width: 400,
    height: 400,
  });
  assert.equal(layout.self.x, 200);
  assert.equal(layout.self.y, 200);
  assert.equal(layout.self.isOwner, true);
});

test('trust state maps to real state + salience radius', () => {
  assert.equal(trustStateOf(trustedEdge()), 'trusted');
  assert.equal(trustStateOf(knownEdge()), 'known');
  assert.equal(trustStateOf(decayedEdge()), 'decayed');

  const layout = computeTrustLayout('o', 'Me', [trustedEdge(), knownEdge(), decayedEdge()]);
  const byState = Object.fromEntries(layout.nodes.map((n) => [n.state, n]));
  // salience: trusted is the most prominent, decayed the least
  assert.equal(byState.trusted.radius, NODE_RADIUS.trusted);
  assert.equal(byState.known.radius, NODE_RADIUS.known);
  assert.equal(byState.decayed.radius, NODE_RADIUS.decayed);
  assert.ok(byState.trusted.radius > byState.known.radius);
  assert.ok(byState.known.radius > byState.decayed.radius);
});

test('trust is an overlay — not an inner/outer ring', () => {
  const contacts = [
    ...Array.from({ length: 6 }, (_, i) =>
      trustedEdge({ tags: ['crew'], peer_fingerprint: `t${i}`, peer_name: `T${i}` }),
    ),
    ...Array.from({ length: 6 }, (_, i) =>
      knownEdge({ tags: ['crew'], peer_fingerprint: `k${i}`, peer_name: `K${i}` }),
    ),
    ...Array.from({ length: 4 }, (_, i) =>
      trustedEdge({ tags: ['other'], peer_fingerprint: `u${i}`, peer_name: `U${i}` }),
    ),
    ...Array.from({ length: 4 }, (_, i) =>
      knownEdge({ tags: ['other'], peer_fingerprint: `v${i}`, peer_name: `V${i}` }),
    ),
  ];
  const layout = computeTrustLayout('o', 'Me', contacts, { width: 640, height: 640 });
  const dist = (n: { x: number; y: number }) => Math.hypot(n.x - layout.cx, n.y - layout.cy);
  const trustedR = layout.nodes.filter((n) => n.state === 'trusted').map(dist);
  const knownR = layout.nodes.filter((n) => n.state === 'known').map(dist);
  assert.ok(Math.max(...trustedR) > Math.min(...knownR), 'trusted still stacked inside known');
  const allR = [...trustedR, ...knownR];
  assert.ok(Math.max(...allR) - Math.min(...allR) > 20, 'lattice collapsed to a ring');
});

// ── I-6: opacity decodes to disclosure depth (what they shared) ──────────────
test('disclosure depth — dim rim for nothing-shared, bright for full disclosure', () => {
  // known + nothing shared → the dim rim (base 0.4). Unlit = privacy.
  assert.equal(disclosureDepth(knownEdge()), 0.4);

  // shared a channel → brighter
  const withPhone = knownEdge({ contact_info: { phones: ['+15551234567'] } });
  assert.ok(disclosureDepth(withPhone) > 0.4);

  // verified proof → brighter still
  const verified = trustedEdge({
    contact_info: { emails: ['x@y.com'] },
    verification: { method: 'qr', verified_at: new Date().toISOString() },
  });
  assert.equal(disclosureDepth(verified), 1); // 0.4 + 0.3 + 0.3, capped

  // opacity is always a valid alpha
  for (const e of [knownEdge(), trustedEdge(), withPhone, verified]) {
    const d = disclosureDepth(e);
    assert.ok(d >= 0 && d <= 1);
  }
});

// ── determinism: no Math.random → stable renders + testable ──────────────────
test('layout is deterministic (no randomness)', () => {
  const contacts = [trustedEdge(), knownEdge(), trustedEdge(), decayedEdge()];
  const a = computeTrustLayout('o', 'Me', contacts, { width: 400, height: 400 });
  const b = computeTrustLayout('o', 'Me', contacts, { width: 400, height: 400 });
  assert.deepEqual(a, b);
});

// ── empty book still yields a valid, on-screen self ──────────────────────────
test('empty contacts → just self, on-screen', () => {
  const layout = computeTrustLayout('owner-fp', 'Me', [], { width: 320, height: 320 });
  assert.equal(layout.nodes.length, 0);
  assert.equal(layout.self.x, 160);
  assert.equal(layout.self.y, 160);
});

test('dense book (200) still fits the world and does not ring-pack trust', () => {
  const contacts = Array.from({ length: 200 }, (_, i) =>
    i % 2 === 0
      ? trustedEdge({ tags: [i % 8 === 0 ? 'a' : 'b'], peer_fingerprint: `t${i}` })
      : knownEdge({ tags: [i % 8 === 0 ? 'a' : 'c'], peer_fingerprint: `k${i}` }),
  );
  const size = 1200;
  const layout = computeTrustLayout('o', 'Me', contacts, { width: size, height: size });
  assert.equal(layout.nodes.length, 200);
  for (const n of layout.nodes) {
    assert.ok(n.x - n.radius >= 0 && n.x + n.radius <= size);
    assert.ok(n.y - n.radius >= 0 && n.y + n.radius <= size);
  }
  const dist = (n: { x: number; y: number }) => Math.hypot(n.x - layout.cx, n.y - layout.cy);
  const tR = layout.nodes.filter((n) => n.state === 'trusted').map(dist);
  const kR = layout.nodes.filter((n) => n.state === 'known').map(dist);
  assert.ok(Math.max(...tR) > Math.min(...kR));
});

test('witnessed mutual springs pull a pair closer than the same graph without they_trust', () => {
  const base = (fp: string, they: string[] = []) =>
    trustedEdge({
      peer_fingerprint: fp,
      peer_name: fp,
      open_visibility: true,
      they_trust: they,
      mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
      tags: [],
    });
  const lonely = [
    base('sally'),
    base('joe'),
    base('other'),
  ];
  const bonded = [
    base('sally', ['joe']),
    base('joe', ['sally']),
    base('other'),
  ];
  const a = computeTrustLayout('o', 'Me', lonely, { width: 720, height: 720 });
  const b = computeTrustLayout('o', 'Me', bonded, { width: 720, height: 720 });
  const by = (layout: typeof a) => Object.fromEntries(layout.nodes.map((n) => [n.id, n]));
  const dist = (layout: typeof a) => {
    const m = by(layout);
    return Math.hypot(m.sally.x - m.joe.x, m.sally.y - m.joe.y);
  };
  const without = dist(a);
  const withBond = dist(b);
  assert.ok(
    withBond < without * 0.75,
    `mutual spring did not tighten Sally↔Joe: ${without} → ${withBond}`,
  );
  assert.ok(withBond < 130, `bonded pair still too far: ${withBond}`);
});
