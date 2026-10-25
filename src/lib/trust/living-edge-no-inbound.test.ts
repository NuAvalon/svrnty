// The Galaxy tab ember must never become a one-sided-trust oracle (Peter's hard gate, KB#93521 / registry NV-10; Flint ruling lane:svrnty #888).
//   1. livingEdgeStatus NEVER produces 'inbound' or 'mutual', for ANY combination of the fields that could plausibly drive a trust phase,
//      including a record whose device bit says they_trust_me === true (that derivation was removed with the affirm wire, #593).
//   2. app/page.tsx builds the ember's attention set from the connection phase only; it does not read the trust phase at all.
// Either failing alone is enough to reopen the oracle, so each is pinned on its own.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { livingEdgeStatus, livingStatusChip } from './living-edge-status';
import { TRUST_VISUAL_LABELS, visualForEdge } from '../../components/trust/trust-phase-visual';
import type { TrustEdge } from './types';

const LIVING_FP = 'p1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function edge(p: Record<string, unknown>): TrustEdge {
  return {
    id: LIVING_FP, peer_fingerprint: LIVING_FP, peer_name: 'x', peer_email: '', peer_public_key: 'PK', trusted: false, trusted_since: null,
    last_interaction: new Date().toISOString(), decay_days: 730, trust_history: [], verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false }, tags: [], notes: '', connection_channels: [], added_at: new Date().toISOString(),
    ...p,
  } as unknown as TrustEdge;
}

/** Every combination of the fields that could plausibly drive a trust phase, with the inputs named for failure messages. */
function allShapes(): Array<{ e: TrustEdge; why: string }> {
  const out: Array<{ e: TrustEdge; why: string }> = [];
  for (const trusted of [false, true])
    for (const theyTrustMe of [null, false, true])
      for (const reciprocal of [false, true])
        for (const lastAffirm of [undefined, new Date().toISOString()])
          for (const outbound of [undefined, true])
            for (const probe of [undefined, 'pending', 'no-ack', 'acked'])
              for (const connection of [undefined, 'pending'])
                for (const key of ['PK', ''])
                  for (const fp of [LIVING_FP, 'short']) {
                    out.push({
                      e: edge({
                        trusted,
                        trusted_since: trusted ? new Date().toISOString() : null,
                        peer_fingerprint: fp,
                        peer_public_key: key,
                        connection_status: connection,
                        mutual: { they_trust_me: theyTrustMe, reciprocal, last_sync: null, last_affirm_at: lastAffirm },
                        metadata: { trust_outbound: outbound, trust_probe: probe },
                      }),
                      why: JSON.stringify({ trusted, theyTrustMe, reciprocal, probe, connection, key: !!key, fp: fp.length }),
                    });
                  }
  return out;
}

test("livingEdgeStatus never returns 'inbound' or 'mutual' for any edge shape (incl. they_trust_me === true)", () => {
  const shapes = allShapes();
  for (const { e, why } of shapes) {
    const s = livingEdgeStatus(e);
    assert.ok(s.trust === 'none' || s.trust === 'outbound', `trust=${s.trust} for ${why}`);
    assert.notEqual(livingStatusChip(s), 'Mutual');
    assert.doesNotMatch(s.statusLine, /mutual|trusts you/i);
  }
  assert.ok(shapes.length >= 500, `covered ${shapes.length} shapes`);
});

// Flint #913: a UI arm keyed on the state the hard gate forbids revealing is a latent leak even when dead. So not only the STATUS but every
// RENDERED label for every edge shape must come from the honest vocabulary, and the dead 'trust-received' word must read like a stranger.
test("every rendered label, for every edge shape, is from the honest set; never 'Trust pending' or 'Mutual'", () => {
  // TWO surfaces with DIFFERENT vocabularies (Hypatia #921), each pinned exactly:
  //   livingStatusChip (living-edge-status.ts)           in {Known, Linked, Trusted, Classical, Pending}  (its only other output is 'Mutual')
  //   trustPhaseVisual().label (trust-phase-visual.ts)   in {Known, Trusted, Pending intro, Blocked}      (note: 'Pending intro', and blocked edges)
  // 'Mutual' / 'Mutual trust' stay in the maps (forward-compatible for PSI #588); this negative pin covers B.
  const CHIPS = new Set(['Known', 'Linked', 'Trusted', 'Classical', 'Pending']);
  const LABELS = new Set(['Known', 'Trusted', 'Pending intro', 'Blocked']);
  const seenChips = new Set<string>();
  const seenLabels = new Set<string>();
  for (const { e, why } of allShapes()) {
    const chip = livingStatusChip(livingEdgeStatus(e));
    seenChips.add(chip);
    assert.ok(CHIPS.has(chip), `chip '${chip}' for ${why}`);
    assert.doesNotMatch(chip, /Trust pending|Mutual|Awaiting|trusts you/i);
    for (const blocked of [false, true]) {
      const label = visualForEdge(e, { blocked }).label;
      seenLabels.add(label);
      assert.ok(LABELS.has(label), `label '${label}' (blocked=${blocked}) for ${why}`);
      assert.doesNotMatch(label, /Trust pending|Mutual|Awaiting|trusts you/i);
    }
  }
  // The loop is not vacuous: it reaches the trusted, known, pending-intro and blocked renderings.
  assert.ok(['Trusted', 'Known', 'Pending intro', 'Blocked'].every((l) => seenLabels.has(l)), `labels seen: ${[...seenLabels].join(', ')}`);
  // 'Known' as a CHIP is not reachable from this shape product (a keyed edge can communicate => 'Linked'); it is still in the allowed set.
  assert.ok(['Trusted', 'Linked', 'Classical', 'Pending'].every((c) => seenChips.has(c)), `chips seen: ${[...seenChips].join(', ')}`);
});

test("the dead 'trust-received' label cannot light up: it reads exactly what a stranger with no trust reads", () => {
  assert.equal(TRUST_VISUAL_LABELS['trust-received'], TRUST_VISUAL_LABELS.known);
  assert.equal(TRUST_VISUAL_LABELS['trust-received'], 'Known');
});

test('control: the same edge with only the OWNER\'s trust set does reach outbound (the loop is not vacuous)', () => {
  assert.equal(livingEdgeStatus(edge({ trusted: true })).trust, 'outbound');
  assert.equal(livingEdgeStatus(edge({ trusted: false })).trust, 'none');
});

test("app/page.tsx's Galaxy ember attention set reads the connection phase only, never the trust phase", () => {
  const src = readFileSync(join(__dirname, '..', '..', '..', 'app', 'page.tsx'), 'utf8');
  const block = /const attention = contacts([\s\S]*?)galaxyActivitySignature\(/.exec(src);
  assert.ok(block, 'the ember attention block exists');
  const code = block![1].replace(/\/\/.*$/gm, ''); // the explanatory comment names these words; only CODE counts
  assert.match(code, /status\.connection === 'pending'/);
  assert.doesNotMatch(code, /inbound/, "no 'inbound' arm");
  assert.doesNotMatch(code, /\.trust\b/, 'the trust phase is not read at all');
});
