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

test("livingEdgeStatus never returns 'inbound' or 'mutual' for any edge shape (incl. they_trust_me === true)", () => {
  let n = 0;
  for (const trusted of [false, true])
    for (const theyTrustMe of [null, false, true])
      for (const reciprocal of [false, true])
        for (const lastAffirm of [undefined, new Date().toISOString()])
          for (const outbound of [undefined, true])
            for (const probe of [undefined, 'pending', 'no-ack', 'acked'])
              for (const connection of [undefined, 'pending'])
                for (const key of ['PK', ''])
                  for (const fp of [LIVING_FP, 'short']) {
                    const e = edge({
                      trusted,
                      trusted_since: trusted ? new Date().toISOString() : null,
                      peer_fingerprint: fp,
                      peer_public_key: key,
                      connection_status: connection,
                      mutual: { they_trust_me: theyTrustMe, reciprocal, last_sync: null, last_affirm_at: lastAffirm },
                      metadata: { trust_outbound: outbound, trust_probe: probe },
                    });
                    const s = livingEdgeStatus(e);
                    n++;
                    assert.ok(s.trust === 'none' || s.trust === 'outbound', `trust=${s.trust} for ${JSON.stringify({ trusted, theyTrustMe, reciprocal, probe, connection })}`);
                    assert.notEqual(livingStatusChip(s), 'Mutual');
                    assert.doesNotMatch(s.statusLine, /mutual|trusts you/i);
                  }
  assert.ok(n >= 500, `covered ${n} shapes`);
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
