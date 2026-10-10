import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { livingEdgeStatus, type LivingEdgeStatus } from '../../lib/trust/living-edge-status';
import type { TrustEdge } from '../../lib/trust/types';
import {
  INTRO_PENDING_DASH,
  TRUST_VISUAL_LABELS,
  TRUST_VISUAL_WHITE_CORE,
  TRUST_VISUAL_WHITE_HALO,
  TRUST_VISUAL_WHITE_SPOKE,
  TRUST_SENT_PRE_WIRE_LABEL,
  trustPhaseVisual,
  trustVisualLane,
  visualForEdge,
  type TrustPhaseVisual,
} from './trust-phase-visual';

function status(p: Partial<LivingEdgeStatus> & Pick<LivingEdgeStatus, 'trust'>): LivingEdgeStatus {
  return {
    connection: 'linked',
    canCommunicate: true,
    methodDelivery: 'none',
    statusLine: '',
    detailLine: null,
    lastMoment: null,
    decayFreshness: 1,
    ...p,
  };
}

/** White light = core / spoke / halo. Shared hex chrome may reuse the cream stroke. */
function usesWhite(v: TrustPhaseVisual): boolean {
  return (
    v.white ||
    v.lit ||
    v.coreFill === TRUST_VISUAL_WHITE_CORE ||
    v.haloStroke === TRUST_VISUAL_WHITE_HALO ||
    v.spokeStroke === TRUST_VISUAL_WHITE_SPOKE
  );
}

describe('trust-phase visual map — white IFF mutual', () => {
  it('mutual is the only white/lit solid bond and labels Mutual trust', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'mutual' }) });
    assert.equal(v.bondState, 'mutual');
    assert.equal(v.lit, true);
    assert.equal(v.white, true);
    assert.equal(v.shape, 'solid-filled');
    assert.equal(v.label, TRUST_VISUAL_LABELS.mutual);
    assert.equal(v.coreFill, TRUST_VISUAL_WHITE_CORE);
    assert.equal(v.haloStroke, TRUST_VISUAL_WHITE_HALO);
    assert.equal(v.spokeGlow, true);
    assert.equal(v.svgDasharray, undefined);
  });

  it('outbound shares the mutual hex — no core, Known spoke; PRE-WIRE label is Trusted', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'outbound' }) });
    const mutual = trustPhaseVisual({ status: status({ trust: 'mutual' }) });
    const known = trustPhaseVisual({ status: status({ trust: 'none' }) });
    assert.equal(v.bondState, 'trust-sent');
    assert.equal(v.lit, false);
    assert.equal(v.white, false);
    assert.equal(v.shape, 'solid-filled');
    assert.equal(v.shape, mutual.shape);
    assert.equal(v.svgFill, mutual.svgFill);
    assert.equal(v.svgStroke, mutual.svgStroke);
    assert.equal(v.svgStrokeWidth, mutual.svgStrokeWidth);
    assert.equal(v.canvasFill, mutual.canvasFill);
    assert.equal(v.spokeStyle, 'single');
    // isMutualTrustWireLive() is false → one-way must NOT label "Trust pending" / "Awaiting mutual".
    assert.equal(v.label, TRUST_SENT_PRE_WIRE_LABEL);
    assert.notEqual(v.label, TRUST_VISUAL_LABELS['trust-sent']);
    assert.equal(v.coreFill, null);
    assert.equal(v.haloStroke, null);
    assert.notEqual(v.coreFill, mutual.coreFill);
    assert.equal(v.spokeGlow, false);
    assert.equal(v.svgDasharray, undefined);
    assert.equal(v.spokeDasharray, undefined);
    assert.equal(usesWhite(v), false);
    assert.equal(v.spokeStyle, known.spokeStyle);
    assert.equal(v.spokeStroke, known.spokeStroke);
  });

  it('one-way and mutual share the hex; only mutual has the core and the lit bond', () => {
    const outbound = trustPhaseVisual({ status: status({ trust: 'outbound' }) });
    const mutual = trustPhaseVisual({ status: status({ trust: 'mutual' }) });
    assert.equal(outbound.shape, mutual.shape);
    assert.equal(outbound.svgFill, mutual.svgFill);
    assert.equal(outbound.svgStroke, mutual.svgStroke);
    assert.notEqual(outbound.label, mutual.label);
    assert.equal(outbound.coreFill, null);
    assert.equal(mutual.coreFill, TRUST_VISUAL_WHITE_CORE);
    assert.equal(outbound.spokeStyle, 'single');
    assert.equal(mutual.spokeStyle, 'thick-bright');
    assert.equal(outbound.label, TRUST_SENT_PRE_WIRE_LABEL);
    assert.equal(mutual.label, TRUST_VISUAL_LABELS.mutual);
  });

  it('verified overlay never promotes outbound to mutual/white', () => {
    const v = trustPhaseVisual({
      status: status({ trust: 'outbound' }),
      verified: true,
    });
    assert.equal(v.verifiedMark, true);
    assert.equal(v.bondState, 'trust-sent');
    assert.equal(v.lit, false);
    assert.equal(v.white, false);
    assert.equal(v.coreFill, null);
    assert.equal(usesWhite(v), false);
  });

  it('intro connection pending is a distinct lane from trust-sent', () => {
    const intro = trustPhaseVisual({
      status: status({ trust: 'none', connection: 'pending', canCommunicate: false }),
    });
    const sent = trustPhaseVisual({ status: status({ trust: 'outbound' }) });
    assert.equal(intro.introPending, true);
    assert.equal(sent.introPending, false);
    assert.equal(intro.bondState, 'known');
    assert.equal(sent.bondState, 'trust-sent');
    assert.equal(intro.label, TRUST_VISUAL_LABELS.introPending);
    assert.equal(sent.label, TRUST_SENT_PRE_WIRE_LABEL); // pre-wire (gated); "Awaiting mutual" post-wire
    assert.notEqual(sent.label, intro.label); // trust-sent lane still distinct from intro-pending
    assert.notEqual(intro.svgDasharray, sent.svgDasharray);
    assert.equal(intro.svgDasharray, INTRO_PENDING_DASH);
    assert.equal(trustVisualLane(intro, false), 'pending');
    assert.equal(trustVisualLane(sent, false), 'trust-sent');
  });

  it('inbound shares the mutual hex — no core, Known spoke, Trust pending', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'inbound' }) });
    const mutual = trustPhaseVisual({ status: status({ trust: 'mutual' }) });
    const known = trustPhaseVisual({ status: status({ trust: 'none' }) });
    assert.equal(v.bondState, 'trust-received');
    assert.equal(v.shape, 'solid-filled');
    assert.equal(v.svgFill, mutual.svgFill);
    assert.equal(v.spokeStyle, known.spokeStyle);
    assert.equal(v.spokeStroke, known.spokeStroke);
    assert.equal(v.coreFill, null);
    assert.equal(v.lit, false);
    assert.equal(v.label, TRUST_VISUAL_LABELS['trust-received']);
    assert.equal(usesWhite(v), false);
    assert.equal(trustVisualLane(v, false), 'trust-received');
  });

  it('blocked is struck and not lit', () => {
    const v = trustPhaseVisual({
      status: status({ trust: 'mutual' }),
      blocked: true,
    });
    assert.equal(v.bondState, 'blocked');
    assert.equal(v.shape, 'struck');
    assert.equal(v.lit, false);
    assert.equal(v.label, TRUST_VISUAL_LABELS.blocked);
    assert.equal(v.coreFill, null);
  });

  it('known is outline, not filled or white', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'none' }) });
    assert.equal(v.bondState, 'known');
    assert.equal(v.shape, 'outline');
    assert.equal(v.lit, false);
    assert.equal(v.label, TRUST_VISUAL_LABELS.known);
    assert.equal(v.coreFill, null);
  });

  it('reads livingEdgeStatus.trust — outbound vs mutual from a real edge', () => {
    const base = {
      id: 'e',
      peer_fingerprint: 'aa'.repeat(20),
      peer_name: 'Pat',
      peer_email: '',
      peer_public_key: 'PK',
      trusted_since: null,
      last_interaction: new Date().toISOString(),
      decay_days: 730,
      trust_history: [],
      verification: { method: 'none' as const, verified_at: null },
      tags: [],
      notes: '',
      connection_channels: [],
      added_at: new Date().toISOString(),
      connection_status: 'accepted',
    };
    const outboundEdge = {
      ...base,
      trusted: true,
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
    } as TrustEdge;
    const mutualEdge = {
      ...base,
      peer_fingerprint: 'bb'.repeat(20),
      trusted: true,
      mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
    } as TrustEdge;
    const outVis = trustPhaseVisual({ status: livingEdgeStatus(outboundEdge) });
    const mutVis = trustPhaseVisual({ status: livingEdgeStatus(mutualEdge) });
    assert.equal(livingEdgeStatus(outboundEdge).trust, 'outbound');
    assert.equal(livingEdgeStatus(mutualEdge).trust, 'mutual');
    assert.equal(outVis.bondState, 'trust-sent');
    assert.equal(mutVis.bondState, 'mutual');
    assert.equal(outVis.white, false);
    assert.equal(mutVis.white, true);
    // Real edge→visual path: pre-wire the one-way bond labels "Trusted" (gated), never "Awaiting mutual".
    assert.equal(outVis.label, TRUST_SENT_PRE_WIRE_LABEL);
    assert.equal(mutVis.label, TRUST_VISUAL_LABELS.mutual);
  });

  it('a break with no remaining trust paints Known — no historical broken state', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'none' }) });
    assert.equal(v.bondState, 'known');
    assert.equal(v.label, TRUST_VISUAL_LABELS.known);
    assert.equal(v.shape, 'outline');
  });

  it('if they still hold after you drop trust, that is one-way inbound', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'inbound' }) });
    assert.equal(v.bondState, 'trust-received');
    assert.equal(v.label, TRUST_VISUAL_LABELS['trust-received']);
    assert.equal(v.shape, 'solid-filled');
  });

  it('trust_history does not invent a broken paint — live boolean only', () => {
    const afterBreak = {
      id: 'brk',
      peer_fingerprint: 'cc'.repeat(20),
      peer_name: 'Pat',
      peer_email: '',
      peer_public_key: 'PK',
      trusted: false,
      trusted_since: null,
      last_interaction: new Date().toISOString(),
      decay_days: 730,
      trust_history: [
        { timestamp: '2026-01-01T00:00:00.000Z', action: 'trust', reason: '', initiated_by: 'self' },
        { timestamp: '2026-02-01T00:00:00.000Z', action: 'break', reason: '', initiated_by: 'self' },
      ],
      verification: { method: 'none' as const, verified_at: null },
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
      tags: [],
      notes: '',
      connection_channels: [],
      added_at: new Date().toISOString(),
    } as TrustEdge;
    const v = visualForEdge(afterBreak);
    assert.equal(v.bondState, 'known');
    assert.equal(v.label, 'Known');
  });
});

describe('trust-phase visual map — consumers inherit the one map', () => {
  it('TrustMap, TrustMapGalaxy, MasterAddressBookList, ContactManagement import the map', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const root = join(dir, '..');
    const files = [
      readFileSync(join(root, 'TrustMap.tsx'), 'utf8'),
      readFileSync(join(root, 'TrustMapGalaxy.tsx'), 'utf8'),
      readFileSync(join(root, 'contacts/MasterAddressBookList.tsx'), 'utf8'),
      readFileSync(join(root, 'ContactManagement.tsx'), 'utf8'),
    ];
    for (const src of files) {
      assert.match(src, /trustPhaseVisual|visualForEdge/);
      assert.match(src, /from '@\/components\/trust\/trust-phase-visual'/);
    }
  });

  it('TrustMap SVG no longer paints white light from node.state === trusted', () => {
    const dir = dirname(fileURLToPath(import.meta.url));
    const map = readFileSync(join(dir, '..', 'TrustMap.tsx'), 'utf8');
    assert.doesNotMatch(
      map,
      /data-light=\{trusted \? 'white'/,
      'white light must follow visual.lit, not layout trusted',
    );
    assert.match(map, /data-bond-state=\{visual\.bondState\}/);
    assert.match(map, /data-light=\{visual\.lit \? 'white'/);
    assert.doesNotMatch(map, /halfFillVertical|half-filled|hex-half|hex-ring|outer-ring/);
    const galaxy = readFileSync(join(dir, '..', 'TrustMapGalaxy.tsx'), 'utf8');
    assert.doesNotMatch(galaxy, /half-filled|outer-ring/);
  });
});
