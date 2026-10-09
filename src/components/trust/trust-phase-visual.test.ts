import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { livingEdgeStatus, type LivingEdgeStatus } from '../../lib/trust/living-edge-status';
import type { TrustEdge } from '../../lib/trust/types';
import {
  INTRO_PENDING_DASH,
  TRUST_SENT_DASH,
  TRUST_VISUAL_LABELS,
  TRUST_VISUAL_WHITE_CORE,
  TRUST_VISUAL_WHITE_HALO,
  TRUST_VISUAL_WHITE_SPOKE,
  trustPhaseVisual,
  trustVisualLane,
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

function whitesOf(v: TrustPhaseVisual): string[] {
  return [v.svgFill, v.svgStroke, v.canvasFill, v.canvasStroke, v.coreFill, v.haloStroke, v.spokeStroke]
    .filter((c): c is string => typeof c === 'string' && c.length > 0);
}

function usesWhite(v: TrustPhaseVisual): boolean {
  const blob = whitesOf(v).join(' ').toLowerCase();
  return (
    v.white ||
    v.lit ||
    v.coreFill === TRUST_VISUAL_WHITE_CORE ||
    blob.includes(TRUST_VISUAL_WHITE_CORE.toLowerCase()) ||
    blob.includes(TRUST_VISUAL_WHITE_HALO.toLowerCase()) ||
    blob.includes(TRUST_VISUAL_WHITE_SPOKE.toLowerCase()) ||
    blob.includes('#fff') ||
    blob.includes('255,255,255') ||
    blob.includes('251,234,210')
  );
}

describe('trust-phase visual map — white IFF mutual', () => {
  it('mutual is the only white/lit solid bond and labels Mutual', () => {
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

  it('outbound is dashed-hollow, muted, never white, labeled Awaiting mutual', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'outbound' }) });
    assert.equal(v.bondState, 'trust-sent');
    assert.equal(v.lit, false);
    assert.equal(v.white, false);
    assert.equal(v.shape, 'dashed-hollow');
    assert.equal(v.label, TRUST_VISUAL_LABELS['trust-sent']);
    assert.equal(v.coreFill, null);
    assert.equal(v.spokeGlow, false);
    assert.equal(v.svgFill, 'transparent');
    assert.equal(v.canvasFill, null);
    assert.equal(v.svgDasharray, TRUST_SENT_DASH);
    assert.equal(usesWhite(v), false);
  });

  it('pending vs mutual differ on shape AND color AND label', () => {
    const outbound = trustPhaseVisual({ status: status({ trust: 'outbound' }) });
    const mutual = trustPhaseVisual({ status: status({ trust: 'mutual' }) });
    assert.notEqual(outbound.shape, mutual.shape);
    assert.notEqual(outbound.svgStroke, mutual.svgStroke);
    assert.notEqual(outbound.label, mutual.label);
    assert.equal(outbound.shape, 'dashed-hollow');
    assert.equal(mutual.shape, 'solid-filled');
    assert.equal(outbound.label, 'Awaiting mutual');
    assert.equal(mutual.label, 'Mutual');
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
    assert.equal(sent.label, TRUST_VISUAL_LABELS['trust-sent']);
    assert.notEqual(intro.svgDasharray, sent.svgDasharray);
    assert.equal(intro.svgDasharray, INTRO_PENDING_DASH);
    assert.equal(trustVisualLane(intro, false), 'pending');
    assert.equal(trustVisualLane(sent, false), 'trust-sent');
  });

  it('inbound is actionable, not white, with the trust-back label', () => {
    const v = trustPhaseVisual({ status: status({ trust: 'inbound' }) });
    assert.equal(v.bondState, 'trust-received');
    assert.equal(v.shape, 'actionable');
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
  });
});
