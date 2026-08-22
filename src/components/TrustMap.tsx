// src/components/TrustMap.tsx
// The crystalline trust-map — a flat, responsive SVG rendering of the viewer's
// trust lattice. Replaces the old <canvas> constellation, whose ABSOLUTE pixel
// radii pushed every node off-screen on a phone ("only the center shows"). This
// renders inside a fixed viewBox scaled to 100% width, so it fits any device.
//
// Design reference: docs/design/svrnty-crystalline-lattice-template.svg
// Tokens + the two constitutional rules (vivre spec §3):
//   (a) FACETS GROW, NEVER APPEAR — nodes/edges crystallize in ~1s on entry.
//   (b) I-6 RENDER PROVENANCE — every visual property decodes to something the
//       viewer AUTHORED or WITNESSED; nothing inferred; unlit = privacy, not absence.
// Positions/opacities/radii come from ./lib/trust/trust-map-layout (pure + tested).
// We render self + my real you→peer edges + real contact nodes. We deliberately do
// NOT render peer↔peer edges (clusters/bridges): that relation isn't in the data,
// so drawing it would be inference. Those arrive with owner-authored groups (tribes).

"use client";

import React, { useMemo, useState, useCallback } from 'react';
import type { TrustEdge } from '@/lib/trust/types';
import {
  computeTrustLayout,
  SELF_CORE_RADIUS,
  SELF_RING_RADIUS,
  type LaidOutNode,
  type TrustState,
} from '@/lib/trust/trust-map-layout';

interface TrustMapProps {
  ownerFingerprint: string;
  ownerName: string;
  contacts: TrustEdge[];
}

const VIEW = 400; // viewBox is VIEW×VIEW; the SVG scales it to the container width.

// Tokens lifted from the crystalline-lattice reference.
const T = {
  field: '#0A0E1A',
  myEdge: '#5DCAA5',   // teal — my direct (you→peer) edges
  dimFill: '#232A45',  // undisclosed / dim rim fill
  dimStroke: '#3A4468',
  lit: '#7DD8E8',      // cyan — a trusted, lit node
  selfRing: '#9FE8E0',
  selfDot: '#E8FBFF',
  label: '#9FB0D8',
  caption: '#6B7699',
} as const;

function nodeStroke(state: TrustState): string {
  if (state === 'trusted') return T.lit;
  if (state === 'decayed') return T.myEdge;
  return T.dimStroke;
}
function nodeFill(state: TrustState): string {
  return state === 'known' ? T.dimFill : T.field;
}

export function TrustMap({ ownerFingerprint, ownerName, contacts }: TrustMapProps) {
  const layout = useMemo(
    () => computeTrustLayout(ownerFingerprint, ownerName, contacts, { width: VIEW, height: VIEW }),
    [ownerFingerprint, ownerName, contacts],
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = layout.nodes.find((n) => n.id === selectedId) ?? null;

  const isEmpty = contacts.length === 0;
  const clearSel = useCallback(() => setSelectedId(null), []);

  return (
    <div
      data-testid="trust-map"
      style={{
        position: 'relative',
        width: '100%',
        maxWidth: 560,
        margin: '0 auto',
        aspectRatio: '1 / 1', // square container ⇄ square viewBox → nothing clipped
        borderRadius: 16,
        overflow: 'hidden',
        border: `1px solid rgba(159, 232, 224, 0.14)`,
        background: T.field,
      }}
    >
      {/* Crystallization + provenance styles. Facets grow; reduced-motion shows the
          final (already-correct) opacities immediately. */}
      <style>{`
        .tm-node { opacity: var(--tm-o, 1); transform-box: fill-box; transform-origin: center;
                   animation: tm-grow 1.05s cubic-bezier(.2,.8,.2,1) both; }
        .tm-edge, .tm-label { opacity: var(--tm-o, 1); animation: tm-fade 1.05s ease-out both; }
        .tm-self { animation: tm-fade .8s ease-out both; }
        @keyframes tm-grow { from { opacity: 0; transform: scale(.3); } to { opacity: var(--tm-o,1); transform: scale(1); } }
        @keyframes tm-fade { from { opacity: 0; } to { opacity: var(--tm-o,1); } }
        @media (prefers-reduced-motion: reduce) {
          .tm-node, .tm-edge, .tm-label, .tm-self { animation: none; }
          .tm-node { transform: none; }
        }
      `}</style>

      <svg
        data-testid="trust-map-svg"
        viewBox={`0 0 ${VIEW} ${VIEW}`}
        width="100%"
        height="100%"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label={`Trust map: ${contacts.length} connection${contacts.length === 1 ? '' : 's'}`}
        onClick={clearSel}
        style={{ display: 'block' }}
      >
        {/* ── edges: my real you→peer connections (teal). Nothing peer↔peer. ── */}
        <g>
          {layout.nodes.map((n, i) => (
            <line
              key={`e-${n.id}`}
              className="tm-edge"
              data-testid="trust-edge"
              x1={layout.self.x}
              y1={layout.self.y}
              x2={n.x}
              y2={n.y}
              stroke={T.myEdge}
              strokeWidth={n.state === 'trusted' ? 1.3 : 0.8}
              strokeDasharray={n.state === 'decayed' ? '3 3' : undefined}
              style={{ ['--tm-o' as string]: n.edgeOpacity, animationDelay: `${0.15 + i * 0.03}s` }}
            />
          ))}
        </g>

        {/* ── contact nodes: radius = salience, opacity = disclosure depth ── */}
        <g>
          {layout.nodes.map((n, i) => (
            <ContactNode
              key={n.id}
              node={n}
              index={i}
              selected={n.id === selectedId}
              onSelect={(id) => setSelectedId(id)}
            />
          ))}
        </g>

        {/* ── self: the viewer, at center — standing-ring + core + dot ── */}
        <g
          className="tm-self"
          data-testid="trust-map-self"
          style={{ ['--tm-o' as string]: 1 }}
        >
          <circle cx={layout.self.x} cy={layout.self.y} r={SELF_RING_RADIUS}
                  fill="none" stroke={T.selfRing} strokeWidth={0.8} opacity={0.4} />
          <circle cx={layout.self.x} cy={layout.self.y} r={SELF_CORE_RADIUS}
                  fill={T.field} stroke={T.selfRing} strokeWidth={1.6} />
          <circle cx={layout.self.x} cy={layout.self.y} r={5} fill={T.selfDot} />
          <text x={layout.self.x} y={layout.self.y + SELF_CORE_RADIUS + 15}
                textAnchor="middle" fontSize={12} fill={T.label}>You</text>
        </g>

        {/* ── labels ── */}
        <g>
          {layout.nodes.map((n, i) => (
            <text
              key={`l-${n.id}`}
              className="tm-label"
              x={n.x}
              y={n.y + n.radius + 11}
              textAnchor="middle"
              fontSize={9}
              fill={n.state === 'known' ? T.label : nodeStroke(n.state)}
              style={{ ['--tm-o' as string]: Math.max(n.opacity, 0.5), animationDelay: `${0.2 + i * 0.03}s`, pointerEvents: 'none' }}
            >
              {truncate(n.name)}
            </text>
          ))}
        </g>

        {/* ── ethics caption (steals the reference's user-facing copy) ── */}
        {!isEmpty && (
          <text x={VIEW / 2} y={VIEW - 10} textAnchor="middle" fontSize={8} fill={T.caption}>
            Every visible line is consented · none inferred
          </text>
        )}

        {/* ── empty-state (unlit = privacy, not absence) ── */}
        {isEmpty && (
          <g data-testid="trust-map-empty">
            <text x={VIEW / 2} y={VIEW / 2 + 58} textAnchor="middle" fontSize={13} fill={T.label}>
              Your lattice is dark
            </text>
            <text x={VIEW / 2} y={VIEW / 2 + 78} textAnchor="middle" fontSize={9} fill={T.caption}>
              Trusted connections crystallize here as you form them.
            </text>
            <text x={VIEW / 2} y={VIEW / 2 + 92} textAnchor="middle" fontSize={9} fill={T.caption}>
              Every line consented — none inferred.
            </text>
          </g>
        )}
      </svg>

      {/* ── selection detail (tap a node) ── */}
      {selected && (
        <div
          data-testid="trust-node-detail"
          onClick={clearSel}
          style={{
            position: 'absolute', left: 12, right: 12, bottom: 12,
            padding: '10px 12px', borderRadius: 10,
            background: 'rgba(10,14,26,0.92)', border: `1px solid ${T.dimStroke}`,
            color: T.label, fontSize: 12, fontFamily: 'system-ui, sans-serif',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8,
          }}
        >
          <span style={{ fontWeight: 600, color: nodeStroke(selected.state) }}>{selected.name}</span>
          <span style={{ color: T.caption }}>{describe(selected)}</span>
        </div>
      )}
    </div>
  );
}

function ContactNode({
  node, index, selected, onSelect,
}: {
  node: LaidOutNode;
  index: number;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <circle
      className="tm-node"
      data-testid="trust-node"
      data-fingerprint={node.id}
      data-trust-state={node.state}
      cx={node.x}
      cy={node.y}
      r={selected ? node.radius + 2 : node.radius}
      fill={nodeFill(node.state)}
      stroke={selected ? T.selfDot : nodeStroke(node.state)}
      strokeWidth={node.state === 'trusted' ? 1.3 : 0.9}
      strokeDasharray={node.state === 'decayed' ? '2 2' : undefined}
      style={{ ['--tm-o' as string]: node.opacity, animationDelay: `${index * 0.04}s`, cursor: 'pointer' }}
      onClick={(e) => { e.stopPropagation(); onSelect(node.id); }}
    >
      <title>{`${node.name} — ${describe(node)}`}</title>
    </circle>
  );
}

function describe(n: LaidOutNode): string {
  if (n.state === 'known') return 'known';
  if (n.state === 'decayed') return 'trust decayed';
  // trusted
  if (n.daysLeft > 365) return `trusted · ${Math.round(n.daysLeft / 365)}y until decay`;
  return `trusted · ${n.daysLeft}d until decay`;
}

function truncate(name: string, max = 14): string {
  return name.length > max ? name.slice(0, max - 1) + '…' : name;
}
