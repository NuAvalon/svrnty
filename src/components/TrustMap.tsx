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
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { IdentitySeal } from '@/components/identity/IdentitySeal';

interface TrustMapProps {
  ownerFingerprint: string;
  ownerName: string;
  contacts: TrustEdge[];
  /** Optional demo seed when the lattice is empty */
  onLoadSample?: () => void | Promise<void>;
  /** Assign a local group label (tag) to selected peers */
  onAssignGroup?: (fingerprints: string[], groupName: string) => void | Promise<void>;
}

const VIEW = 400; // viewBox is VIEW×VIEW; the SVG scales it to the container width.

// Solar Ember via CSS vars — follows light/dark appearance.
const T = {
  field: E.bg,
  myEdge: E.accent,
  dimFill: E.surfaceSolid,
  dimStroke: E.border,
  lit: E.accent2,
  selfRing: E.accent,
  selfDot: E.text,
  label: E.muted,
  caption: E.dim,
} as const;

function nodeStroke(state: TrustState): string {
  if (state === 'trusted') return T.lit;
  if (state === 'decayed') return T.myEdge;
  return T.dimStroke;
}
function nodeFill(state: TrustState): string {
  return state === 'known' ? T.dimFill : T.field;
}

function formatKeyGroups(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (!hex) return '····';
  const groups = hex.match(/.{1,4}/g) || [];
  return groups.slice(0, 6).join('·');
}

export function TrustMap({
  ownerFingerprint,
  ownerName,
  contacts,
  onLoadSample,
  onAssignGroup,
}: TrustMapProps) {
  const layout = useMemo(
    () => computeTrustLayout(ownerFingerprint, ownerName, contacts, { width: VIEW, height: VIEW }),
    [ownerFingerprint, ownerName, contacts],
  );
  const [focusId, setFocusId] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [groupName, setGroupName] = useState('');
  const [groupNote, setGroupNote] = useState<string | null>(null);
  const [assigning, setAssigning] = useState(false);

  const focusNode = layout.nodes.find((n) => n.id === focusId) ?? null;
  const focusEdge = useMemo(
    () => contacts.find((c) => c.peer_fingerprint === focusId) ?? null,
    [contacts, focusId]
  );

  const isEmpty = contacts.length === 0;

  const clearFocus = useCallback(() => setFocusId(null), []);

  const handleNodeClick = useCallback((id: string, multi: boolean) => {
    setFocusId(id);
    if (multi) {
      setPicked((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    }
  }, []);

  const togglePick = useCallback((id: string) => {
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const clearPicks = useCallback(() => {
    setPicked(new Set());
    setGroupNote(null);
  }, []);

  const handleAssign = async () => {
    const name = groupName.trim();
    if (!name || picked.size === 0 || !onAssignGroup) return;
    setAssigning(true);
    setGroupNote(null);
    try {
      await onAssignGroup([...picked], name);
      setGroupNote(`Added ${picked.size} to “${name}”.`);
      setGroupName('');
      setPicked(new Set());
    } catch {
      setGroupNote('Could not save group label.');
    } finally {
      setAssigning(false);
    }
  };

  return (
    <div style={{ width: '100%', maxWidth: 560, margin: '0 auto' }}>
      <div
        data-testid="trust-map"
        style={{
          position: 'relative',
          width: '100%',
          aspectRatio: '1 / 1',
          borderRadius: 16,
          overflow: 'hidden',
          border: `1px solid ${E.borderLit}`,
          background: E.bgCss,
        }}
      >
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
          onClick={clearFocus}
          style={{ display: 'block' }}
        >
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
                strokeOpacity={n.state === 'trusted' ? 0.55 : 0.28}
                strokeWidth={n.state === 'trusted' ? 1.2 : 0.8}
                strokeDasharray={n.state === 'decayed' ? '3 3' : undefined}
                style={{ ['--tm-o' as string]: n.edgeOpacity, animationDelay: `${0.15 + i * 0.03}s` }}
              />
            ))}
          </g>

          <g>
            {layout.nodes.map((n, i) => (
              <ContactNode
                key={n.id}
                node={n}
                index={i}
                selected={focusId === n.id}
                picked={picked.has(n.id)}
                onSelect={handleNodeClick}
              />
            ))}
          </g>

          <g className="tm-self" data-testid="trust-map-self" style={{ ['--tm-o' as string]: 1 }}>
            <circle
              cx={layout.self.x}
              cy={layout.self.y}
              r={SELF_RING_RADIUS}
              fill="none"
              stroke={T.selfRing}
              strokeWidth={0.8}
              opacity={0.4}
            />
            <circle
              cx={layout.self.x}
              cy={layout.self.y}
              r={SELF_CORE_RADIUS}
              fill={T.field}
              stroke={T.selfRing}
              strokeWidth={1.6}
            />
            <circle cx={layout.self.x} cy={layout.self.y} r={5} fill={T.selfDot} />
            <text
              x={layout.self.x}
              y={layout.self.y + SELF_CORE_RADIUS + 15}
              textAnchor="middle"
              fontSize={12}
              fill={T.label}
              style={{ fontFamily: E.fontSans }}
            >
              You
            </text>
          </g>

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
                style={{
                  fontFamily: E.fontSans,
                  ['--tm-o' as string]: Math.max(n.opacity, 0.5),
                  animationDelay: `${0.2 + i * 0.03}s`,
                  pointerEvents: 'none',
                }}
              >
                {truncate(n.name)}
              </text>
            ))}
          </g>

          {!isEmpty && (
            <text x={VIEW / 2} y={VIEW - 10} textAnchor="middle" fontSize={8} fill={T.caption}>
              Every visible line is consented · none inferred
            </text>
          )}

          {isEmpty && (
            <g data-testid="trust-map-empty">
              <text
                x={VIEW / 2}
                y={VIEW / 2 + 58}
                textAnchor="middle"
                fontSize={14}
                fill={T.label}
                style={{ fontFamily: E.fontSans }}
              >
                Your lattice is dark
              </text>
              <text
                x={VIEW / 2}
                y={VIEW / 2 + 78}
                textAnchor="middle"
                fontSize={10}
                fill={T.caption}
                style={{ fontFamily: E.fontSans }}
              >
                Trusted connections crystallize here as you form them.
              </text>
              <text
                x={VIEW / 2}
                y={VIEW / 2 + 94}
                textAnchor="middle"
                fontSize={10}
                fill={T.caption}
                style={{ fontFamily: E.fontSans }}
              >
                Every line consented — none inferred.
              </text>
            </g>
          )}
        </svg>

        {isEmpty && onLoadSample && (
          <div style={{ position: 'absolute', left: 0, right: 0, bottom: 28, display: 'flex', justifyContent: 'center' }}>
            <button
              type="button"
              onClick={() => void onLoadSample()}
              style={{
                fontFamily: E.fontSans,
                fontSize: 12,
                letterSpacing: '0.08em',
                color: T.myEdge,
                background: 'color-mix(in srgb, var(--se-accent) 12%, transparent)',
                border: `1px solid ${T.dimStroke}`,
                borderRadius: 8,
                padding: '8px 14px',
                cursor: 'pointer',
              }}
            >
              Load sample circle
            </button>
          </div>
        )}
      </div>

      {/* Contact sheet — seal + info + multi-select / group */}
      {focusNode && focusEdge && (
        <div
          data-testid="trust-node-detail"
          onClick={(e) => e.stopPropagation()}
          style={{
            marginTop: 14,
            padding: 16,
            borderRadius: 14,
            background: E.surfaceSolid,
            border: `1px solid ${E.borderLit}`,
            boxShadow: 'var(--se-glass-shadow)',
            fontFamily: E.fontSans,
          }}
        >
          <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
            {focusEdge.peer_fingerprint ? (
              <IdentitySeal fingerprint={focusEdge.peer_fingerprint} size={72} />
            ) : (
              <div
                style={{
                  width: 72,
                  height: 72,
                  borderRadius: 12,
                  border: `1px dashed ${E.border}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: E.dim,
                  fontSize: 10,
                  fontFamily: E.fontSans,
                  textAlign: 'center',
                  padding: 8,
                }}
              >
                no key yet
              </div>
            )}
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'flex-start' }}>
                <div>
                  <p style={{ margin: 0, fontSize: 16, fontWeight: 600, color: E.text }}>
                    {focusEdge.peer_name || focusNode.name}
                  </p>
                  <p style={{ margin: '4px 0 0', fontSize: 12, color: E.accent }}>
                    {describe(focusNode)}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={clearFocus}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: E.dim,
                    cursor: 'pointer',
                    fontSize: 12,
                    fontFamily: E.fontSans,
                  }}
                >
                  Close
                </button>
              </div>
              {focusEdge.peer_email && (
                <p style={{ margin: '10px 0 0', fontSize: 13, color: E.muted }}>
                  {focusEdge.peer_email}
                </p>
              )}
              {focusEdge.contact_info?.phones?.[0] && (
                <p style={{ margin: '4px 0 0', fontSize: 13, color: E.muted }}>
                  {focusEdge.contact_info.phones[0]}
                </p>
              )}
              <p
                style={{
                  margin: '8px 0 0',
                  fontSize: 11,
                  color: E.dim,
                  fontFamily: E.fontMono,
                  letterSpacing: '0.04em',
                  wordBreak: 'break-all',
                }}
              >
                key · {formatKeyGroups(focusEdge.peer_fingerprint)}
              </p>
              {focusEdge.tags?.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
                  {focusEdge.tags.map((t) => (
                    <span
                      key={t}
                      style={{
                        fontSize: 10,
                        letterSpacing: '0.06em',
                        padding: '3px 8px',
                        borderRadius: 999,
                        border: `1px solid ${E.border}`,
                        color: E.accent,
                        background: 'color-mix(in srgb, var(--se-accent) 8%, transparent)',
                      }}
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div
            style={{
              marginTop: 14,
              paddingTop: 12,
              borderTop: `1px solid ${E.border}`,
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
            }}
          >
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              <button
                type="button"
                onClick={() => togglePick(focusEdge.peer_fingerprint)}
                style={{
                  fontSize: 12,
                  fontFamily: E.fontSans,
                  padding: '7px 12px',
                  borderRadius: 8,
                  border: `1px solid ${E.borderLit}`,
                  background: picked.has(focusEdge.peer_fingerprint)
                    ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
                    : 'transparent',
                  color: E.accent,
                  cursor: 'pointer',
                }}
              >
                {picked.has(focusEdge.peer_fingerprint) ? 'Selected' : 'Select'}
              </button>
              <span style={{ fontSize: 11, color: E.dim }}>
                Tip: shift-click nodes on the map to multi-select
              </span>
            </div>

            {picked.size > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: E.muted }}>{picked.size} selected</span>
                <input
                  type="text"
                  placeholder="Group label"
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  style={{
                    flex: 1,
                    minWidth: 120,
                    background: E.inputBg,
                    border: `1px solid ${E.border}`,
                    borderRadius: 8,
                    padding: '8px 10px',
                    color: E.text,
                    fontFamily: E.fontSans,
                    fontSize: 13,
                  }}
                />
                <button
                  type="button"
                  disabled={!groupName.trim() || assigning || !onAssignGroup}
                  onClick={() => void handleAssign()}
                  style={{
                    fontSize: 12,
                    fontFamily: E.fontSans,
                    fontWeight: 500,
                    padding: '8px 12px',
                    borderRadius: 8,
                    border: `1px solid ${E.borderLit}`,
                    background: 'color-mix(in srgb, var(--se-accent) 14%, transparent)',
                    color: E.accent,
                    cursor: groupName.trim() && onAssignGroup ? 'pointer' : 'default',
                    opacity: !groupName.trim() || !onAssignGroup ? 0.5 : 1,
                  }}
                >
                  {assigning ? 'Saving…' : 'Add to group'}
                </button>
                <button
                  type="button"
                  onClick={clearPicks}
                  style={{
                    fontSize: 12,
                    fontFamily: E.fontSans,
                    background: 'none',
                    border: 'none',
                    color: E.dim,
                    cursor: 'pointer',
                  }}
                >
                  Clear
                </button>
              </div>
            )}
            {groupNote && (
              <p style={{ margin: 0, fontSize: 11, color: E.ok }}>{groupNote}</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ContactNode({
  node,
  index,
  selected,
  picked,
  onSelect,
}: {
  node: LaidOutNode;
  index: number;
  selected: boolean;
  picked: boolean;
  onSelect: (id: string, multi: boolean) => void;
}) {
  return (
    <circle
      className="tm-node"
      data-testid="trust-node"
      data-fingerprint={node.id}
      data-trust-state={node.state}
      cx={node.x}
      cy={node.y}
      r={selected || picked ? node.radius + 2.5 : node.radius}
      fill={nodeFill(node.state)}
      stroke={picked ? E.accent : selected ? T.selfDot : nodeStroke(node.state)}
      strokeWidth={picked || node.state === 'trusted' ? 1.5 : 0.9}
      strokeDasharray={node.state === 'decayed' ? '2 2' : undefined}
      style={{ ['--tm-o' as string]: node.opacity, animationDelay: `${index * 0.04}s`, cursor: 'pointer' }}
      onClick={(e) => {
        e.stopPropagation();
        onSelect(node.id, e.shiftKey || e.metaKey || e.ctrlKey);
      }}
    >
      <title>{`${node.name} — ${describe(node)}`}</title>
    </circle>
  );
}

function describe(n: LaidOutNode): string {
  if (n.state === 'known') return 'known';
  if (n.state === 'decayed') return 'trust decayed';
  if (n.daysLeft > 365) return `trusted · ${Math.round(n.daysLeft / 365)}y until decay`;
  return `trusted · ${n.daysLeft}d until decay`;
}

function truncate(name: string, max = 14): string {
  return name.length > max ? name.slice(0, max - 1) + '…' : name;
}
