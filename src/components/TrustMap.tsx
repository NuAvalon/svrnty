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
// We render self + my real you→peer edges + real contact nodes.
// Owner-authored group tags → soft cluster chords + centroid pull (NOT peer↔peer
// trust inference). Mutual reciprocal is witnessed on the edge. Pending intros
// are explicit metadata (introduction ≠ trust).

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

interface PendingIntro {
  introduced_by: string;
  introduced_by_fp: string;
  context: string;
}

type EdgeExtras = TrustEdge & {
  connection_status?: string;
  pending_intro?: PendingIntro;
};

interface TrustMapProps {
  ownerFingerprint: string;
  ownerName: string;
  contacts: TrustEdge[];
  /** Optional demo seed when the lattice is empty / refreshable */
  onLoadSample?: () => void | Promise<void>;
  /** Show refresh when book is demo-only */
  sampleRefreshable?: boolean;
  /** Assign a local group label (tag) to selected peers */
  onAssignGroup?: (fingerprints: string[], groupName: string) => void | Promise<void>;
  onTrustToggle?: (edge: TrustEdge) => void | Promise<void>;
  onRemoveContact?: (edge: TrustEdge) => void | Promise<void>;
  onAcceptIntro?: (edge: TrustEdge) => void | Promise<void>;
  onUpdateContact?: (
    edge: TrustEdge,
    patch: { name?: string; email?: string; notes?: string; phones?: string[] }
  ) => void | Promise<void>;
  /** CUR-1 — open revise/send flow for this peer as notify target */
  onSendMethodUpdate?: (edge: TrustEdge) => void;
  /** UI stub — introduce a third party (creates pending on both sides in prod) */
  onIntroduce?: (fromEdge: TrustEdge, introduceeName: string) => void | Promise<void>;
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
  pending: E.accent,
  cluster: E.muted,
} as const;

function isPending(edge: EdgeExtras | null | undefined): boolean {
  if (!edge) return false;
  return edge.connection_status === 'pending' || !!edge.pending_intro;
}

function nodeStroke(state: TrustState, pending: boolean): string {
  if (pending) return T.pending;
  if (state === 'trusted') return T.lit;
  if (state === 'decayed') return T.myEdge;
  return T.dimStroke;
}

function nodeFill(state: TrustState, pending: boolean): string {
  if (pending) return 'transparent';
  if (state === 'trusted') return 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))';
  if (state === 'known') return 'transparent';
  return T.dimFill;
}

function formatKeyGroups(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (!hex) return '····';
  const groups = hex.match(/.{1,4}/g) || [];
  return groups.slice(0, 6).join('·');
}

/** Soft pull same-tag nodes toward group centroids (owner-authored clusters). */
function clusterPull(
  nodes: LaidOutNode[],
  contacts: TrustEdge[],
  width: number,
  height: number,
): LaidOutNode[] {
  const byId = new Map(nodes.map((n) => [n.id, { ...n }]));
  const tagMembers = new Map<string, string[]>();
  for (const c of contacts) {
    const tags = c.tags || [];
    for (const t of tags) {
      if (!t) continue;
      const list = tagMembers.get(t) || [];
      list.push(c.peer_fingerprint);
      tagMembers.set(t, list);
    }
  }
  const margin = 18;
  for (const [, fps] of tagMembers) {
    if (fps.length < 2) continue;
    const members = fps.map((id) => byId.get(id)).filter(Boolean) as LaidOutNode[];
    if (members.length < 2) continue;
    const cx = members.reduce((s, m) => s + m.x, 0) / members.length;
    const cy = members.reduce((s, m) => s + m.y, 0) / members.length;
    for (const m of members) {
      const nx = m.x + (cx - m.x) * 0.42;
      const ny = m.y + (cy - m.y) * 0.42;
      m.x = Math.min(width - margin, Math.max(margin, nx));
      m.y = Math.min(height - margin - 8, Math.max(margin, ny));
      byId.set(m.id, m);
    }
  }
  return nodes.map((n) => byId.get(n.id) || n);
}

/** Owner-authored shared-tag chords (not inferred peer trust). */
function clusterChords(contacts: TrustEdge[]): { a: string; b: string; tag: string }[] {
  const chords: { a: string; b: string; tag: string }[] = [];
  const seen = new Set<string>();
  const byTag = new Map<string, string[]>();
  for (const c of contacts) {
    for (const t of c.tags || []) {
      if (!t) continue;
      const list = byTag.get(t) || [];
      list.push(c.peer_fingerprint);
      byTag.set(t, list);
    }
  }
  for (const [tag, fps] of byTag) {
    for (let i = 0; i < fps.length; i++) {
      for (let j = i + 1; j < fps.length; j++) {
        const a = fps[i];
        const b = fps[j];
        const key = [a, b].sort().join('|') + '|' + tag;
        if (seen.has(key)) continue;
        seen.add(key);
        chords.push({ a, b, tag });
      }
    }
  }
  return chords;
}

export function TrustMap({
  ownerFingerprint,
  ownerName,
  contacts,
  onLoadSample,
  sampleRefreshable,
  onAssignGroup,
  onTrustToggle,
  onRemoveContact,
  onAcceptIntro,
  onUpdateContact,
  onSendMethodUpdate,
  onIntroduce,
}: TrustMapProps) {
  const baseLayout = useMemo(
    () => computeTrustLayout(ownerFingerprint, ownerName, contacts, { width: VIEW, height: VIEW }),
    [ownerFingerprint, ownerName, contacts],
  );
  const layout = useMemo(
    () => ({
      ...baseLayout,
      nodes: clusterPull(baseLayout.nodes, contacts, VIEW, VIEW),
    }),
    [baseLayout, contacts],
  );
  const chords = useMemo(() => clusterChords(contacts), [contacts]);
  const edgeByFp = useMemo(() => {
    const m = new Map<string, EdgeExtras>();
    for (const c of contacts) m.set(c.peer_fingerprint, c as EdgeExtras);
    return m;
  }, [contacts]);

  const [focusId, setFocusId] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(() => new Set());
  const [groupName, setGroupName] = useState('');
  const [groupNote, setGroupNote] = useState<string | null>(null);
  const [assigning, setAssigning] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editEmail, setEditEmail] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [editPhone, setEditPhone] = useState('');
  const [actionNote, setActionNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [introName, setIntroName] = useState('');
  const [showIntro, setShowIntro] = useState(false);
  const [showHistory, setShowHistory] = useState(false);

  const focusNode = layout.nodes.find((n) => n.id === focusId) ?? null;
  const focusEdge = useMemo(
    () => (focusId ? edgeByFp.get(focusId) ?? null : null),
    [edgeByFp, focusId]
  );

  const isEmpty = contacts.length === 0;
  const showSampleBtn = !!onLoadSample && (isEmpty || !!sampleRefreshable);

  const clearFocus = useCallback(() => {
    setFocusId(null);
    setEditing(false);
    setShowIntro(false);
    setShowHistory(false);
    setActionNote(null);
  }, []);

  const openFocus = useCallback((id: string) => {
    setFocusId(id);
    const edge = edgeByFp.get(id);
    setEditName(edge?.peer_name || '');
    setEditEmail(edge?.peer_email || '');
    setEditNotes(edge?.notes || '');
    setEditPhone(edge?.contact_info?.phones?.[0] || '');
    setEditing(false);
    setShowIntro(false);
    setShowHistory(false);
    setActionNote(null);
    setIntroName('');
  }, [edgeByFp]);

  const handleNodeClick = useCallback((id: string, multi: boolean) => {
    openFocus(id);
    if (multi) {
      setPicked((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
    }
  }, [openFocus]);

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

  const runAction = async (fn: () => void | Promise<void>, okMsg: string) => {
    setBusy(true);
    setActionNote(null);
    try {
      await fn();
      setActionNote(okMsg);
    } catch {
      setActionNote('Something went wrong.');
    } finally {
      setBusy(false);
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
          .tm-edge, .tm-label, .tm-cluster { opacity: var(--tm-o, 1); animation: tm-fade 1.05s ease-out both; }
          .tm-self { animation: tm-fade .8s ease-out both; }
          .tm-pending { animation: tm-pulse 1.8s ease-in-out infinite; }
          @keyframes tm-grow { from { opacity: 0; transform: scale(.3); } to { opacity: var(--tm-o,1); transform: scale(1); } }
          @keyframes tm-fade { from { opacity: 0; } to { opacity: var(--tm-o,1); } }
          @keyframes tm-pulse { 0%, 100% { opacity: 0.45; } 50% { opacity: 0.95; } }
          @media (prefers-reduced-motion: reduce) {
            .tm-node, .tm-edge, .tm-label, .tm-self, .tm-cluster, .tm-pending { animation: none; }
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
          {/* Owner-authored group cluster chords */}
          <g>
            {chords.map((ch, i) => {
              const a = layout.nodes.find((n) => n.id === ch.a);
              const b = layout.nodes.find((n) => n.id === ch.b);
              if (!a || !b) return null;
              return (
                <line
                  key={`c-${ch.tag}-${ch.a}-${ch.b}`}
                  className="tm-cluster"
                  data-testid="trust-cluster-edge"
                  data-group={ch.tag}
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke={T.cluster}
                  strokeOpacity={0.28}
                  strokeWidth={0.9}
                  strokeDasharray="2 3"
                  style={{ ['--tm-o' as string]: 0.9, animationDelay: `${0.05 + i * 0.02}s` }}
                >
                  <title>{`Group · ${ch.tag}`}</title>
                </line>
              );
            })}
          </g>

          {/* Pending intro chords (introducer → introducee) — authored metadata */}
          <g>
            {contacts.map((c) => {
              const pe = c as EdgeExtras;
              const intro = pe.pending_intro;
              if (!intro?.introduced_by_fp) return null;
              const from = layout.nodes.find((n) => n.id === intro.introduced_by_fp);
              const to = layout.nodes.find((n) => n.id === c.peer_fingerprint);
              if (!from || !to) return null;
              return (
                <line
                  key={`intro-${c.peer_fingerprint}`}
                  className="tm-cluster tm-pending"
                  data-testid="trust-intro-edge"
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={T.pending}
                  strokeOpacity={0.55}
                  strokeWidth={1}
                  strokeDasharray="4 3"
                >
                  <title>{`Introduction · ${intro.introduced_by} → ${c.peer_name}`}</title>
                </line>
              );
            })}
          </g>

          <g>
            {layout.nodes.map((n, i) => {
              const edge = edgeByFp.get(n.id);
              const pending = isPending(edge);
              const mutual = !!edge?.mutual?.reciprocal;
              return (
                <g key={`e-${n.id}`}>
                  <line
                    className="tm-edge"
                    data-testid="trust-edge"
                    x1={layout.self.x}
                    y1={layout.self.y}
                    x2={n.x}
                    y2={n.y}
                    stroke={pending ? T.pending : T.myEdge}
                    strokeOpacity={
                      pending ? 0.4 : n.state === 'trusted' ? (mutual ? 0.75 : 0.55) : 0.22
                    }
                    strokeWidth={n.state === 'trusted' ? (mutual ? 2 : 1.4) : pending ? 1.1 : 0.7}
                    strokeDasharray={
                      pending ? '5 4' : n.state === 'decayed' ? '3 3' : n.state === 'known' ? '2 3' : undefined
                    }
                    style={{ ['--tm-o' as string]: n.edgeOpacity, animationDelay: `${0.15 + i * 0.03}s` }}
                  />
                  {mutual && n.state === 'trusted' && (
                    <line
                      className="tm-edge"
                      x1={layout.self.x}
                      y1={layout.self.y}
                      x2={n.x}
                      y2={n.y}
                      stroke={T.lit}
                      strokeOpacity={0.2}
                      strokeWidth={4}
                      style={{ ['--tm-o' as string]: 0.8, animationDelay: `${0.15 + i * 0.03}s` }}
                    />
                  )}
                </g>
              );
            })}
          </g>

          <g>
            {layout.nodes.map((n, i) => {
              const edge = edgeByFp.get(n.id);
              return (
                <ContactNode
                  key={n.id}
                  node={n}
                  index={i}
                  selected={focusId === n.id}
                  picked={picked.has(n.id)}
                  pending={isPending(edge)}
                  mutual={!!edge?.mutual?.reciprocal}
                  onSelect={handleNodeClick}
                />
              );
            })}
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
            {layout.nodes.map((n, i) => {
              const edge = edgeByFp.get(n.id);
              const pending = isPending(edge);
              return (
                <text
                  key={`l-${n.id}`}
                  className="tm-label"
                  x={n.x}
                  y={n.y + n.radius + 11}
                  textAnchor="middle"
                  fontSize={9}
                  fill={pending ? T.pending : n.state === 'known' ? T.caption : nodeStroke(n.state, false)}
                  style={{
                    fontFamily: E.fontSans,
                    ['--tm-o' as string]: Math.max(n.opacity, 0.5),
                    animationDelay: `${0.2 + i * 0.03}s`,
                    pointerEvents: 'none',
                    fontWeight: n.state === 'trusted' ? 600 : 400,
                  }}
                >
                  {truncate(n.name)}
                </text>
              );
            })}
          </g>

          {!isEmpty && (
            <g data-testid="trust-map-legend">
              <text x={VIEW / 2} y={VIEW - 21} textAnchor="middle" fontSize={8} fill={T.caption}>
                Groups you named · mutual glow · pending ≠ trust
              </text>
              <text x={VIEW / 2} y={VIEW - 10} textAnchor="middle" fontSize={8} fill={T.caption}>
                Every visible line consented — none inferred.
              </text>
            </g>
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

        {showSampleBtn && (
          <div style={{ position: 'absolute', left: 0, right: 0, bottom: 28, display: 'flex', justifyContent: 'center' }}>
            <button
              type="button"
              onClick={() => void onLoadSample?.()}
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
              {isEmpty ? 'Load sample circle' : 'Refresh demo circle'}
            </button>
          </div>
        )}
      </div>

      {/* Legend */}
      {!isEmpty && (
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 12,
            marginTop: 10,
            fontFamily: E.fontSans,
            fontSize: 10,
            color: E.dim,
            letterSpacing: '0.04em',
          }}
        >
          <span style={{ color: E.accent2 }}>● trusted</span>
          <span>○ known</span>
          <span style={{ color: E.accent }}>◌ pending intro</span>
          <span style={{ color: E.accent2 }}>═ mutual</span>
          <span>- - group</span>
        </div>
      )}

      {/* Contact sheet — alive contacts: seal + info + actions */}
      {focusNode && focusEdge && (
        <div
          data-testid="trust-node-detail"
          onClick={(e) => e.stopPropagation()}
          style={{
            marginTop: 14,
            padding: 16,
            borderRadius: 14,
            background: E.surfaceSolid,
            border: `1px solid ${
              isPending(focusEdge)
                ? E.borderLit
                : focusNode.state === 'trusted'
                  ? E.borderLit
                  : E.border
            }`,
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
                  <p
                    style={{
                      margin: '4px 0 0',
                      fontSize: 12,
                      color: isPending(focusEdge)
                        ? E.accent
                        : focusNode.state === 'trusted'
                          ? E.accent2
                          : E.dim,
                      fontWeight: focusNode.state === 'trusted' ? 600 : 400,
                    }}
                  >
                    {describeAlive(focusNode, focusEdge)}
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

              {!editing && (
                <>
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
                  {focusEdge.contact_info?.handles &&
                    Object.entries(focusEdge.contact_info.handles).map(([k, v]) => (
                      <p key={k} style={{ margin: '4px 0 0', fontSize: 12, color: E.muted }}>
                        {k} · {v}
                      </p>
                    ))}
                  {focusEdge.contact_info?.urls?.[0] && (
                    <p style={{ margin: '4px 0 0', fontSize: 12, color: E.accent }}>
                      {focusEdge.contact_info.urls[0]}
                    </p>
                  )}
                  {focusEdge.notes && (
                    <p style={{ margin: '8px 0 0', fontSize: 12, color: E.dim, fontStyle: 'italic' }}>
                      {focusEdge.notes}
                    </p>
                  )}
                  {isPending(focusEdge) && focusEdge.pending_intro && (
                    <p
                      style={{
                        margin: '10px 0 0',
                        fontSize: 12,
                        color: E.accent,
                        padding: '8px 10px',
                        borderRadius: 8,
                        border: `1px dashed ${E.borderLit}`,
                        background: 'color-mix(in srgb, var(--se-accent) 8%, transparent)',
                      }}
                    >
                      {focusEdge.pending_intro.context ||
                        `${focusEdge.pending_intro.introduced_by} introduced you`}
                      . Both sides stay pending until you accept — that is knowing, not trusting.
                    </p>
                  )}
                </>
              )}

              {editing && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
                  <input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    placeholder="Name"
                    style={fieldStyle()}
                  />
                  <input
                    value={editEmail}
                    onChange={(e) => setEditEmail(e.target.value)}
                    placeholder="Email"
                    style={fieldStyle()}
                  />
                  <input
                    value={editPhone}
                    onChange={(e) => setEditPhone(e.target.value)}
                    placeholder="Phone"
                    style={fieldStyle()}
                  />
                  <textarea
                    value={editNotes}
                    onChange={(e) => setEditNotes(e.target.value)}
                    placeholder="Private notes"
                    rows={2}
                    style={{ ...fieldStyle(), resize: 'vertical' as const }}
                  />
                </div>
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
                        borderRadius: 6,
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

          {/* Primary actions — alive contact card */}
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
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {isPending(focusEdge) && onAcceptIntro && (
                <ActionBtn
                  label={busy ? '…' : 'Accept connection'}
                  primary
                  onClick={() =>
                    void runAction(
                      () => onAcceptIntro(focusEdge),
                      'Connection accepted — they are known. Trust is still yours to grant.'
                    )
                  }
                />
              )}
              {!editing ? (
                <ActionBtn label="Edit" onClick={() => setEditing(true)} />
              ) : (
                <>
                  <ActionBtn
                    label={busy ? '…' : 'Save'}
                    primary
                    onClick={() =>
                      void runAction(async () => {
                        await onUpdateContact?.(focusEdge, {
                          name: editName.trim(),
                          email: editEmail.trim(),
                          notes: editNotes,
                          phones: editPhone.trim() ? [editPhone.trim()] : undefined,
                        });
                        setEditing(false);
                      }, 'Contact updated.')
                    }
                  />
                  <ActionBtn label="Cancel" onClick={() => setEditing(false)} />
                </>
              )}
              {!isPending(focusEdge) && onTrustToggle && (
                <ActionBtn
                  label={
                    busy
                      ? '…'
                      : focusEdge.trusted
                        ? 'Remove trust'
                        : 'TRUST'
                  }
                  primary={!focusEdge.trusted}
                  danger={!!focusEdge.trusted}
                  onClick={() =>
                    void runAction(
                      () => onTrustToggle(focusEdge),
                      focusEdge.trusted ? 'Trust removed — still known.' : 'Trusted.'
                    )
                  }
                />
              )}
              <ActionBtn
                label="Version history"
                onClick={() => {
                  setShowHistory((v) => !v);
                  setShowIntro(false);
                }}
              />
              <ActionBtn
                label="Introduce…"
                onClick={() => {
                  setShowIntro((v) => !v);
                  setShowHistory(false);
                }}
              />
              <ActionBtn
                label="Send update"
                onClick={() => {
                  if (onSendMethodUpdate) {
                    onSendMethodUpdate(focusEdge);
                    return;
                  }
                  setActionNote(
                    'Send updated contact method — open from Your Card → revise (CUR-1).'
                  );
                }}
              />
              {onRemoveContact && (
                <ActionBtn
                  label="Remove"
                  danger
                  onClick={() =>
                    void runAction(async () => {
                      await onRemoveContact(focusEdge);
                      clearFocus();
                    }, 'Removed.')
                  }
                />
              )}
              <ActionBtn
                label={picked.has(focusEdge.peer_fingerprint) ? 'Selected' : 'Select'}
                onClick={() => togglePick(focusEdge.peer_fingerprint)}
              />
            </div>

            {showHistory && (
              <div
                style={{
                  fontSize: 12,
                  color: E.muted,
                  padding: 10,
                  borderRadius: 8,
                  border: `1px solid ${E.border}`,
                  background: 'color-mix(in srgb, var(--se-accent) 5%, transparent)',
                }}
              >
                Version history is in progress (team). You’ll correct/retract method updates here —
                recipients see the corrected version. Not wired yet.
              </div>
            )}

            {showIntro && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                <input
                  type="text"
                  placeholder="Introduce whom? (name)"
                  value={introName}
                  onChange={(e) => setIntroName(e.target.value)}
                  style={{ ...fieldStyle(), flex: 1, minWidth: 140 }}
                />
                <ActionBtn
                  label={busy ? '…' : 'Send intro'}
                  primary
                  onClick={() => {
                    if (!introName.trim() || !onIntroduce) {
                      setActionNote(
                        onIntroduce
                          ? 'Enter a name.'
                          : 'Intro UI ready — wire protocol is team-owned (pending both sides).'
                      );
                      return;
                    }
                    void runAction(
                      () => onIntroduce(focusEdge, introName.trim()),
                      `Introduced ${introName.trim()} via ${focusEdge.peer_name}. Both sides stay pending until each accepts.`
                    );
                    setIntroName('');
                    setShowIntro(false);
                  }}
                />
              </div>
            )}

            {picked.size > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: E.muted }}>{picked.size} selected</span>
                <input
                  type="text"
                  placeholder="Group label"
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  style={{ ...fieldStyle(), flex: 1, minWidth: 120 }}
                />
                <ActionBtn
                  label={assigning ? 'Saving…' : 'Add to group'}
                  primary
                  onClick={() => void handleAssign()}
                />
                <ActionBtn label="Clear" onClick={clearPicks} />
              </div>
            )}
            {(groupNote || actionNote) && (
              <p style={{ margin: 0, fontSize: 11, color: E.ok }}>{groupNote || actionNote}</p>
            )}
            <p style={{ margin: 0, fontSize: 11, color: E.dim }}>
              Tip: shift-click nodes to multi-select · groups form clusters on the map
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

function fieldStyle(): React.CSSProperties {
  return {
    background: E.inputBg,
    border: `1px solid ${E.border}`,
    borderRadius: 8,
    padding: '8px 10px',
    color: E.text,
    fontFamily: E.fontSans,
    fontSize: 13,
    width: '100%',
    boxSizing: 'border-box',
  };
}

function ActionBtn({
  label,
  onClick,
  primary,
  danger,
}: {
  label: string;
  onClick: () => void;
  primary?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        fontSize: 12,
        fontFamily: E.fontSans,
        fontWeight: primary ? 600 : 400,
        padding: '7px 12px',
        borderRadius: 8,
        border: `1px solid ${danger ? E.danger : E.borderLit}`,
        background: primary
          ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
          : 'transparent',
        color: danger ? E.danger : E.accent,
        cursor: 'pointer',
        letterSpacing: primary ? '0.06em' : undefined,
      }}
    >
      {label}
    </button>
  );
}

function ContactNode({
  node,
  index,
  selected,
  picked,
  pending,
  mutual,
  onSelect,
}: {
  node: LaidOutNode;
  index: number;
  selected: boolean;
  picked: boolean;
  pending: boolean;
  mutual: boolean;
  onSelect: (id: string, multi: boolean) => void;
}) {
  const r = selected || picked ? node.radius + 2.5 : node.radius;
  const trusted = node.state === 'trusted' && !pending;
  return (
    <g
      className={`tm-node${pending ? ' tm-pending' : ''}`}
      style={{ ['--tm-o' as string]: node.opacity, animationDelay: `${index * 0.04}s`, cursor: 'pointer' }}
      onClick={(e) => {
        e.stopPropagation();
        onSelect(node.id, e.shiftKey || e.metaKey || e.ctrlKey);
      }}
    >
      {trusted && (
        <circle
          cx={node.x}
          cy={node.y}
          r={r + (mutual ? 5 : 3.5)}
          fill="none"
          stroke={T.lit}
          strokeOpacity={mutual ? 0.35 : 0.18}
          strokeWidth={mutual ? 1.4 : 1}
          style={{ pointerEvents: 'none' }}
        />
      )}
      <circle
        data-testid="trust-node"
        data-fingerprint={node.id}
        data-trust-state={pending ? 'pending' : node.state}
        data-mutual={mutual ? 'true' : 'false'}
        cx={node.x}
        cy={node.y}
        r={r}
        fill={nodeFill(node.state, pending)}
        stroke={picked ? E.accent : selected ? T.selfDot : nodeStroke(node.state, pending)}
        strokeWidth={picked || trusted ? 1.8 : pending ? 1.4 : 0.9}
        strokeDasharray={pending ? '3 2' : node.state === 'decayed' || node.state === 'known' ? '2 2' : undefined}
      >
        <title>{`${node.name} — ${pending ? 'pending intro' : describe(node)}${mutual ? ' · mutual' : ''}`}</title>
      </circle>
    </g>
  );
}

function describe(n: LaidOutNode): string {
  if (n.state === 'known') return 'known';
  if (n.state === 'decayed') return 'trust decayed';
  if (n.daysLeft > 365) return `trusted · ${Math.round(n.daysLeft / 365)}y until decay`;
  return `trusted · ${n.daysLeft}d until decay`;
}

function describeAlive(n: LaidOutNode, edge: EdgeExtras): string {
  if (isPending(edge)) return 'pending connection · not yet known';
  if (n.state === 'known') return 'known · not trusted';
  if (n.state === 'decayed') return 'trust decayed';
  const mutual = edge.mutual?.reciprocal ? ' · mutual' : '';
  if (n.daysLeft > 365) return `trusted${mutual} · ${Math.round(n.daysLeft / 365)}y until decay`;
  return `trusted${mutual} · ${n.daysLeft}d until decay`;
}

function truncate(name: string, max = 14): string {
  return name.length > max ? name.slice(0, max - 1) + '…' : name;
}
