// src/components/TrustMap.tsx
// Egocentric particle-lattice: you at center, contacts in organic neighborhoods
// (owner-authored tags). Trust is a GLOW overlay on your bonds — not concentric
// rings. Camera viewBox handles pan/zoom (never CSS-scale a tiny SVG).
//
// Constitutional:
//   (a) FACETS GROW, NEVER APPEAR — nodes/edges crystallize on entry.
//   (b) I-6 RENDER PROVENANCE — authored or witnessed only; none inferred.
// Layout: src/lib/trust/trust-map-layout.ts (pure). Camera: graph-camera.ts.

"use client";

import React, { useMemo, useState, useCallback, useEffect } from 'react';
import { Maximize2, Minimize2, ZoomIn, ZoomOut, Users } from 'lucide-react';
import { useGraphViewport } from '@/lib/trust/use-graph-viewport';
import { boundsOf } from '@/lib/trust/graph-camera';
import type { TrustEdge } from '@/lib/trust/types';
import {
  computeTrustLayout,
  worldSizeForCount,
  type LaidOutNode,
  type TrustState,
} from '@/lib/trust/trust-map-layout';
import { constellationCaption, focusConstellation } from '@/lib/trust/constellation';
import { TrustMapLatticeField } from '@/components/TrustMapLatticeField';
import { TrustMapGalaxy } from '@/components/TrustMapGalaxy';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { IdentitySeal } from '@/components/identity/IdentitySeal';
import { ContactMethodLink } from '@/components/contacts/ContactMethodLink';
import {
  safeEmailLink,
  safePhoneLink,
  safeUrlLink,
  safeHandleLink,
} from '@/lib/contacts/safe-contact-link';
import { TrustActionConfirmDialog } from '@/components/trust-actions/TrustActionConfirmDialog';
import {
  applyTrustAction,
  isContactBlocked,
  type TrustActionKind,
  type TrustActionTarget,
} from '@/components/trust-actions/trust-actions';
import { MethodHistoryPanel } from '@/components/identity/MethodHistoryPanel';
import {
  loadMethodHistory,
  revisionsForPeer,
  type MethodRevision,
} from '@/components/identity/method-history';
import {
  CardAsSeenByDialog,
  type CardAsSeenAudience,
  type OwnerCardSnapshot,
} from '@/components/identity/CardAsSeenByDialog';
import {
  collectGroupTags,
  computeBrowseClusters,
} from '@/lib/trust/trust-map-browse-layout';
import { loadLocalMethods } from '@/components/identity/local-methods';

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
  /** Living methods on YOUR card — used for “as they see it” preview. */
  ownerCard?: OwnerCardSnapshot;
  contacts: TrustEdge[];
  /** Optional demo seed when the lattice is empty / refreshable */
  onLoadSample?: () => void | Promise<void>;
  /** Show refresh when book is demo-only */
  sampleRefreshable?: boolean;
  /** Assign a local group label (tag) to selected peers */
  onAssignGroup?: (fingerprints: string[], groupName: string) => void | Promise<void>;
  /** Rename a local group tag across members (owner-private). */
  onRenameGroup?: (from: string, to: string) => void | Promise<void>;
  /** Strip a local group tag from every contact that has it. */
  onDeleteGroup?: (tag: string) => void | Promise<void>;
  onTrustToggle?: (edge: TrustEdge) => void | Promise<void>;
  onRemoveContact?: (edge: TrustEdge) => void | Promise<void>;
  /** Local block / unblock — owner-only flag; relay stays blind (CUR-5). */
  onBlockContact?: (edge: TrustEdge, blocked: boolean) => void | Promise<void>;
  onAcceptIntro?: (edge: TrustEdge) => void | Promise<void>;
  onUpdateContact?: (
    edge: TrustEdge,
    patch: { name?: string; email?: string; notes?: string; phones?: string[] }
  ) => void | Promise<void>;
  /** CUR-1 — open revise/send flow for this peer as notify target */
  onSendMethodUpdate?: (edge: TrustEdge) => void;
  /** UI stub — introduce a third party (creates pending on both sides in prod) */
  onIntroduce?: (fromEdge: TrustEdge, introduceeName: string) => void | Promise<void>;
  /** CUR-2 — owner method-revision log (local). Parent may refresh after restore. */
  methodHistory?: MethodRevision[];
  onMethodHistoryChange?: () => void;
}


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


export function TrustMap({
  ownerFingerprint,
  ownerName,
  ownerCard,
  contacts,
  onLoadSample,
  sampleRefreshable,
  onAssignGroup,
  onRenameGroup,
  onDeleteGroup,
  onTrustToggle,
  onRemoveContact,
  onBlockContact,
  onAcceptIntro,
  onUpdateContact,
  onSendMethodUpdate,
  onIntroduce,
  methodHistory,
  onMethodHistoryChange,
}: TrustMapProps) {
  // Blocked contacts stay off the lattice (local owner filter — not a disclosure gate).

  const [viewMode, setViewMode] = useState<'orbit' | 'browse'>('orbit');
  const [selectMode, setSelectMode] = useState(false);
  const [groupFilter, setGroupFilter] = useState<string | null>(null);
  const [groupsOpen, setGroupsOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<string | null>(null);
  const [editGroupName, setEditGroupName] = useState('');
  const [fullscreen, setFullscreen] = useState(false);
  const { cam, reset: resetVp, zoomBy, applyFit, elRef: viewportElRef, handlers: vpHandlers } = useGraphViewport();
  const [selectionPanel, setSelectionPanel] = useState<'view' | 'edit' | 'options' | null>(null);
  const [cardAudience, setCardAudience] = useState<CardAsSeenAudience | null>(null);
  const [cardPreviewOpen, setCardPreviewOpen] = useState(false);

  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setFullscreen(false);
    };
    window.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [fullscreen]);

  const visibleContacts = useMemo(() => {
    return contacts.filter((c) => {
      if (isContactBlocked(c as EdgeExtras & { blocked?: boolean; metadata?: { blocked?: boolean } })) return false;
      if (!groupFilter) return true;
      return (c.tags || []).includes(groupFilter);
    });
  }, [contacts, groupFilter]);

  const world = useMemo(() => worldSizeForCount(visibleContacts.length), [visibleContacts.length]);
  const [searchQuery, setSearchQuery] = useState('');

  const allGroupTags = useMemo(() => collectGroupTags(contacts.filter((c) => !isContactBlocked(c as EdgeExtras & { blocked?: boolean; metadata?: { blocked?: boolean } }))), [contacts]);

  const browseClusters = useMemo(
    () => computeBrowseClusters(visibleContacts, world, world),
    [visibleContacts, world],
  );

  const ownerCardSnapshot = useMemo(() => {
    const local = loadLocalMethods(ownerFingerprint);
    return {
      name: ownerName,
      fingerprint: ownerFingerprint,
      email: ownerCard?.email,
      signal: ownerCard?.signal ?? local.signal,
      site: ownerCard?.site ?? local.site,
      handle: ownerCard?.handle,
    };
  }, [ownerFingerprint, ownerName, ownerCard]);

  const layout = useMemo(
    () =>
      computeTrustLayout(ownerFingerprint, ownerName, visibleContacts, {
        width: world,
        height: world,
      }),
    [ownerFingerprint, ownerName, visibleContacts, world],
  );

  useEffect(() => {
    const el = viewportElRef.current;
    const aspect = el ? el.clientWidth / Math.max(el.clientHeight, 1) : 1;
    if (viewMode === 'browse') {
      const pts = browseClusters.flatMap((c) => c.members);
      applyFit(boundsOf(pts.length ? pts : [{ x: world / 2, y: world / 2, radius: 24 }], 20), aspect);
    } else {
      applyFit(boundsOf([layout.self, ...layout.nodes], 28), aspect);
    }
  }, [layout, browseClusters, viewMode, fullscreen, applyFit, viewportElRef, world]);
  const edgeByFp = useMemo(() => {
    const m = new Map<string, EdgeExtras>();
    for (const c of visibleContacts) m.set(c.peer_fingerprint, c as EdgeExtras);
    return m;
  }, [visibleContacts]);

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
  const [confirmKind, setConfirmKind] = useState<TrustActionKind | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);


  const lamped = useMemo(
    () => (focusId ? focusConstellation(focusId, visibleContacts) : null),
    [focusId, visibleContacts],
  );
  const focusNode = layout.nodes.find((n) => n.id === focusId) ?? null;
  const focusEdge = useMemo(
    () => (focusId ? edgeByFp.get(focusId) ?? null : null),
    [edgeByFp, focusId]
  );

  const isEmpty = visibleContacts.length === 0;
  const showSampleBtn = !!onLoadSample && (isEmpty || !!sampleRefreshable);

  const clearFocus = useCallback(() => {
    setFocusId(null);
    setEditing(false);
    setShowIntro(false);
    setShowHistory(false);
    setActionNote(null);
    setConfirmKind(null);
  }, []);

  const confirmTarget: TrustActionTarget | null = focusEdge
    ? {
        id: focusEdge.id,
        fingerprint: focusEdge.peer_fingerprint,
        name: focusEdge.peer_name,
        trusted: !!focusEdge.trusted,
        blocked: isContactBlocked(focusEdge as EdgeExtras & { blocked?: boolean; metadata?: { blocked?: boolean } }),
      }
    : null;

  const runConfirmedAction = useCallback(
    async (kind: TrustActionKind, opts?: { reason?: string }) => {
      if (!focusEdge || !confirmTarget) return;
      setConfirmBusy(true);
      try {
        const result = await applyTrustAction(kind, confirmTarget, {
          applyLocal: async (patch) => {
            if (patch.kind === 'remove') {
              await onRemoveContact?.(focusEdge);
              return;
            }
            if (patch.kind === 'trust' || patch.kind === 'break') {
              // Parent toggles based on current edge; we only call when state matches.
              if (patch.kind === 'trust' && !focusEdge.trusted) await onTrustToggle?.(focusEdge);
              if (patch.kind === 'break' && focusEdge.trusted) await onTrustToggle?.(focusEdge);
              return;
            }
            if (patch.kind === 'block') {
              await onBlockContact?.(focusEdge, true);
              return;
            }
            if (patch.kind === 'unblock') {
              await onBlockContact?.(focusEdge, false);
            }
          },
        }, opts);

        setConfirmKind(null);
        if (!result.ok) {
          setActionNote(result.message);
          return;
        }
        setActionNote(result.message);
        if (kind === 'remove' || kind === 'block') {
          clearFocus();
        }
      } finally {
        setConfirmBusy(false);
      }
    },
    [focusEdge, confirmTarget, onRemoveContact, onTrustToggle, onBlockContact, clearFocus]
  );

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
    if (selectMode || multi) {
      setPicked((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
      if (!selectMode) openFocus(id);
      return;
    }
    openFocus(id);
  }, [openFocus, selectMode]);

  const openCardPreviewForPeer = useCallback((edge: TrustEdge) => {
    setCardAudience({
      kind: 'peer',
      name: edge.peer_name || 'Contact',
      fingerprint: edge.peer_fingerprint,
      trusted: !!edge.trusted,
    });
    setCardPreviewOpen(true);
  }, []);

  const openCardPreviewForSelection = useCallback(() => {
    if (picked.size === 0) return;
    if (picked.size === 1) {
      const fp = [...picked][0];
      const edge = edgeByFp.get(fp);
      if (edge) openCardPreviewForPeer(edge);
      return;
    }
    const members = [...picked].map((fp) => edgeByFp.get(fp)).filter(Boolean) as TrustEdge[];
    const trustedCount = members.filter((m) => m.trusted).length;
    setCardAudience({
      kind: 'group',
      name: groupFilter || groupName.trim() || 'Selection',
      memberCount: members.length,
      trustedCount,
      knownCount: members.length - trustedCount,
    });
    setCardPreviewOpen(true);
  }, [picked, edgeByFp, groupFilter, groupName, openCardPreviewForPeer]);

  const openCardPreviewForGroup = useCallback((tag: string) => {
    const members = contacts.filter((c) => {
      if (isContactBlocked(c as EdgeExtras & { blocked?: boolean; metadata?: { blocked?: boolean } })) return false;
      const tags = c.tags || [];
      if (tag === 'Ungrouped') return tags.length === 0;
      return tags.includes(tag);
    });
    const trustedCount = members.filter((m) => m.trusted).length;
    setCardAudience({
      kind: 'group',
      name: tag,
      memberCount: members.length,
      trustedCount,
      knownCount: members.length - trustedCount,
    });
    setCardPreviewOpen(true);
  }, [contacts]);

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
      setGroupsOpen(true);
    } catch {
      setGroupNote('Could not save group label.');
    } finally {
      setAssigning(false);
    }
  };

  const handleRenameGroup = async (from: string) => {
    const to = editGroupName.trim();
    if (!to || !onRenameGroup || to === from) return;
    try {
      await onRenameGroup(from, to);
      if (groupFilter === from) setGroupFilter(to);
      setEditingGroup(null);
      setEditGroupName('');
      setGroupNote(`Renamed “${from}” → “${to}” (local only).`);
    } catch {
      setGroupNote('Could not rename group.');
    }
  };

  const handleDeleteGroup = async (tag: string) => {
    if (!onDeleteGroup) return;
    if (!window.confirm(`Remove group “${tag}” from all contacts? Tags are local-only.`)) return;
    try {
      await onDeleteGroup(tag);
      if (groupFilter === tag) setGroupFilter(null);
      setEditingGroup(null);
      setGroupNote(`Removed group “${tag}”.`);
    } catch {
      setGroupNote('Could not remove group.');
    }
  };

  const selectGroupMembers = (tag: string) => {
    const fps = contacts
      .filter((c) => (c.tags || []).includes(tag))
      .map((c) => c.peer_fingerprint);
    setPicked(new Set(fps));
    setSelectMode(true);
    setGroupFilter(tag);
    setGroupsOpen(false);
    setSelectionPanel('options');
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

  const shellStyle: React.CSSProperties = fullscreen
    ? {
        position: 'fixed',
        inset: 0,
        zIndex: 80,
        width: '100%',
        maxWidth: 'none',
        margin: 0,
        padding: 12,
        boxSizing: 'border-box',
        background: E.bgCss,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
      }
    : { width: '100%', maxWidth: 560, margin: '0 auto' };

  return (
    <div style={shellStyle} data-testid="trust-map-shell" data-fullscreen={fullscreen ? '1' : '0'}>
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 8,
          alignItems: 'center',
          marginBottom: 10,
          fontFamily: E.fontSans,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            display: 'inline-flex',
            borderRadius: 8,
            border: `1px solid ${E.border}`,
            overflow: 'hidden',
          }}
        >
          {(['orbit', 'browse'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setViewMode(mode)}
              style={{
                fontSize: 11,
                padding: '6px 10px',
                border: 'none',
                cursor: 'pointer',
                fontFamily: E.fontSans,
                background:
                  viewMode === mode
                    ? 'color-mix(in srgb, var(--se-accent) 16%, transparent)'
                    : 'transparent',
                color: viewMode === mode ? E.accent : E.muted,
              }}
            >
              {mode === 'orbit' ? 'Lattice' : 'Browse'}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => {
            setSelectMode((v) => !v);
            if (selectMode) {
              setPicked(new Set());
              setSelectionPanel(null);
            } else {
              setSelectionPanel('options');
            }
          }}
          style={{
            fontSize: 11,
            padding: '6px 10px',
            borderRadius: 8,
            border: `1px solid ${E.border}`,
            cursor: 'pointer',
            fontFamily: E.fontSans,
            background: selectMode
              ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
              : 'transparent',
            color: E.accent,
          }}
        >
          {selectMode ? 'Done selecting' : 'Select'}
        </button>
        <button
          type="button"
          data-testid="trust-map-groups-btn"
          onClick={() => setGroupsOpen((v) => !v)}
          style={{
            fontSize: 11,
            padding: '6px 10px',
            borderRadius: 8,
            border: `1px solid ${groupsOpen || groupFilter ? E.borderLit : E.border}`,
            cursor: 'pointer',
            fontFamily: E.fontSans,
            background: groupsOpen
              ? 'color-mix(in srgb, var(--se-accent) 14%, transparent)'
              : 'transparent',
            color: E.accent,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          <Users className="h-3.5 w-3.5" />
          Groups{groupFilter ? ` · ${groupFilter}` : allGroupTags.length ? ` (${allGroupTags.length})` : ''}
        </button>
        <input
          data-testid="trust-map-search"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Find someone…"
          aria-label="Find someone in your lattice"
          style={{
            ...fieldStyle(),
            width: 140,
            padding: '6px 10px',
            fontSize: 11,
          }}
        />
        <div style={{ marginLeft: 'auto', display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <button type="button" aria-label="Zoom out" onClick={() => zoomBy(1 / 1.28)} style={iconBtnStyle()}>
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button type="button" aria-label="Zoom in" onClick={() => zoomBy(1.28)} style={iconBtnStyle()}>
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button type="button" aria-label="Fit network" onClick={resetVp} style={{ ...iconBtnStyle(), fontSize: 10, padding: '6px 8px' }}>
            Fit
          </button>
          <button
            type="button"
            data-testid="trust-map-fullscreen"
            aria-label={fullscreen ? 'Exit full screen' : 'Full screen'}
            onClick={() => {
              setFullscreen((v) => !v);
              resetVp();
            }}
            style={iconBtnStyle()}
          >
            {fullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

      {groupsOpen ? (
        <div
          data-testid="trust-map-groups-panel"
          style={{
            marginBottom: 10,
            padding: 12,
            borderRadius: 12,
            border: `1px solid ${E.border}`,
            background: E.surfaceSolid,
            fontFamily: E.fontSans,
            flexShrink: 0,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
            <p style={{ margin: 0, fontSize: 12, color: E.muted }}>
              Local groups · select · rename · remove · never published
            </p>
            <button
              type="button"
              onClick={() => {
                setGroupFilter(null);
                setGroupsOpen(false);
              }}
              style={{ ...iconBtnStyle(), fontSize: 11, padding: '4px 8px' }}
            >
              Close
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 8 }}>
            <button
              type="button"
              onClick={() => setGroupFilter(null)}
              style={{
                fontSize: 11,
                padding: '5px 10px',
                borderRadius: 8,
                border: `1px solid ${groupFilter === null ? E.borderLit : E.border}`,
                background: groupFilter === null ? 'color-mix(in srgb, var(--se-accent) 12%, transparent)' : 'transparent',
                color: E.muted,
                cursor: 'pointer',
                fontFamily: E.fontSans,
              }}
            >
              All contacts
            </button>
          </div>
          {allGroupTags.length === 0 ? (
            <p style={{ margin: 0, fontSize: 12, color: E.dim }}>
              No groups yet — Select seals, then Add to group.
            </p>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {allGroupTags.map((tag) => {
                const count = contacts.filter((c) => (c.tags || []).includes(tag)).length;
                const isEditing = editingGroup === tag;
                return (
                  <li
                    key={tag}
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: 8,
                      alignItems: 'center',
                      padding: '8px 10px',
                      borderRadius: 10,
                      border: `1px solid ${groupFilter === tag ? E.borderLit : E.border}`,
                      background:
                        groupFilter === tag
                          ? 'color-mix(in srgb, var(--se-accent) 10%, transparent)'
                          : 'transparent',
                    }}
                  >
                    {isEditing ? (
                      <>
                        <input
                          value={editGroupName}
                          onChange={(e) => setEditGroupName(e.target.value)}
                          style={{ ...fieldStyle(), flex: 1, minWidth: 120 }}
                          aria-label={`Rename ${tag}`}
                        />
                        <ActionBtn label="Save" primary onClick={() => void handleRenameGroup(tag)} />
                        <ActionBtn
                          label="Cancel"
                          onClick={() => {
                            setEditingGroup(null);
                            setEditGroupName('');
                          }}
                        />
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={() => setGroupFilter((cur) => (cur === tag ? null : tag))}
                          style={{
                            flex: 1,
                            textAlign: 'left',
                            background: 'none',
                            border: 'none',
                            color: E.text,
                            cursor: 'pointer',
                            fontFamily: E.fontSans,
                            fontSize: 13,
                            padding: 0,
                          }}
                        >
                          {tag}
                          <span style={{ color: E.dim, marginLeft: 8, fontSize: 11 }}>{count}</span>
                        </button>
                        <ActionBtn label="Select" onClick={() => selectGroupMembers(tag)} />
                        <ActionBtn
                          label="Edit"
                          onClick={() => {
                            setEditingGroup(tag);
                            setEditGroupName(tag);
                          }}
                        />
                        <ActionBtn label="Card" onClick={() => openCardPreviewForGroup(tag)} />
                        <ActionBtn label="Remove" danger onClick={() => void handleDeleteGroup(tag)} />
                      </>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      ) : null}


      <div
        ref={viewportElRef}
        data-testid="trust-map"
        style={{
          position: 'relative',
          width: '100%',
          flex: fullscreen ? 1 : undefined,
          aspectRatio: fullscreen ? undefined : '1 / 1',
          minHeight: fullscreen ? 0 : undefined,
          borderRadius: fullscreen ? 12 : 16,
          overflow: 'hidden',
          border: `1px solid ${E.borderLit}`,
          background: E.bgCss,
          touchAction: 'none',
        }}
        {...vpHandlers}
      >
        <TrustMapLatticeField />
        {viewMode === 'browse' ? (
          <div
            data-testid="trust-map-browse"
            style={{
              position: 'relative',
              width: '100%',
              height: '100%',
              minHeight: fullscreen ? '100%' : undefined,
              zIndex: 1,
            }}
          >
            <svg
              viewBox={`${cam.x} ${cam.y} ${cam.w} ${cam.h}`}
              width="100%"
              height="100%"
              preserveAspectRatio="none"
              role="img"
              aria-label="Browse clusters — owner groups with trust overlay"
            >
              <defs>
                <filter id="tm-soft" x="-40%" y="-40%" width="180%" height="180%">
                  <feGaussianBlur stdDeviation="1.4" />
                </filter>
              </defs>
              {browseClusters.map((cl) => {
                const hull = cl.hull.length >= 3
                  ? cl.hull.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ') + ' Z'
                  : null;
                return (
                <g key={cl.tag} data-graph-cluster={cl.tag}>
                  {hull ? (
                    <path
                      d={hull}
                      fill="color-mix(in srgb, var(--se-accent) 8%, transparent)"
                      stroke={E.border}
                      strokeWidth={1.1}
                      strokeDasharray={cl.tag === 'Ungrouped' ? '3 4' : undefined}
                      style={{ cursor: 'pointer' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        setGroupFilter(cl.tag === 'Ungrouped' ? null : cl.tag);
                        setGroupsOpen(false);
                      }}
                    >
                      <title>{`${cl.tag} · owner group · not inferred`}</title>
                    </path>
                  ) : (
                    <circle
                      cx={cl.cx}
                      cy={cl.cy}
                      r={cl.r}
                      fill="color-mix(in srgb, var(--se-accent) 7%, transparent)"
                      stroke={E.border}
                      strokeWidth={1}
                      onClick={(e) => {
                        e.stopPropagation();
                        setGroupFilter(cl.tag === 'Ungrouped' ? null : cl.tag);
                      }}
                    />
                  )}
                  <text
                    x={cl.cx}
                    y={cl.cy - cl.r - 6}
                    textAnchor="middle"
                    fill={E.muted}
                    fontSize={11}
                    fontFamily={E.fontSans}
                  >
                    {cl.tag}
                  </text>
                  {cl.members.map((m) => (
                    <g
                      key={m.id}
                      data-graph-node={m.id}
                      style={{ cursor: 'pointer' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleNodeClick(m.id, selectMode || e.shiftKey || e.metaKey || e.ctrlKey);
                        if (!selectMode) setSelectionPanel('view');
                      }}
                    >
                      {m.mutual ? (
                        <circle
                          cx={m.x}
                          cy={m.y}
                          r={picked.has(m.id) ? 15 : 12}
                          fill="none"
                          stroke={E.accent2}
                          strokeWidth={1.2}
                          strokeOpacity={0.5}
                          filter="url(#tm-soft)"
                        />
                      ) : null}
                      <circle
                        cx={m.x}
                        cy={m.y}
                        r={picked.has(m.id) ? 11 : 8}
                        fill={
                          m.trusted
                            ? 'color-mix(in srgb, var(--se-accent2) 38%, transparent)'
                            : 'transparent'
                        }
                        stroke={
                          picked.has(m.id) ? E.accent : m.trusted ? E.accent2 : E.border
                        }
                        strokeWidth={m.trusted || picked.has(m.id) ? 1.7 : 1.1}
                        strokeDasharray={m.trusted ? undefined : '2.5 2'}
                      />
                      <title>{`${m.name}${m.trusted ? ' · trusted' : ' · known'}${m.mutual ? ' · mutual' : ''}`}</title>
                    </g>
                  ))}
                </g>
                );
              })}
            </svg>
            <p
              style={{
                position: 'absolute',
                left: 10,
                right: 10,
                bottom: 8,
                margin: 0,
                fontSize: 10,
                color: E.dim,
                fontFamily: E.fontSans,
                textAlign: 'center',
                pointerEvents: 'none',
              }}
            >
              Neighborhoods you named · glow is trust · not a map
            </p>
          </div>

        ) : (
        <>
        <TrustMapGalaxy
          layout={layout}
          cam={cam}
          focusId={focusId}
          constellation={lamped}
          picked={picked}
          query={searchQuery}
          onNodeClick={handleNodeClick}
          onBackgroundClick={clearFocus}
        />
        {!isEmpty ? (
          <p
            data-testid="trust-map-legend"
            style={{
              position: 'absolute',
              left: 12,
              right: 12,
              bottom: 10,
              margin: 0,
              fontSize: 10,
              color: T.caption,
              fontFamily: E.fontSans,
              textAlign: 'center',
              pointerEvents: 'none',
              zIndex: 2,
            }}
          >
            {lamped && focusId
              ? `${constellationCaption(lamped, !!focusEdge?.trusted)}. Every visible line consented — none inferred.`
              : 'Your bonds · glow is trust · lamp a person to see their constellation. Every visible line consented — none inferred.'}
          </p>
        ) : (
          <div
            data-testid="trust-map-empty"
            style={{
              position: 'absolute',
              left: 16,
              right: 16,
              top: '58%',
              textAlign: 'center',
              pointerEvents: 'none',
              zIndex: 2,
              fontFamily: E.fontSans,
            }}
          >
            <p style={{ margin: 0, fontSize: 14, color: T.label }}>Your lattice is dark</p>
            <p style={{ margin: '8px 0 0', fontSize: 11, color: T.caption }}>
              Bonds crystallize here as you form them. Every line consented — none inferred.
            </p>
          </div>
        )}

        </>
        )}
        {showSampleBtn && (
          <div style={{ position: 'absolute', left: 0, right: 0, bottom: 28, zIndex: 4, display: 'flex', justifyContent: 'center', pointerEvents: 'none' }}>
            <button
              type="button"
              data-testid="trust-map-load-sample"
              onClick={() => {
                void (async () => {
                  try {
                    await onLoadSample?.();
                  } catch (err) {
                    setGroupNote(err instanceof Error ? err.message : 'Sample seed failed');
                  }
                })();
              }}
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
                pointerEvents: 'auto',
              }}
            >
              {isEmpty ? 'Load sample circle' : 'Refresh demo circle'}
            </button>
          </div>
        )}

        {(picked.size > 0 || focusId) && (
          <div
            data-testid="trust-map-selection-bar"
            style={{
              position: 'absolute',
              left: 10,
              right: 10,
              bottom: 12,
              zIndex: 5,
              display: 'flex',
              flexWrap: 'wrap',
              gap: 8,
              alignItems: 'center',
              padding: '10px 12px',
              borderRadius: 12,
              border: `1px solid ${E.borderLit}`,
              background: 'color-mix(in srgb, var(--se-surface-solid) 92%, transparent)',
              backdropFilter: 'blur(12px)',
              fontFamily: E.fontSans,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <span style={{ fontSize: 12, color: E.muted, marginRight: 4 }}>
              {picked.size > 0 ? `${picked.size} selected` : '1 focused'}
            </span>
            <ActionBtn
              label="View"
              primary={selectionPanel === 'view'}
              onClick={() => {
                setSelectionPanel('view');
                if (picked.size === 1) {
                  const id = [...picked][0];
                  handleNodeClick(id, false);
                }
              }}
            />
            <ActionBtn
              label="Edit"
              primary={selectionPanel === 'edit'}
              onClick={() => {
                setSelectionPanel('edit');
                if (focusId) setEditing(true);
                else if (picked.size === 1) {
                  const id = [...picked][0];
                  handleNodeClick(id, false);
                  setEditing(true);
                }
              }}
            />
            <ActionBtn
              label="Options"
              primary={selectionPanel === 'options'}
              onClick={() => setSelectionPanel('options')}
            />
            {selectionPanel === 'options' && picked.size > 0 ? (
              <>
                <input
                  type="text"
                  placeholder="Group label"
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  style={{ ...fieldStyle(), flex: 1, minWidth: 100 }}
                />
                <ActionBtn label={assigning ? 'Saving…' : 'Add to group'} primary onClick={() => void handleAssign()} />
                <ActionBtn label="Card preview" onClick={() => openCardPreviewForSelection()} />
                <ActionBtn label="Clear" onClick={clearPicks} />
              </>
            ) : null}
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
                      <ContactMethodLink
                        safe={safeEmailLink(focusEdge.peer_email)}
                        style={{ color: E.muted }}
                      />
                    </p>
                  )}
                  {focusEdge.contact_info?.phones?.[0] && (
                    <p style={{ margin: '4px 0 0', fontSize: 13, color: E.muted }}>
                      <ContactMethodLink
                        safe={safePhoneLink(focusEdge.contact_info.phones[0])}
                        style={{ color: E.muted }}
                      />
                    </p>
                  )}
                  {focusEdge.contact_info?.handles &&
                    Object.entries(focusEdge.contact_info.handles).map(([k, v]) => (
                      <p key={k} style={{ margin: '4px 0 0', fontSize: 12, color: E.muted }}>
                        {k} ·{' '}
                        <ContactMethodLink
                          safe={safeHandleLink(k, v)}
                          style={{ color: E.muted }}
                        />
                      </p>
                    ))}
                  {focusEdge.contact_info?.urls?.[0] && (
                    <p style={{ margin: '4px 0 0', fontSize: 12, color: E.accent }}>
                      <ContactMethodLink
                        safe={safeUrlLink(focusEdge.contact_info.urls[0])}
                        style={{ color: E.accent }}
                      />
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
                    setConfirmKind(focusEdge.trusted ? 'break' : 'trust')
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
              {onBlockContact && (
                <ActionBtn
                  label="Block"
                  danger
                  onClick={() => setConfirmKind('block')}
                />
              )}
              {onRemoveContact && (
                <ActionBtn
                  label="Remove"
                  danger
                  onClick={() => setConfirmKind('remove')}
                />
              )}
              <ActionBtn
                label={picked.has(focusEdge.peer_fingerprint) ? 'Selected' : 'Select'}
                onClick={() => togglePick(focusEdge.peer_fingerprint)}
              />
              <ActionBtn
                label="My card as they see it"
                onClick={() => openCardPreviewForPeer(focusEdge)}
              />
            </div>

            {showHistory && focusEdge && (
              <MethodHistoryPanel
                ownerFingerprint={ownerFingerprint}
                peerFingerprint={focusEdge.peer_fingerprint}
                revisions={revisionsForPeer(
                  methodHistory ?? loadMethodHistory(ownerFingerprint),
                  focusEdge.peer_fingerprint
                )}
                peerWireVersion={
                  typeof (focusEdge as { version?: number }).version === 'number'
                    ? (focusEdge as { version?: number }).version
                    : null
                }
                onHistoryChange={onMethodHistoryChange}
              />
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
                <ActionBtn
                  label="My card as they see it"
                  onClick={() => openCardPreviewForSelection()}
                />
                <ActionBtn label="Clear" onClick={clearPicks} />
              </div>
            )}
            {(groupNote || actionNote) && (
              <p style={{ margin: 0, fontSize: 11, color: E.ok }}>{groupNote || actionNote}</p>
            )}
            <p style={{ margin: 0, fontSize: 11, color: E.dim }}>
              {selectMode
                ? 'Select mode on — tap seals to multi-select · Add to group or preview your card'
                : 'Tip: wheel or pinch to zoom toward the cursor · Fit recenters · glow is the trust overlay'}
            </p>
          </div>
        </div>
      )}

      <CardAsSeenByDialog
        open={cardPreviewOpen}
        onClose={() => {
          setCardPreviewOpen(false);
          setCardAudience(null);
        }}
        owner={ownerCardSnapshot}
        audience={cardAudience}
      />

      <TrustActionConfirmDialog
        open={!!confirmKind && !!confirmTarget}
        kind={confirmKind}
        target={confirmTarget}
        busy={confirmBusy}
        onCancel={() => setConfirmKind(null)}
        onConfirm={(opts) => {
          if (!confirmKind) return;
          return runConfirmedAction(confirmKind, opts);
        }}
      />
    </div>
  );
}


function iconBtnStyle(): React.CSSProperties {
  return {
    fontSize: 11,
    padding: '6px 8px',
    borderRadius: 8,
    border: `1px solid ${E.border}`,
    background: 'transparent',
    color: E.muted,
    cursor: 'pointer',
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: E.fontSans,
  };
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
      data-graph-node={node.id}
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
