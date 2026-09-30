// src/components/TrustMap.tsx
// Egocentric particle-lattice: you at center, contacts in organic neighborhoods
// (owner-authored tags). Trust is a GLOW overlay — not concentric rings.
// Camera viewBox handles pan / wheel / pinch zoom (never CSS-scale a tiny SVG).
//
// Constitutional:
//   (a) FACETS GROW, NEVER APPEAR — nodes/edges crystallize on entry.
//   (b) I-6 RENDER PROVENANCE — authored or witnessed only; none inferred.
//   Peer filaments: open-visibility Know (disclosed_circle) and Trust (they_trust), never tags.
// Layout: trust-map-layout.ts (pure). Camera: graph-camera.ts.

"use client";

import React, { useMemo, useState, useCallback, useEffect, useRef } from 'react';
import { ChevronDown, Maximize2, Minimize2, ZoomIn, ZoomOut, RotateCw } from 'lucide-react';
import { useGraphViewport } from '@/lib/trust/use-graph-viewport';
import { boundsOf, hitTestNodes } from '@/lib/trust/graph-camera';
import type { TrustEdge } from '@/lib/trust/types';
import {
  computeTrustLayout,
  hexagonPoints,
  worldSizeForCount,
  SELF_CORE_RADIUS,
  SELF_RING_RADIUS,
  trustStateOf,
  type LaidOutNode,
  type TrustState,
} from '@/lib/trust/trust-map-layout';
import { witnessedPeerChords } from '@/lib/trust/peer-trust-chords';
import { latticeChords, relaxGraphNodes, tagMembership } from '@/lib/trust/graph-forces';
import { GalaxyGateMembrane } from '@/components/GalaxyGateMembrane';
import { GrowGatePanel } from '@/components/GrowGatePanel';
import { loadGateArrivals } from '@/lib/identity/client-store';
import { subscribeContactChanges } from '@/lib/contacts/contact-events';
import {
  applyLayoutMemory,
  glassStateSignature,
  loadLayoutMemory,
  mutualTopologySignature,
  saveLayoutMemory,
} from '@/lib/trust/layout-memory';
import { selectLabels, shortDisplayName, type LabelCandidate } from '@/lib/trust/label-lod';
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
  ownerHasVerified,
  formatFingerprintForVerify,
  TRUST_RECIPE_COPY,
} from '@/lib/trust/trust-recipe';
import { ownerLocalBadge } from '@/lib/trust/grow-gate';
import {
  loadMethodHistory,
  revisionsForPeer,
  type MethodRevision,
} from '@/components/identity/method-history';
import { VerifySheet } from '@/components/verify/VerifySheet';
import { VERIFY_SHEET_COPY } from '@/components/verify/verify-copy';

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
  /** Empty galaxy CTA — opens Grow (share / in-person). */
  onGrow?: () => void;
  /** Assign a local group label (tag) to selected peers */
  onAssignGroup?: (fingerprints: string[], groupName: string) => void | Promise<void>;
  onTrustToggle?: (edge: TrustEdge) => void | Promise<void>;
  onRemoveContact?: (edge: TrustEdge) => void | Promise<void>;
  /** Local block / unblock — owner-only flag; relay stays blind (CUR-5). */
  onBlockContact?: (edge: TrustEdge, blocked: boolean) => void | Promise<void>;
  onAcceptIntro?: (edge: TrustEdge) => void | Promise<void>;
  onUpdateContact?: (
    edge: TrustEdge,
    patch: { name?: string; email?: string; notes?: string; phones?: string[] }
  ) => void | Promise<void>;
  /** Owner-local verify (trust prereq). Private — not a badge. */
  onOwnerVerify?: (edge: TrustEdge, method: 'in_person' | 'other_channel') => void | Promise<void>;
  /** CUR-1 — open revise/send flow for this peer as notify target */
  onSendMethodUpdate?: (edge: TrustEdge) => void;
  /** CUR-2 — owner method-revision log (local). Parent may refresh after restore. */
  methodHistory?: MethodRevision[];
  onMethodHistoryChange?: () => void;
  /** Pull / tap to consume mailbox + re-read the local book. Fail-soft. */
  onRefresh?: () => void | Promise<void>;
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

/** Known stars rise from the Gate membrane once per session, then settle. */
const IGNITE_MS = 1100;
const GLASS_POP_MS = 900;
const GATE_SPARK_MS = 1600;

type GlassLane = 'pending' | 'known' | 'verified' | 'trusted' | 'decayed';

function glassLane(state: TrustState, verified: boolean, pending: boolean): GlassLane {
  if (pending) return 'pending';
  if (state === 'trusted') return 'trusted';
  if (state === 'decayed') return 'decayed';
  if (verified) return 'verified';
  return 'known';
}
const IGNITE_STORE = 'svrnty.galaxy.ignited.v1';

function loadIgnited(owner: string): Set<string> {
  if (typeof sessionStorage === 'undefined' || !owner) return new Set();
  try {
    const raw = sessionStorage.getItem(`${IGNITE_STORE}:${owner}`);
    const arr = JSON.parse(raw || '[]');
    return new Set(Array.isArray(arr) ? arr.filter((x) => typeof x === 'string') : []);
  } catch {
    return new Set();
  }
}

function saveIgnited(owner: string, ids: Set<string>) {
  if (typeof sessionStorage === 'undefined' || !owner) return;
  try {
    sessionStorage.setItem(`${IGNITE_STORE}:${owner}`, JSON.stringify([...ids]));
  } catch {
    /* quota */
  }
}

function forgetIgnited(owner: string, fp: string) {
  const s = loadIgnited(owner);
  if (!s.delete(fp)) return;
  saveIgnited(owner, s);
}

function isPending(edge: EdgeExtras | null | undefined): boolean {
  if (!edge) return false;
  return edge.connection_status === 'pending' || !!edge.pending_intro;
}

function nodeStroke(state: TrustState, pending: boolean): string {
  if (pending) return T.pending;
  if (state === 'trusted') return T.lit;
  return T.myEdge;
}

function nodeFill(state: TrustState, pending: boolean): string {
  if (pending) return 'transparent';
  if (state === 'trusted') return 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))';
  if (state === 'known') return 'color-mix(in srgb, var(--se-accent) 7%, transparent)';
  return T.dimFill;
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

export function TrustMap({
  ownerFingerprint,
  ownerName,
  contacts,
  onGrow,
  onAssignGroup,
  onTrustToggle,
  onRemoveContact,
  onBlockContact,
  onAcceptIntro,
  onUpdateContact,
  onOwnerVerify,
  onSendMethodUpdate,
  methodHistory,
  onMethodHistoryChange,
  onRefresh,
}: TrustMapProps) {
  const [fullscreen, setFullscreen] = useState(false);
  const {
    cam,
    reset: resetVp,
    zoomBy,
    applyFit,
    elRef: viewportElRef,
    didPan,
    handlers: vpHandlers,
  } = useGraphViewport();
  const fittedOnce = useRef(false);
  const [vpSize, setVpSize] = useState({ w: 400, h: 400 });
  const [pullDy, setPullDy] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshNote, setRefreshNote] = useState<string | null>(null);
  const pullRef = useRef<{ y: number; x: number; armed: boolean; pulling: boolean } | null>(null);
  const [crystallizeNote, setCrystallizeNote] = useState<string | null>(null);
  const prevMutualRef = useRef<Set<string>>(new Set());
  const [gateCount, setGateCount] = useState(0);
  const [gateSparks, setGateSparks] = useState<string[]>([]);
  const [gateOpen, setGateOpen] = useState(false);
  const [igniteIds, setIgniteIds] = useState<Set<string>>(() => new Set());
  const [glassPop, setGlassPop] = useState<Set<string>>(() => new Set());
  const gateIdsRef = useRef<Set<string>>(new Set());
  const gateBootedRef = useRef(false);
  const prevGlassRef = useRef<Map<string, GlassLane>>(new Map());

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

  // Blocked contacts stay off the lattice (local owner filter — not a disclosure gate).
  const visibleContacts = useMemo(
    () => contacts.filter((c) => !isContactBlocked(c as EdgeExtras & { blocked?: boolean; metadata?: { blocked?: boolean } })),
    [contacts],
  );
  const starKey = visibleContacts.map((c) => c.peer_fingerprint).join('\n');

  useEffect(() => {
    if (!ownerFingerprint) return;
    let cancelled = false;
    const refresh = async () => {
      try {
        const list = await loadGateArrivals(ownerFingerprint);
        if (cancelled) return;
        const ids = list.map((a) => a.fingerprint).filter(Boolean);
        const prev = gateIdsRef.current;
        const incoming = gateBootedRef.current
          ? ids.filter((id) => !prev.has(id))
          : [];
        gateBootedRef.current = true;
        gateIdsRef.current = new Set(ids);
        setGateCount(list.length);
        if (incoming.length > 0) {
          setGateSparks(incoming);
          window.setTimeout(() => {
            setGateSparks((cur) => cur.filter((id) => !incoming.includes(id)));
          }, GATE_SPARK_MS);
        }
      } catch {
        /* non-fatal */
      }
    };
    void refresh();
    const unsub = subscribeContactChanges(() => {
      void refresh();
    });
    // Cheap local read so a joiner isn't waiting on the next mailbox tick alone.
    const poll = window.setInterval(() => void refresh(), 1_000);
    return () => {
      cancelled = true;
      unsub();
      window.clearInterval(poll);
    };
  }, [ownerFingerprint]);

  useEffect(() => {
    if (!ownerFingerprint) return;
    const known = loadIgnited(ownerFingerprint);
    const current = visibleContacts
      .filter((c) => !isPending(c as EdgeExtras))
      .map((c) => c.peer_fingerprint)
      .filter(Boolean);
    const fresh = current.filter((id) => !known.has(id));
    if (fresh.length === 0) return;
    setIgniteIds((prev) => {
      const next = new Set(prev);
      for (const id of fresh) next.add(id);
      return next;
    });
    const t = window.setTimeout(() => {
      const settled = loadIgnited(ownerFingerprint);
      for (const id of current) settled.add(id);
      saveIgnited(ownerFingerprint, settled);
      setIgniteIds(new Set());
    }, IGNITE_MS);
    return () => window.clearTimeout(t);
  }, [ownerFingerprint, starKey]);

  useEffect(() => {
    if (!gateOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setGateOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [gateOpen]);

  const world = useMemo(() => worldSizeForCount(visibleContacts.length), [visibleContacts.length]);

  const layout = useMemo(() => {
    const raw = computeTrustLayout(ownerFingerprint, ownerName, visibleContacts, {
      width: world,
      height: world,
    });
    const mutualBonds = witnessedPeerChords(visibleContacts).map((c) => ({
      a: c.a,
      b: c.b,
    }));
    const topo = mutualTopologySignature(mutualBonds);
    const glass = glassStateSignature(
      visibleContacts.map((c) => ({
        id: c.peer_fingerprint,
        state: trustStateOf(c),
        verified: ownerHasVerified(c),
      })),
    );
    const {
      nodes: memory,
      topology: rememberedTopo,
      glass: rememberedGlass,
    } = loadLayoutMemory(ownerFingerprint);
    const topologyChanged = topo !== rememberedTopo;
    const stateChanged = glass !== rememberedGlass;
    const blended = applyLayoutMemory(raw.nodes, memory, 0.55, topologyChanged, stateChanged);
    const n = blended.length;
    const density = Math.sqrt(Math.max(n, 1));
    const rearrange = topologyChanged || stateChanged;
    const nodes = relaxGraphNodes(blended, {
      width: raw.width,
      height: raw.height,
      cx: raw.cx,
      cy: raw.cy,
      tagMembers: tagMembership(visibleContacts),
      mutualBonds,
      mutualBondGravity: rearrange ? 0.26 : 0.14,
      mutualBondRest: 64,
      padding: Math.min(40, Math.round(18 + density * 1.8)),
      selfClearance: SELF_RING_RADIUS + 20,
      iterations: rearrange
        ? Math.min(72, 28 + Math.floor(n / 3))
        : Math.min(36, 16 + Math.floor(n / 5)),
      clusterGravity: rearrange ? 0.18 : 0.12,
      centerGravity: rearrange ? 0.008 : 0.003,
      cloudMin: SELF_RING_RADIUS + 40,
      cloudMax: Math.min(raw.cx, raw.cy) * 0.94,
      repulsion: Math.min(1.25, (rearrange ? 0.88 : 0.75) + density * 0.035),
      margin: 22,
    });
    return { ...raw, nodes, topology: topo, glass };
  }, [ownerFingerprint, ownerName, visibleContacts, world]);

  useEffect(() => {
    if (!ownerFingerprint || layout.nodes.length === 0) return;
    const t = window.setTimeout(() => {
      saveLayoutMemory(
        ownerFingerprint,
        layout.nodes.map((n) => ({ id: n.id, x: n.x, y: n.y })),
        layout.topology,
        layout.glass,
      );
    }, 400);
    return () => window.clearTimeout(t);
  }, [ownerFingerprint, layout.nodes, layout.topology, layout.glass]);

  useEffect(() => {
    fittedOnce.current = false;
  }, [fullscreen]);

  useEffect(() => {
    const el = viewportElRef.current;
    const aspect = el ? el.clientWidth / Math.max(el.clientHeight, 1) : 1;
    applyFit(boundsOf([layout.self, ...layout.nodes], 48), aspect, fittedOnce.current ? 'limits' : 'reset');
    fittedOnce.current = true;
  }, [layout, fullscreen, applyFit, viewportElRef, world]);

  useEffect(() => {
    const el = viewportElRef.current;
    if (!el) return;
    const sync = () => setVpSize({ w: el.clientWidth, h: el.clientHeight });
    sync();
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    return () => ro.disconnect();
  }, [viewportElRef, fullscreen]);

  const posById = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    for (const n of layout.nodes) m.set(n.id, n);
    return m;
  }, [layout.nodes]);

  const chords = useMemo(
    () => latticeChords(visibleContacts, posById, 2),
    [visibleContacts, posById],
  );
  const peerChords = useMemo(
    () => witnessedPeerChords(visibleContacts),
    [visibleContacts],
  );
  const edgeByFp = useMemo(() => {
    const m = new Map<string, EdgeExtras>();
    for (const c of visibleContacts) m.set(c.peer_fingerprint, c as EdgeExtras);
    return m;
  }, [visibleContacts]);

  useEffect(() => {
    const rank: Record<GlassLane, number> = {
      pending: 0,
      known: 1,
      verified: 2,
      trusted: 3,
      decayed: 1,
    };
    const next = new Map<string, GlassLane>();
    const popped = new Set<string>();
    for (const n of layout.nodes) {
      const edge = edgeByFp.get(n.id);
      const lane = glassLane(n.state, !!edge && ownerHasVerified(edge), isPending(edge));
      next.set(n.id, lane);
      const prev = prevGlassRef.current.get(n.id);
      if (prev && rank[lane] > rank[prev]) popped.add(n.id);
    }
    prevGlassRef.current = next;
    if (popped.size === 0) return;
    setGlassPop(popped);
    const t = window.setTimeout(() => setGlassPop(new Set()), GLASS_POP_MS);
    return () => window.clearTimeout(t);
  }, [layout.nodes, edgeByFp]);

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
  const [actionsOpen, setActionsOpen] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [confirmKind, setConfirmKind] = useState<TrustActionKind | null>(null);
  const [confirmBusy, setConfirmBusy] = useState(false);
  const [verifyOpen, setVerifyOpen] = useState(false);

  const focusNode = layout.nodes.find((n) => n.id === focusId) ?? null;
  const focusEdge = useMemo(
    () => (focusId ? edgeByFp.get(focusId) ?? null : null),
    [edgeByFp, focusId]
  );

  const isEmpty = visibleContacts.length === 0;

  const clearFocus = useCallback(() => {
    setFocusId(null);
    setEditing(false);
    setActionsOpen(false);
    setShowHistory(false);
    setActionNote(null);
    setConfirmKind(null);
    setVerifyOpen(false);
  }, []);

  const confirmTarget: TrustActionTarget | null = focusEdge
    ? {
        id: focusEdge.id,
        fingerprint: focusEdge.peer_fingerprint,
        name: focusEdge.peer_name,
        trusted: !!focusEdge.trusted,
        ownerVerified: ownerHasVerified(focusEdge),
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
    setActionsOpen(false);
    setShowHistory(false);
    setActionNote(null);
    setVerifyOpen(false);
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

  useEffect(() => {
    const now = new Set<string>();
    for (const c of visibleContacts) {
      if (c.mutual?.reciprocal) now.add(c.peer_fingerprint);
    }
    const prev = prevMutualRef.current;
    if (prev.size === 0 && now.size > 0) {
      prevMutualRef.current = now;
      return;
    }
    for (const id of now) {
      if (!prev.has(id)) {
        const name = edgeByFp.get(id)?.peer_name || 'Someone';
        setCrystallizeNote(`Mutual trust crystallised with ${name}`);
        window.setTimeout(() => setCrystallizeNote(null), 3200);
        break;
      }
    }
    prevMutualRef.current = now;
  }, [visibleContacts, edgeByFp]);

  const pxPerWorld = vpSize.w / Math.max(cam.w, 1);
  const labels = useMemo(() => {
    const cands: LabelCandidate[] = layout.nodes.map((n) => {
      const sx = ((n.x - cam.x) / Math.max(cam.w, 1e-6)) * vpSize.w;
      const sy = ((n.y - cam.y) / Math.max(cam.h, 1e-6)) * vpSize.h;
      const rPx = Math.max(n.radius * pxPerWorld, 6);
      return {
        id: n.id,
        name: pxPerWorld < 1.3 ? shortDisplayName(n.name) : n.name,
        x: sx,
        y: sy,
        r: rPx,
        priority: (n.id === focusId ? 'force' : n.state === 'trusted' ? 'trusted' : 'known') as LabelCandidate['priority'],
      };
    });
    return selectLabels(cands, {
      viewW: vpSize.w,
      viewH: vpSize.h,
      pxPerWorld,
      maxLabels: 48,
    });
  }, [layout.nodes, cam, vpSize, pxPerWorld, focusId]);

  const runRefresh = useCallback(async () => {
    if (!onRefresh || refreshing) return;
    setRefreshing(true);
    setRefreshNote('Checking for updates…');
    try {
      await onRefresh();
      setRefreshNote('Caught up.');
    } catch {
      setRefreshNote('Could not check right now.');
    } finally {
      setRefreshing(false);
      setPullDy(0);
      window.setTimeout(() => setRefreshNote(null), 1800);
    }
  }, [onRefresh, refreshing]);

  const onVpPointerDown = useCallback(
    (e: React.PointerEvent) => {
      const el = viewportElRef.current;
      if (onRefresh && el) {
        const rect = el.getBoundingClientRect();
        if (e.clientY - rect.top < 64) {
          pullRef.current = { y: e.clientY, x: e.clientX, armed: true, pulling: false };
          return;
        }
      }
      pullRef.current = null;
      vpHandlers.onPointerDown(e);
    },
    [onRefresh, vpHandlers, viewportElRef],
  );

  const onVpPointerMove = useCallback(
    (e: React.PointerEvent) => {
      const pull = pullRef.current;
      if (pull?.armed && onRefresh && !pull.pulling) {
        const dy = e.clientY - pull.y;
        const dx = Math.abs(e.clientX - pull.x);
        if (dy > 12 && dy > dx * 1.2) {
          pull.pulling = true;
          setPullDy(Math.min(120, dy));
          return;
        }
        if (Math.hypot(dx, dy) > 8) {
          pullRef.current = null;
          vpHandlers.onPointerDown(e);
          vpHandlers.onPointerMove(e);
          return;
        }
        return;
      }
      if (pull?.pulling) {
        e.preventDefault();
        setPullDy(Math.min(120, Math.max(0, e.clientY - pull.y)));
        return;
      }
      vpHandlers.onPointerMove(e);
    },
    [onRefresh, vpHandlers],
  );

  const onVpPointerUp = useCallback(
    (e: React.PointerEvent) => {
      const pull = pullRef.current;
      const firedPull = !!(pull?.pulling && pullDy > 64);
      pullRef.current = null;
      if (firedPull) {
        void runRefresh();
        vpHandlers.onPointerUp();
        return;
      }
      setPullDy(0);
      const panned = didPan();
      vpHandlers.onPointerUp();
      if (panned) return;
      const el = viewportElRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const hit = hitTestNodes(
        [layout.self, ...layout.nodes],
        cam,
        rect,
        e.clientX,
        e.clientY,
      );
      if (hit && hit !== layout.self.id) openFocus(hit);
      else if (!hit) clearFocus();
    },
    [pullDy, runRefresh, vpHandlers, didPan, viewportElRef, layout, cam, openFocus, clearFocus],
  );

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
          gap: 6,
          alignItems: 'center',
          marginBottom: 10,
          fontFamily: E.fontSans,
          flexShrink: 0,
        }}
      >
        {onRefresh ? (
          <button
            type="button"
            data-testid="trust-map-refresh"
            aria-label="Check for updates"
            onClick={() => void runRefresh()}
            disabled={refreshing}
            style={iconBtnStyle()}
          >
            <RotateCw className="h-3.5 w-3.5" />
          </button>
        ) : null}
        <div style={{ marginLeft: 'auto', display: 'inline-flex', gap: 6, alignItems: 'center' }}>
          <button type="button" data-testid="trust-map-zoom-out" aria-label="Zoom out" onClick={() => zoomBy(1 / 1.12)} style={iconBtnStyle()}>
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button type="button" data-testid="trust-map-zoom-in" aria-label="Zoom in" onClick={() => zoomBy(1.12)} style={iconBtnStyle()}>
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
              fittedOnce.current = false;
            }}
            style={iconBtnStyle()}
          >
            {fullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
          </button>
        </div>
      </div>

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
        onPointerDown={onVpPointerDown}
        onPointerMove={onVpPointerMove}
        onPointerUp={onVpPointerUp}
        onPointerCancel={onVpPointerUp}
        onTouchStart={vpHandlers.onTouchStart}
        onTouchMove={vpHandlers.onTouchMove}
        onTouchEnd={vpHandlers.onTouchEnd}
      >
        <style>{`
          .tm-node { opacity: var(--tm-o, 1); transform-box: fill-box; transform-origin: center; }
          .tm-node.tm-enter { animation: tm-grow .72s cubic-bezier(.2,.8,.2,1) both; }
          .tm-node.tm-ignite { animation: tm-ignite 1.05s cubic-bezier(.16,1,.3,1) both; }
          .tm-ignite-halo { animation: tm-ignite-halo 1.05s ease-out both; pointer-events: none; }
          .tm-edge, .tm-label, .tm-cluster { opacity: var(--tm-o, 1); animation: tm-fade .72s ease-out both; }
          .tm-self { animation: tm-fade .55s ease-out both; }
          .tm-pending { animation: tm-pulse 1.8s ease-in-out infinite; }
          .tm-spoke-known { stroke-linecap: round; }
          .tm-spoke-verified { stroke-linecap: round; }
          .tm-spoke-trusted { stroke-linecap: round; animation: tm-spoke-live 2.4s ease-in-out infinite; }
          .tm-peer-trust { stroke-linecap: round; animation: tm-spoke-live 2.4s ease-in-out infinite; }
          .tm-peer-know { stroke-linecap: round; }
          .tm-core-light { animation: tm-core-breathe 2.8s ease-in-out infinite; }
          .tm-self-light { animation: tm-self-breathe 3.6s ease-in-out infinite; }
          .tm-glass-up { animation: tm-glass-up .9s cubic-bezier(.16,1,.3,1) both; }
          @keyframes tm-grow { from { opacity: 0; transform: scale(.3); } to { opacity: var(--tm-o,1); transform: scale(1); } }
          @keyframes tm-ignite {
            0% { opacity: 0; transform: translateY(42px) scale(.18); }
            38% { opacity: 1; transform: translateY(-8px) scale(1.18); }
            100% { opacity: var(--tm-o,1); transform: translateY(0) scale(1); }
          }
          @keyframes tm-ignite-halo {
            0% { opacity: 0; stroke-width: 0; }
            40% { opacity: 0.85; stroke-width: 3.2; }
            100% { opacity: 0; stroke-width: 0.4; }
          }
          @keyframes tm-fade { from { opacity: 0; } to { opacity: var(--tm-o,1); } }
          @keyframes tm-pulse { 0%, 100% { opacity: 0.45; } 50% { opacity: 0.95; } }
          @keyframes tm-spoke-live {
            0%, 100% { stroke-opacity: 0.72; }
            50% { stroke-opacity: 1; }
          }
          @keyframes tm-core-breathe {
            0%, 100% { opacity: 0.82; }
            50% { opacity: 1; }
          }
          @keyframes tm-self-breathe {
            0%, 100% { opacity: 0.88; }
            50% { opacity: 1; }
          }
          @keyframes tm-glass-up {
            0% { transform: scale(.86); filter: brightness(1.35); }
            55% { transform: scale(1.12); filter: brightness(1.2); }
            100% { transform: scale(1); filter: brightness(1); }
          }
          @media (prefers-reduced-motion: reduce) {
            .tm-node, .tm-edge, .tm-label, .tm-self, .tm-cluster, .tm-pending, .tm-ignite, .tm-ignite-halo,
            .tm-spoke-trusted, .tm-peer-trust, .tm-core-light, .tm-self-light, .tm-glass-up { animation: none; }
            .tm-node { transform: none; }
          }
        `}</style>

        <svg
          data-testid="trust-map-svg"
          viewBox={`${cam.x} ${cam.y} ${cam.w} ${cam.h}`}
          width="100%"
          height="100%"
          preserveAspectRatio="none"
          role="img"
          aria-label={`Galaxy: ${visibleContacts.length} connection${visibleContacts.length === 1 ? '' : 's'}`}
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
              const verified = !!edge && ownerHasVerified(edge);
              const mutual = !!edge?.mutual?.reciprocal;
              const lane = glassLane(n.state, verified, pending);
              const trusted = lane === 'trusted';
              const spokeClass =
                trusted ? 'tm-edge tm-spoke-trusted' : verified ? 'tm-edge tm-spoke-verified' : 'tm-edge tm-spoke-known';
              return (
                <g key={`e-${n.id}`}>
                  {trusted && (
                    <line
                      className="tm-edge"
                      x1={layout.self.x}
                      y1={layout.self.y}
                      x2={n.x}
                      y2={n.y}
                      stroke="#fff8ee"
                      strokeOpacity={mutual ? 0.28 : 0.16}
                      strokeWidth={mutual ? 5.5 : 4.2}
                      style={{ ['--tm-o' as string]: 0.85, animationDelay: `${0.08 + i * 0.02}s` }}
                    />
                  )}
                  <line
                    className={spokeClass}
                    data-testid="trust-edge"
                    data-spoke={lane}
                    x1={layout.self.x}
                    y1={layout.self.y}
                    x2={n.x}
                    y2={n.y}
                    stroke={pending ? T.pending : trusted ? '#fff6e8' : T.myEdge}
                    strokeOpacity={
                      pending
                        ? 0.4
                        : trusted
                          ? mutual
                            ? 0.95
                            : 0.82
                          : verified
                            ? 0.58
                            : 0.48
                    }
                    strokeWidth={trusted ? (mutual ? 2.4 : 1.85) : verified ? 1.25 : pending ? 1.1 : 1.05}
                    strokeDasharray={pending ? '5 4' : n.state === 'decayed' ? '3 3' : undefined}
                    style={{ ['--tm-o' as string]: n.edgeOpacity, animationDelay: `${0.08 + i * 0.02}s` }}
                  />
                </g>
              );
            })}
          </g>

          {/* Witnessed open-visibility peer mesh — Know and Trust between contacts, not tags */}
          <g>
            {peerChords.map((ch, i) => {
              const a = layout.nodes.find((n) => n.id === ch.a);
              const b = layout.nodes.find((n) => n.id === ch.b);
              if (!a || !b) return null;
              const trust = ch.layer === 'trust';
              return (
                <g key={`peer-${ch.layer}-${ch.a}-${ch.b}`}>
                  {trust ? (
                    <line
                      className="tm-cluster"
                      x1={a.x}
                      y1={a.y}
                      x2={b.x}
                      y2={b.y}
                      stroke="#fff8ee"
                      strokeOpacity={0.22}
                      strokeWidth={4.4}
                      style={{ ['--tm-o' as string]: 0.85, animationDelay: `${0.08 + i * 0.02}s` }}
                    />
                  ) : null}
                  <line
                    className={trust ? 'tm-cluster tm-peer-trust' : 'tm-cluster tm-peer-know'}
                    data-testid="trust-peer-chord"
                    data-layer={ch.layer}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke={trust ? '#fff6e8' : T.myEdge}
                    strokeOpacity={trust ? 0.92 : 0.55}
                    strokeWidth={trust ? 2.05 : 1.2}
                    style={{ ['--tm-o' as string]: 0.95, animationDelay: `${0.08 + i * 0.02}s` }}
                  >
                    <title>{trust ? 'Witnessed mutual trust' : 'Witnessed mutual know'}</title>
                  </line>
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
                  verified={!!edge && ownerHasVerified(edge)}
                  mutual={!!edge?.mutual?.reciprocal}
                  ignite={igniteIds.has(n.id)}
                  glassPop={glassPop.has(n.id)}
                  onSelect={handleNodeClick}
                />
              );
            })}
          </g>

          <g className="tm-self" data-testid="trust-map-self" style={{ ['--tm-o' as string]: 1 }}>
            <polygon
              points={hexagonPoints(layout.self.x, layout.self.y, SELF_RING_RADIUS)}
              fill="none"
              stroke={T.selfRing}
              strokeWidth={0.85}
              opacity={0.38}
            />
            <polygon
              points={hexagonPoints(layout.self.x, layout.self.y, SELF_CORE_RADIUS)}
              fill={T.field}
              stroke={T.selfRing}
              strokeWidth={1.7}
            />
            <circle
              className="tm-self-light"
              cx={layout.self.x}
              cy={layout.self.y}
              r={11}
              fill="#fff8ee"
              opacity={0.16}
              style={{ pointerEvents: 'none' }}
            />
            <circle
              className="tm-self-light"
              data-testid="trust-self-light"
              cx={layout.self.x}
              cy={layout.self.y}
              r={6.2}
              fill="#fffef8"
            />
          </g>
        </svg>

        {(pullDy > 8 || refreshing || refreshNote) && (
          <div
            data-testid="trust-map-pull"
            style={{
              position: 'absolute',
              left: '50%',
              top: 10,
              transform: `translate(-50%, ${Math.min(pullDy, 80) * 0.35}px)`,
              zIndex: 6,
              padding: '6px 12px',
              borderRadius: 999,
              background: 'color-mix(in srgb, var(--se-bg) 82%, transparent)',
              border: `1px solid ${E.border}`,
              color: E.muted,
              fontFamily: E.fontSans,
              fontSize: 11,
              pointerEvents: 'none',
            }}
          >
            {refreshing || refreshNote
              ? refreshNote || 'Checking for updates…'
              : pullDy > 64
                ? 'Release to update'
                : 'Pull for updates'}
          </div>
        )}

        {crystallizeNote ? (
          <div
            data-testid="trust-map-crystallize"
            style={{
              position: 'absolute',
              left: '50%',
              top: 16,
              transform: 'translateX(-50%)',
              zIndex: 5,
              padding: '10px 16px',
              borderRadius: 12,
              background: 'color-mix(in srgb, var(--se-accent2) 22%, var(--se-bg))',
              border: `1px solid ${E.accent2}`,
              color: E.text,
              fontFamily: E.fontSans,
              fontSize: 13,
              pointerEvents: 'none',
            }}
          >
            {crystallizeNote}
          </div>
        ) : null}

        <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 2 }}>
          {labels
            .filter((l) => l.textY > 10 && l.textY < vpSize.h - 88)
            .map((l) => (
            <span
              key={l.id}
              style={{
                position: 'absolute',
                left: l.x,
                top: l.textY,
                transform: 'translate(-50%, 0)',
                fontFamily: E.fontSans,
                fontSize: 11,
                color: l.id === focusId ? E.text : E.muted,
                fontWeight: l.id === focusId ? 600 : 400,
                whiteSpace: 'nowrap',
              }}
            >
              {l.name}
            </span>
          ))}
          <span
            style={{
              position: 'absolute',
              left: ((layout.self.x - cam.x) / Math.max(cam.w, 1e-6)) * vpSize.w,
              top: ((layout.self.y - cam.y) / Math.max(cam.h, 1e-6)) * vpSize.h + SELF_CORE_RADIUS * pxPerWorld + 10,
              transform: 'translate(-50%, 0)',
              fontFamily: E.fontSans,
              fontSize: 11,
              color: E.muted,
            }}
          >
            You
          </span>
        </div>

        {isEmpty && (
          <div
            data-testid="trust-map-empty"
            style={{
              position: 'absolute',
              left: 16,
              right: 16,
              bottom: 104,
              textAlign: 'center',
              pointerEvents: 'none',
              fontFamily: E.fontSans,
              zIndex: 7,
            }}
          >
            <p style={{ margin: 0, fontSize: 16, color: T.label, letterSpacing: '0.04em' }}>
              Grow your galaxy
            </p>
            <p style={{ margin: '8px 0 0', fontSize: 10, color: T.caption }}>
              In person they can become a star you Know. Remote, they wait at the Gate.
            </p>
            <p style={{ margin: '4px 0 0', fontSize: 10, color: T.caption }}>
              Trust is mutual, after you make sure it&apos;s them.
            </p>
            {onGrow ? (
              <button
                type="button"
                data-testid="trust-map-grow"
                onClick={onGrow}
                style={{
                  pointerEvents: 'auto',
                  marginTop: 14,
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
                Grow
              </button>
            ) : null}
          </div>
        )}

        <GalaxyGateMembrane count={gateCount} sparkIds={gateSparks} onOpen={() => setGateOpen(true)} />

        {gateOpen && ownerFingerprint ? (
          <GrowGatePanel
            ownerFp={ownerFingerprint}
            variant="overlay"
            onClose={() => setGateOpen(false)}
            onAdmitted={(fp) => {
              forgetIgnited(ownerFingerprint, fp);
              setIgniteIds((prev) => {
                const next = new Set(prev);
                next.add(fp);
                return next;
              });
            }}
          />
        ) : null}
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
          <span style={{ color: E.accent2 }}>⬡ trusted · white light</span>
          <span>⬡ known · dim spoke</span>
          <span style={{ color: E.text }}>⬡ you · larger + light</span>
          <span style={{ color: E.accent2 }}>═ trust between you</span>
          <span>─ know between you</span>
          <span style={{ color: E.accent }}>∪ known sphere</span>
          <span style={{ color: E.accent }}>⊙ Gate</span>
          <span style={{ color: E.accent }}>◌ pending intro</span>
          <span>- - group</span>
        </div>
      )}
      <p
        data-testid="trust-map-legend"
        style={{
          margin: '8px 0 0',
          fontSize: 11,
          color: E.dim,
          fontFamily: E.fontSans,
          lineHeight: 1.45,
        }}
      >
        Wheel or pinch to zoom · Fit recenters · pull the top of the map for updates.
        Spokes go to you. Solid gold between people is Know they both consented to show;
        white-gold is mutual Trust. Dashed gold is a group you named — not a bond.
        Verify is a private ember — nobody else sees a badge. The U is your known sphere; the hole is the Gate.
      </p>

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
            position: 'relative',
            overflow: 'hidden',
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
                  {(() => {
                    const mark = ownerLocalBadge({
                      mintChannel: focusEdge.metadata?.grow_mint_channel as string | undefined,
                      verified: ownerHasVerified(focusEdge),
                    });
                    if (!mark.kind) return null;
                    return (
                      <p
                        data-testid="star-provenance"
                        data-kind={mark.kind}
                        style={{
                          margin: '6px 0 0',
                          fontSize: 11,
                          letterSpacing: '0.08em',
                          textTransform: 'lowercase',
                          color: mark.kind === 'verified' ? E.accent2 : E.muted,
                        }}
                      >
                        {mark.label}
                      </p>
                    );
                  })()}
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
                  {focusEdge.peer_fingerprint && (
                    <p
                      style={{
                        margin: '10px 0 0',
                        fontSize: 11,
                        color: E.dim,
                        fontFamily: E.fontMono,
                        letterSpacing: '0.04em',
                        wordBreak: 'break-all',
                      }}
                    >
                      {formatFingerprintForVerify(focusEdge.peer_fingerprint)}
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
                  margin: '10px 0 0',
                  fontSize: 11,
                  color: E.dim,
                  lineHeight: 1.45,
                }}
              >
                Read the fingerprint aloud. Verify is you making sure it&apos;s them — in the world, not a badge.
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

          {/* Actions — nested; the card itself is name, key, notes */}
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
            {!isPending(focusEdge) && onOwnerVerify && !ownerHasVerified(focusEdge) && (
              <ActionBtn
                testId="galaxy-verify"
                label={VERIFY_SHEET_COPY.title}
                primary
                onClick={() => setVerifyOpen(true)}
              />
            )}
            <ActionBtn
              label="Actions"
              primary
              onClick={() => setActionsOpen((v) => !v)}
              trailing={
                <ChevronDown
                  size={14}
                  style={{
                    transform: actionsOpen ? 'rotate(180deg)' : undefined,
                    transition: 'transform 120ms ease',
                  }}
                />
              }
            />
            {actionsOpen && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
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
                {!editing && (
                  <ActionBtn
                    label="Edit"
                    onClick={() => {
                      setEditing(true);
                      setActionsOpen(false);
                    }}
                  />
                )}
                {!isPending(focusEdge) && onTrustToggle && (
                  <ActionBtn
                    label={
                      busy
                        ? '…'
                        : focusEdge.trusted
                          ? 'Remove trust'
                          : ownerHasVerified(focusEdge)
                            ? 'TRUST'
                            : 'Verify first, then Trust'
                    }
                    primary={!focusEdge.trusted && ownerHasVerified(focusEdge)}
                    danger={!!focusEdge.trusted}
                    onClick={() => {
                      if (focusEdge.trusted) {
                        setConfirmKind('break');
                        return;
                      }
                      if (!ownerHasVerified(focusEdge)) {
                        setVerifyOpen(true);
                        return;
                      }
                      setConfirmKind('trust');
                    }}
                  />
                )}
                <ActionBtn
                  label="Version history"
                  onClick={() => setShowHistory((v) => !v)}
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
              </div>
            )}
            {editing && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
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
              </div>
            )}
            {!isPending(focusEdge) && ownerHasVerified(focusEdge) && !focusEdge.trusted && (
              <p style={{ margin: 0, fontSize: 11, color: E.dim, lineHeight: 1.45 }}>
                {TRUST_RECIPE_COPY.verifiedHere}
              </p>
            )}

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

      <VerifySheet
        open={verifyOpen && !!focusEdge}
        onClose={() => setVerifyOpen(false)}
        displayName={focusEdge?.peer_name || focusNode?.name || ''}
        fingerprint={focusEdge?.peer_fingerprint || ''}
        onConfirm={async (method) => {
          if (!focusEdge || !onOwnerVerify) return;
          await onOwnerVerify(focusEdge, method);
          setActionNote('Saved here only.');
        }}
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
  trailing,
  testId,
}: {
  label: string;
  onClick: () => void;
  primary?: boolean;
  danger?: boolean;
  trailing?: React.ReactNode;
  testId?: string;
}) {
  return (
    <button
      type="button"
      data-testid={testId}
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
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
      }}
    >
      {label}
      {trailing}
    </button>
  );
}

function ContactNode({
  node,
  index,
  selected,
  picked,
  pending,
  verified,
  mutual,
  ignite,
  glassPop,
  onSelect,
}: {
  node: LaidOutNode;
  index: number;
  selected: boolean;
  picked: boolean;
  pending: boolean;
  verified: boolean;
  mutual: boolean;
  ignite: boolean;
  glassPop: boolean;
  onSelect: (id: string, multi: boolean) => void;
}) {
  const r = selected || picked ? node.radius + 2.5 : node.radius;
  const trusted = node.state === 'trusted' && !pending;
  const lane = glassLane(node.state, verified, pending);
  const cls = [
    'tm-node',
    pending ? 'tm-pending' : '',
    ignite ? 'tm-ignite' : '',
    glassPop ? 'tm-glass-up' : '',
  ]
    .filter(Boolean)
    .join(' ');
  return (
    <g
      className={cls}
      data-graph-node={node.id}
      style={{ ['--tm-o' as string]: node.opacity, animationDelay: `${index * 0.025}s`, cursor: 'pointer' }}
      onClick={(e) => {
        e.stopPropagation();
        onSelect(node.id, e.shiftKey || e.metaKey || e.ctrlKey);
      }}
    >
      {ignite && (
        <polygon
          className="tm-ignite-halo"
          points={hexagonPoints(node.x, node.y, r + 10)}
          fill="none"
          stroke={T.myEdge}
          strokeOpacity={0.8}
        />
      )}
      {trusted && (
        <polygon
          points={hexagonPoints(node.x, node.y, r + (mutual ? 5 : 3.5))}
          fill="none"
          stroke="#fff8ee"
          strokeOpacity={mutual ? 0.42 : 0.22}
          strokeWidth={mutual ? 1.5 : 1.05}
          style={{ pointerEvents: 'none' }}
        />
      )}
      <polygon
        data-testid="trust-node"
        data-fingerprint={node.id}
        data-trust-state={pending ? 'pending' : node.state}
        data-verified={verified ? 'true' : 'false'}
        data-mutual={mutual ? 'true' : 'false'}
        data-ignite={ignite ? 'true' : 'false'}
        data-shape="hex"
        data-glass={lane}
        data-light={trusted ? 'white' : verified ? 'ember' : 'none'}
        points={hexagonPoints(node.x, node.y, r)}
        fill={nodeFill(node.state, pending)}
        stroke={picked ? E.accent : selected ? T.selfDot : nodeStroke(node.state, pending)}
        strokeWidth={picked || trusted ? 1.85 : pending ? 1.4 : 1.05}
        strokeDasharray={pending || node.state === 'decayed' ? (pending ? '3 2' : '2 2') : undefined}
      >
        <title>{`${node.name} — ${pending ? 'pending intro' : describe(node)}${mutual ? ' · mutual' : ''}`}</title>
      </polygon>
      {verified && !trusted && !pending && (
        <circle
          cx={node.x}
          cy={node.y}
          r={Math.max(1.6, r * 0.22)}
          fill={T.myEdge}
          opacity={0.85}
          style={{ pointerEvents: 'none' }}
        />
      )}
      {trusted && (
        <>
          <circle
            cx={node.x}
            cy={node.y}
            r={Math.max(4.2, r * 0.55)}
            fill="#fff8ee"
            opacity={0.18}
            style={{ pointerEvents: 'none' }}
          />
          <circle
            className="tm-core-light"
            data-testid="trust-node-light"
            cx={node.x}
            cy={node.y}
            r={Math.max(2.1, r * 0.28)}
            fill="#fffef8"
            style={{ pointerEvents: 'none' }}
          />
        </>
      )}
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
