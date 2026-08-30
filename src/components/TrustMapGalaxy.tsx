'use client';

import { useCallback, useEffect, useRef } from 'react';
import type { Camera } from '@/lib/trust/graph-camera';
import { hitTestNodes } from '@/lib/trust/graph-camera';
import type { LaidOutNode, TrustLayout } from '@/lib/trust/trust-map-layout';
import type { FocusConstellation } from '@/lib/trust/constellation';
import { constellationLinkKind } from '@/lib/trust/constellation';
import type { WitnessedPeerChord } from '@/lib/trust/peer-trust-chords';
import { selectLabels, shortDisplayName, type LabelCandidate } from '@/lib/trust/label-lod';
import type { LivingEdgeStatus } from '@/lib/trust/living-edge-status';

function worldToScreen(cam: Camera, w: number, h: number, x: number, y: number) {
  return {
    x: ((x - cam.x) / Math.max(cam.w, 1e-6)) * w,
    y: ((y - cam.y) / Math.max(cam.h, 1e-6)) * h,
  };
}

export function TrustMapGalaxy({
  layout,
  cam,
  focusId,
  hoverId,
  pulseId,
  constellation,
  peerChords = [],
  picked,
  query,
  livingIds,
  livingById,
  introLinks = [],
  onNodeClick,
  onBackgroundClick,
  onHoverChange,
}: {
  layout: TrustLayout;
  cam: Camera;
  focusId: string | null;
  hoverId?: string | null;
  /** Brief search / fly-to pulse target. */
  pulseId?: string | null;
  constellation: FocusConstellation | null;
  peerChords?: WitnessedPeerChord[];
  picked: Set<string>;
  query: string;
  livingIds?: Set<string>;
  livingById?: Map<string, LivingEdgeStatus>;
  /** Pending intro → introducer filaments (not trust). */
  introLinks?: Array<{ from: string; to: string }>;
  onNodeClick: (id: string, multi: boolean) => void;
  onBackgroundClick: () => void;
  onHoverChange?: (id: string | null) => void;
}) {
  const ref = useRef<HTMLCanvasElement | null>(null);
  const layoutRef = useRef(layout);
  layoutRef.current = layout;
  const camRef = useRef(cam);
  camRef.current = cam;
  const hoverRef = useRef<string | null>(hoverId ?? null);
  hoverRef.current = hoverId ?? null;
  const pulseRef = useRef(pulseId ?? null);
  pulseRef.current = pulseId ?? null;
  const pulseT0 = useRef(0);
  const rafRef = useRef<number | null>(null);

  const paint = useCallback(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    const parent = canvas.parentElement;
    const w = parent?.clientWidth ?? 1;
    const h = parent?.clientHeight ?? 1;
    const dpr = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2);
    if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const L = layoutRef.current;
    const C = camRef.current;
    const living = livingIds ?? new Set<string>();
    const q = query.trim().toLowerCase();
    const lit = constellation?.members ?? new Map();
    const pxPerWorld = w / Math.max(C.w, 1);
    const self = worldToScreen(C, w, h, L.self.x, L.self.y);
    const hover = hoverRef.current;
    const pulse = pulseRef.current;

    // Dim spokes to everyone — the book is yours. Brighten the lamped constellation.
    for (const n of L.nodes) {
      const p = worldToScreen(C, w, h, n.x, n.y);
      const isLit = focusId === n.id || lit.has(n.id);
      const mem = lit.get(n.id);
      const kind = mem ? constellationLinkKind(mem) : null;
      const dim = focusId && !isLit;
      ctx.beginPath();
      ctx.moveTo(self.x, self.y);
      ctx.lineTo(p.x, p.y);
      if (focusId === n.id) {
        const focusTrusted = n.state === 'trusted';
        ctx.strokeStyle = focusTrusted ? 'rgba(255,122,26,0.72)' : 'rgba(249,168,37,0.35)';
        ctx.lineWidth = focusTrusted ? 2.4 : 1.2;
      } else if (kind === 'witnessed-trust') {
        ctx.strokeStyle = 'rgba(255,122,26,0.22)';
        ctx.lineWidth = 1.0;
      } else if (n.state === 'trusted') {
        ctx.strokeStyle = dim ? 'rgba(255,122,26,0.03)' : 'rgba(255,122,26,0.22)';
        ctx.lineWidth = isLit ? 1.4 : 0.7;
      } else {
        ctx.strokeStyle = dim ? 'rgba(249,168,37,0.02)' : 'rgba(249,168,37,0.10)';
        ctx.lineWidth = 0.45;
      }
      ctx.stroke();
    }

    // Witnessed peer-trust filaments — when lamped, only chords involving the lamp stay.
    const nodeById = new Map(L.nodes.map((n) => [n.id.toLowerCase(), n]));
    for (const chord of peerChords) {
      const na = nodeById.get(chord.a.toLowerCase());
      const nb = nodeById.get(chord.b.toLowerCase());
      if (!na || !nb) continue;
      const pa = worldToScreen(C, w, h, na.x, na.y);
      const pb = worldToScreen(C, w, h, nb.x, nb.y);
      const involvesLamp =
        !!focusId &&
        (chord.a.toLowerCase() === focusId.toLowerCase() ||
          chord.b.toLowerCase() === focusId.toLowerCase());
      if (focusId && !involvesLamp) continue;
      ctx.beginPath();
      ctx.moveTo(pa.x, pa.y);
      ctx.lineTo(pb.x, pb.y);
      ctx.strokeStyle = involvesLamp ? 'rgba(255,122,26,0.70)' : 'rgba(255,122,26,0.22)';
      ctx.lineWidth = involvesLamp ? 2.6 : 1.15;
      ctx.stroke();
    }

    // Intro filaments — pending → introducer (not trust)
    for (const link of introLinks) {
      const aN = nodeById.get(link.from.toLowerCase()) || L.nodes.find((n) => n.id === link.from);
      const bN = nodeById.get(link.to.toLowerCase()) || L.nodes.find((n) => n.id === link.to);
      if (!aN || !bN) continue;
      const pa = worldToScreen(C, w, h, aN.x, aN.y);
      const pb = worldToScreen(C, w, h, bN.x, bN.y);
      ctx.beginPath();
      ctx.moveTo(pa.x, pa.y);
      ctx.lineTo(pb.x, pb.y);
      ctx.strokeStyle = 'rgba(201,162,113,0.45)';
      ctx.lineWidth = 1.2;
      ctx.setLineDash([2, 6]);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Beams from the lamped person — witnessed trust vs disclosed vs group (not trust)
    if (focusId) {
      const lamp = L.nodes.find((n) => n.id === focusId);
      if (lamp) {
        const a = worldToScreen(C, w, h, lamp.x, lamp.y);
        const ordered = [...lit.entries()].sort(([, ma], [, mb]) => {
          const rank = (m: (typeof ma)) => {
            const k = constellationLinkKind(m);
            return k === 'witnessed-trust' ? 2 : k === 'disclosed-circle' ? 1 : 0;
          };
          return rank(ma) - rank(mb);
        });
        for (const [id, mem] of ordered) {
          const other = L.nodes.find((n) => n.id === id);
          if (!other) continue;
          const b = worldToScreen(C, w, h, other.x, other.y);
          const kind = constellationLinkKind(mem);
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          if (kind === 'witnessed-trust') {
            ctx.strokeStyle = 'rgba(255,122,26,0.78)';
            ctx.lineWidth = 2.8;
            ctx.setLineDash([]);
          } else if (kind === 'disclosed-circle') {
            ctx.strokeStyle = 'rgba(249,168,37,0.55)';
            ctx.lineWidth = 2.0;
            ctx.setLineDash([]);
          } else {
            ctx.strokeStyle = 'rgba(201,162,113,0.42)';
            ctx.lineWidth = 1.35;
            ctx.setLineDash([4, 5]);
          }
          ctx.stroke();
          ctx.setLineDash([]);
        }
      }
    }

    // You
    ctx.beginPath();
    ctx.arc(self.x, self.y, 11, 0, Math.PI * 2);
    ctx.fillStyle = '#0f0a06';
    ctx.fill();
    ctx.strokeStyle = 'rgba(249,168,37,0.85)';
    ctx.lineWidth = 1.6;
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(self.x, self.y, 4, 0, Math.PI * 2);
    ctx.fillStyle = '#fbead2';
    ctx.fill();

    const candidates: LabelCandidate[] = [];
    const now = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const breath = 0.5 + 0.5 * Math.sin(now / 900);

    for (const n of L.nodes) {
      const p = worldToScreen(C, w, h, n.x, n.y);
      const isFocus = focusId === n.id;
      const mem = lit.get(n.id);
      const linkKind = mem ? constellationLinkKind(mem) : null;
      const isLit = isFocus || !!mem;
      const isPick = picked.has(n.id);
      const isHover = hover === n.id;
      const match = q && n.name.toLowerCase().includes(q);
      const dim = focusId && !isLit && !match && !isHover;
      const st = livingById?.get(n.id);
      const decay = st?.decayFreshness ?? 1;
      const mutualAlive = st?.trust === 'mutual';
      const outboundTrust = st?.trust === 'outbound';
      const rBase =
        (isFocus || isPick || isHover || linkKind === 'witnessed-trust' || mutualAlive
          ? n.radius + 2
          : n.radius) * Math.min(2.2, Math.max(0.7, pxPerWorld));
      const r = mutualAlive && !dim ? rBase * (1 + 0.06 * breath) : rBase;
      const alphaMul = dim ? 0.35 : 0.45 + 0.55 * decay;

      if (pulse === n.id) {
        if (!pulseT0.current) pulseT0.current = now;
        const t = (now - pulseT0.current) / 900;
        if (t < 1) {
          const ring = r + 6 + t * 18;
          ctx.beginPath();
          ctx.arc(p.x, p.y, ring, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(249,168,37,${(1 - t) * 0.7})`;
          ctx.lineWidth = 2;
          ctx.stroke();
        }
      }

      // Mutual = double ring; outbound trust sent = single directed tick (not mutual)
      if (mutualAlive && !dim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 7, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(255,122,26,${0.55 + 0.3 * breath})`;
        ctx.lineWidth = 2.0;
        ctx.stroke();
      } else if (outboundTrust && !dim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 5, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255,122,26,0.55)';
        ctx.lineWidth = 1.4;
        ctx.setLineDash([5, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      } else if (linkKind === 'witnessed-trust' && !dim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 6, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(255,122,26,0.85)';
        ctx.lineWidth = 2.0;
        ctx.setLineDash([]);
        ctx.stroke();
      } else if (linkKind === 'group-only' && !dim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 5, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(201,162,113,0.55)';
        ctx.lineWidth = 1.2;
        ctx.setLineDash([3, 3]);
        ctx.stroke();
        ctx.setLineDash([]);
      } else if (linkKind === 'disclosed-circle' && !dim) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 5, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(249,168,37,0.65)';
        ctx.lineWidth = 1.4;
        ctx.setLineDash([]);
        ctx.stroke();
      }

      if (n.state === 'trusted') {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 4, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,122,26,${(dim ? 0.04 : 0.16) * alphaMul})`;
        ctx.fill();
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,122,26,${(dim ? 0.15 : 0.55) * alphaMul})`;
        ctx.fill();
      } else if (living.has(n.id)) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(249,168,37,${(dim ? 0.1 : 0.32) * alphaMul})`;
        ctx.fill();
        ctx.strokeStyle = `rgba(249,168,37,${(dim ? 0.2 : 0.7) * alphaMul})`;
        ctx.lineWidth = 1.1;
        ctx.stroke();
      } else {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(249,168,37,${(dim ? 0.12 : 0.55) * alphaMul})`;
        ctx.lineWidth = 1.1;
        ctx.stroke();
      }
      if (isPick || isHover || isFocus) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 3, 0, Math.PI * 2);
        ctx.strokeStyle = '#f9a825';
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }

      const force = !!(isLit || isFocus || match || isHover);
      let priority: LabelCandidate['priority'] = 'known';
      if (force) priority = 'force';
      else if (n.state === 'trusted') priority = 'trusted';
      else if (living.has(n.id)) priority = 'living';
      candidates.push({
        id: n.id,
        name: pxPerWorld < 1.4 ? shortDisplayName(n.name) : n.name,
        x: p.x,
        y: p.y,
        r,
        priority,
      });
    }

    // Screen-space labels (fixed CSS px font) + collision LOD
    const labels = selectLabels(candidates, {
      viewW: w,
      viewH: h,
      pxPerWorld,
      maxLabels: 36,
      boxW: pxPerWorld < 1.3 ? 64 : 92,
      boxH: 16,
      pad: 6,
    });
    ctx.font = '12px "Space Grotesk", sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    for (const lab of labels) {
      const forced = candidates.find((c) => c.id === lab.id)?.priority === 'force';
      ctx.fillStyle = forced ? '#fbead2' : 'rgba(251,234,210,0.82)';
      // Soft plate for legibility on dense fields
      const tw = ctx.measureText(lab.name).width;
      ctx.fillStyle = 'rgba(15,10,6,0.55)';
      ctx.fillRect(lab.x - tw / 2 - 4, lab.textY - 11, tw + 8, 14);
      ctx.fillStyle = forced ? '#fbead2' : 'rgba(251,234,210,0.88)';
      ctx.fillText(lab.name, lab.x, lab.textY);
    }

    ctx.font = '12px "Space Grotesk", sans-serif';
    ctx.fillStyle = '#c9a271';
    ctx.textAlign = 'center';
    ctx.fillText('You', self.x, self.y + 22);
  }, [focusId, constellation, peerChords, picked, query, livingIds, livingById, introLinks]);

  useEffect(() => {
    paint();
  }, [paint, layout, cam, focusId, constellation, peerChords, picked, query, hoverId, pulseId, livingById, introLinks]);

  // Soft breathe for mutual-alive nodes
  useEffect(() => {
    let hasMutual = false;
    livingById?.forEach((s) => {
      if (s.trust === 'mutual') hasMutual = true;
    });
    if (!hasMutual && !pulseId) return;
    let id = 0;
    const tick = () => {
      paint();
      id = requestAnimationFrame(tick);
    };
    id = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(id);
  }, [livingById, pulseId, paint]);

  useEffect(() => {
    if (!pulseId) {
      pulseT0.current = 0;
      return;
    }
    pulseT0.current = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const tick = () => {
      paint();
      const elapsed =
        (typeof performance !== 'undefined' ? performance.now() : Date.now()) - pulseT0.current;
      if (elapsed < 1000) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, [pulseId, paint]);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ro = new ResizeObserver(() => paint());
    if (canvas.parentElement) ro.observe(canvas.parentElement);
    return () => ro.disconnect();
  }, [paint]);

  const hit = (clientX: number, clientY: number): LaidOutNode | null => {
    const canvas = ref.current;
    if (!canvas) return null;
    const rect = canvas.getBoundingClientRect();
    const L = layoutRef.current;
    const id = hitTestNodes(L.nodes, camRef.current, rect, clientX, clientY, 24);
    if (!id) return null;
    return L.nodes.find((n) => n.id === id) ?? null;
  };

  const drag = useRef<{ x: number; y: number } | null>(null);

  return (
    <canvas
      ref={ref}
      data-testid="trust-map-galaxy"
      data-graph-canvas="true"
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        zIndex: 1,
        cursor: 'grab',
      }}
      onPointerDown={(e) => {
        if (e.button !== 0) return;
        drag.current = { x: e.clientX, y: e.clientY };
      }}
      onPointerCancel={() => {
        drag.current = null;
      }}
      onPointerMove={(e) => {
        const n = hit(e.clientX, e.clientY);
        const next = n?.id ?? null;
        if (next !== hoverRef.current) {
          hoverRef.current = next;
          onHoverChange?.(next);
          paint();
        }
      }}
      onPointerLeave={() => {
        if (hoverRef.current) {
          hoverRef.current = null;
          onHoverChange?.(null);
          paint();
        }
      }}
      onPointerUp={(e) => {
        const start = drag.current;
        drag.current = null;
        if (!start || e.button !== 0) return;
        if (Math.hypot(e.clientX - start.x, e.clientY - start.y) > 8) return;
        const n = hit(e.clientX, e.clientY);
        if (n) onNodeClick(n.id, e.shiftKey || e.metaKey || e.ctrlKey);
        else onBackgroundClick();
      }}
    />
  );
}
