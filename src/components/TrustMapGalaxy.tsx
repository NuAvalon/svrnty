'use client';

import { useCallback, useEffect, useRef } from 'react';
import type { Camera } from '@/lib/trust/graph-camera';
import { hitTestNodes } from '@/lib/trust/graph-camera';
import type { LaidOutNode, TrustLayout } from '@/lib/trust/trust-map-layout';
import type { FocusConstellation } from '@/lib/trust/constellation';
import type { WitnessedPeerChord } from '@/lib/trust/peer-trust-chords';
import { selectLabels, shortDisplayName, type LabelCandidate } from '@/lib/trust/label-lod';

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
      const dim = focusId && !isLit;
      ctx.beginPath();
      ctx.moveTo(self.x, self.y);
      ctx.lineTo(p.x, p.y);
      if (n.state === 'trusted') {
        ctx.strokeStyle = dim ? 'rgba(255,122,26,0.05)' : 'rgba(255,122,26,0.28)';
        ctx.lineWidth = isLit ? 1.8 : 0.7;
      } else {
        ctx.strokeStyle = dim ? 'rgba(249,168,37,0.03)' : 'rgba(249,168,37,0.10)';
        ctx.lineWidth = 0.45;
      }
      ctx.stroke();
    }

    // Witnessed peer-trust filaments — ember, solid. Distinct from dashed group beams.
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
      const dim = !!focusId && !involvesLamp;
      ctx.beginPath();
      ctx.moveTo(pa.x, pa.y);
      ctx.lineTo(pb.x, pb.y);
      ctx.strokeStyle = dim
        ? 'rgba(255,122,26,0.05)'
        : involvesLamp
          ? 'rgba(255,122,26,0.58)'
          : 'rgba(255,122,26,0.22)';
      ctx.lineWidth = involvesLamp ? 2.3 : 1.15;
      ctx.stroke();
    }

    // Volumetric beams from the lamped person to constellation (Cathedral select)
    if (focusId) {
      const lamp = L.nodes.find((n) => n.id === focusId);
      if (lamp) {
        const a = worldToScreen(C, w, h, lamp.x, lamp.y);
        for (const [id, mem] of lit) {
          const other = L.nodes.find((n) => n.id === id);
          if (!other) continue;
          const b = worldToScreen(C, w, h, other.x, other.y);
          const g = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
          const witnessed = mem.reasons.includes('disclosed-circle') || mem.reasons.includes('they-trust');
          const groupOnly = mem.reasons.includes('shared-group') && !witnessed;
          g.addColorStop(0, witnessed ? 'rgba(255,122,26,0.35)' : 'rgba(201,162,113,0.22)');
          g.addColorStop(1, 'rgba(249,168,37,0.02)');
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = g;
          ctx.lineWidth = witnessed ? 2.4 : 1.3;
          if (groupOnly) ctx.setLineDash([5, 5]);
          ctx.stroke();
          if (groupOnly) ctx.setLineDash([]);
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

    for (const n of L.nodes) {
      const p = worldToScreen(C, w, h, n.x, n.y);
      const isFocus = focusId === n.id;
      const isLit = isFocus || lit.has(n.id);
      const isPick = picked.has(n.id);
      const isHover = hover === n.id;
      const match = q && n.name.toLowerCase().includes(q);
      const dim = focusId && !isLit && !match && !isHover;
      const r = (isFocus || isPick || isHover ? n.radius + 2 : n.radius) * Math.min(2.2, Math.max(0.7, pxPerWorld));

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

      if (n.state === 'trusted') {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r + 4, 0, Math.PI * 2);
        ctx.fillStyle = dim ? 'rgba(255,122,26,0.04)' : 'rgba(255,122,26,0.16)';
        ctx.fill();
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = dim ? 'rgba(255,122,26,0.15)' : 'rgba(255,122,26,0.55)';
        ctx.fill();
      } else if (living.has(n.id)) {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = dim ? 'rgba(249,168,37,0.10)' : 'rgba(249,168,37,0.32)';
        ctx.fill();
        ctx.strokeStyle = dim ? 'rgba(249,168,37,0.20)' : 'rgba(249,168,37,0.70)';
        ctx.lineWidth = 1.1;
        ctx.stroke();
      } else {
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.strokeStyle = dim ? 'rgba(249,168,37,0.12)' : 'rgba(249,168,37,0.55)';
        ctx.lineWidth = 1.1;
        ctx.stroke();
      }
      if (isPick || isHover) {
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
      maxLabels: 56,
      boxW: pxPerWorld < 1.2 ? 56 : 78,
      boxH: 14,
      pad: 3,
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
  }, [focusId, constellation, peerChords, picked, query, livingIds]);

  useEffect(() => {
    paint();
  }, [paint, layout, cam, focusId, constellation, peerChords, picked, query, hoverId, pulseId]);

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
