/**
 * Viewport transform for Social Graph (zoom / pan / pinch).
 * Pure UI — no trust semantics.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

export type GraphViewport = {
  scale: number;
  tx: number;
  ty: number;
};

const MIN = 0.55;
const MAX = 3.2;

export function useGraphViewport(initial: GraphViewport = { scale: 1, tx: 0, ty: 0 }) {
  const [vp, setVp] = useState<GraphViewport>(initial);
  const vpRef = useRef(vp);
  vpRef.current = vp;
  const pinchRef = useRef<{ dist: number; scale: number } | null>(null);
  const panRef = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);

  const reset = useCallback(() => setVp({ scale: 1, tx: 0, ty: 0 }), []);

  const zoomBy = useCallback((factor: number, cx?: number, cy?: number) => {
    setVp((prev) => {
      const nextScale = Math.min(MAX, Math.max(MIN, prev.scale * factor));
      if (nextScale === prev.scale) return prev;
      if (cx == null || cy == null) return { ...prev, scale: nextScale };
      // Keep point under cursor stable
      const ratio = nextScale / prev.scale;
      return {
        scale: nextScale,
        tx: cx - (cx - prev.tx) * ratio,
        ty: cy - (cy - prev.ty) * ratio,
      };
    });
  }, []);

  const onWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const factor = e.deltaY > 0 ? 0.92 : 1.08;
      zoomBy(factor, cx, cy);
    },
    [zoomBy],
  );

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    // Pan with middle button, or primary when not on a node (caller may gate).
    if (e.button === 1 || e.button === 0) {
      const el = e.target as HTMLElement;
      if (el.closest('[data-graph-node]') || el.closest('[data-graph-cluster]')) {
        if (e.button === 0) return;
      }
      panRef.current = {
        x: e.clientX,
        y: e.clientY,
        tx: vpRef.current.tx,
        ty: vpRef.current.ty,
      };
      (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
    }
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!panRef.current) return;
    const dx = e.clientX - panRef.current.x;
    const dy = e.clientY - panRef.current.y;
    setVp((prev) => ({
      ...prev,
      tx: panRef.current!.tx + dx,
      ty: panRef.current!.ty + dy,
    }));
  }, []);

  const onPointerUp = useCallback(() => {
    panRef.current = null;
  }, []);

  const onTouchStart = useCallback((e: React.TouchEvent) => {
    if (e.touches.length === 2) {
      const a = e.touches[0];
      const b = e.touches[1];
      const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      pinchRef.current = { dist, scale: vpRef.current.scale };
      panRef.current = null;
    }
  }, []);

  const onTouchMove = useCallback((e: React.TouchEvent) => {
    if (e.touches.length === 2 && pinchRef.current) {
      e.preventDefault();
      const a = e.touches[0];
      const b = e.touches[1];
      const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      const nextScale = Math.min(
        MAX,
        Math.max(MIN, pinchRef.current.scale * (dist / Math.max(pinchRef.current.dist, 1))),
      );
      setVp((prev) => ({ ...prev, scale: nextScale }));
    }
  }, []);

  const onTouchEnd = useCallback(() => {
    pinchRef.current = null;
  }, []);

  useEffect(() => {
    // Prevent browser pinch-zoom on the graph when attached.
    return () => {
      pinchRef.current = null;
      panRef.current = null;
    };
  }, []);

  return {
    vp,
    setVp,
    reset,
    zoomBy,
    handlers: {
      onWheel,
      onPointerDown,
      onPointerMove,
      onPointerUp,
      onPointerCancel: onPointerUp,
      onTouchStart,
      onTouchMove,
      onTouchEnd,
    },
  };
}
