/**
 * Viewport camera for Social Graph (zoom / pan / pinch) in world space.
 * Pure UI — no trust semantics.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type Camera,
  type Bounds,
  clientToWorld,
  fitCamera,
  panCamera,
  zoomCamera,
  cameraCenter,
  cameraLookingAt,
  zoomLimits,
  wheelZoomFactor,
} from '@/lib/trust/graph-camera';

const DEFAULT: Camera = { x: 0, y: 0, w: 640, h: 640 };

export function useGraphViewport(initial: Camera = DEFAULT) {
  const [cam, setCam] = useState<Camera>(initial);
  const camRef = useRef(cam);
  camRef.current = cam;
  const pinchRef = useRef<{ dist: number; cam: Camera; mx: number; my: number } | null>(null);
  const panRef = useRef<{
    x: number;
    y: number;
    cam: Camera;
    pointerId: number;
    dragging: boolean;
  } | null>(null);
  const elRef = useRef<HTMLDivElement | null>(null);
  const fitRef = useRef<Camera>(initial);
  const minWRef = useRef(80);
  const maxWRef = useRef(2400);

  const gestureRef = useRef({ dragging: false });

  const applyFit = useCallback((bounds: Bounds, aspect: number, mode: 'reset' | 'limits' = 'reset') => {
    const fitted = fitCamera(bounds, aspect, 36);
    fitRef.current = fitted;
    const lim = zoomLimits(fitted.w);
    minWRef.current = lim.minW;
    maxWRef.current = lim.maxW;
    if (mode === 'reset') setCam(fitted);
  }, []);

  const reset = useCallback(() => setCam(fitRef.current), []);

  const zoomAtClient = useCallback((factor: number, clientX?: number, clientY?: number) => {
    setCam((prev) => {
      const el = elRef.current;
      let wx: number;
      let wy: number;
      if (el && clientX != null && clientY != null) {
        const rect = el.getBoundingClientRect();
        const p = clientToWorld(prev, rect, clientX, clientY);
        wx = p.x;
        wy = p.y;
      } else {
        const c = cameraCenter(prev);
        wx = c.x;
        wy = c.y;
      }
      return zoomCamera(prev, factor, wx, wy, minWRef.current, maxWRef.current);
    });
  }, []);

  const zoomBy = useCallback(
    (factor: number) => {
      zoomAtClient(factor);
    },
    [zoomAtClient],
  );

  /** Fly the camera to a world point (search / lamp). Optional tighter window. */
  const focusOn = useCallback((worldX: number, worldY: number, zoomFactor = 0.35) => {
    setCam((prev) => {
      const fitW = fitRef.current.w;
      const targetW = Math.min(
        prev.w,
        Math.max(minWRef.current, fitW * zoomFactor),
      );
      return cameraLookingAt(
        prev,
        worldX,
        worldY,
        targetW,
        minWRef.current,
        maxWRef.current,
      );
    });
  }, []);

  useEffect(() => {
    const el = elRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const factor = wheelZoomFactor(e.deltaY, e.deltaMode);
      zoomAtClient(factor, e.clientX, e.clientY);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [zoomAtClient]);

  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if (e.button !== 0 && e.button !== 1) return;
    const el = e.target as HTMLElement;
    if (e.button === 0 && (el.closest('[data-graph-node]') || el.closest('[data-graph-cluster]'))) {
      return;
    }
    if (el.closest('button, a, input, textarea, [data-testid="trust-map-selection-bar"]')) {
      return;
    }
    // Record a possible pan but do NOT capture yet — a tap must reach the canvas.
    gestureRef.current.dragging = false;
    panRef.current = {
      x: e.clientX,
      y: e.clientY,
      cam: camRef.current,
      pointerId: e.pointerId,
      dragging: false,
    };
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!panRef.current) return;
    const el = elRef.current;
    if (!el) return;
    const start = panRef.current;
    const dxPx = e.clientX - start.x;
    const dyPx = e.clientY - start.y;
    if (!start.dragging) {
      if (Math.hypot(dxPx, dyPx) < 7) return;
      start.dragging = true;
      gestureRef.current.dragging = true;
      (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
    }
    const rect = el.getBoundingClientRect();
    const dxWorld = (dxPx / Math.max(rect.width, 1)) * start.cam.w;
    const dyWorld = (dyPx / Math.max(rect.height, 1)) * start.cam.h;
    setCam(panCamera(start.cam, dxWorld, dyWorld));
  }, []);

  const onPointerUp = useCallback(() => {
    panRef.current = null;
  }, []);

  const onTouchStart = useCallback((e: React.TouchEvent) => {
    if (e.touches.length === 2) {
      const a = e.touches[0];
      const b = e.touches[1];
      const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      pinchRef.current = {
        dist,
        cam: camRef.current,
        mx: (a.clientX + b.clientX) / 2,
        my: (a.clientY + b.clientY) / 2,
      };
      panRef.current = null;
    }
  }, []);

  const onTouchMove = useCallback((e: React.TouchEvent) => {
    if (e.touches.length === 2 && pinchRef.current) {
      e.preventDefault();
      const a = e.touches[0];
      const b = e.touches[1];
      const dist = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
      const factor = dist / Math.max(pinchRef.current.dist, 1);
      const origin = pinchRef.current.cam;
      const el = elRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const p = clientToWorld(origin, rect, pinchRef.current.mx, pinchRef.current.my);
      setCam(
        zoomCamera(origin, factor, p.x, p.y, minWRef.current, maxWRef.current),
      );
    }
  }, []);

  const onTouchEnd = useCallback(() => {
    pinchRef.current = null;
  }, []);

  useEffect(() => {
    return () => {
      pinchRef.current = null;
      panRef.current = null;
    };
  }, []);

  return {
    cam,
    reset,
    zoomBy,
    focusOn,
    applyFit,
    elRef,
    didPan: () => gestureRef.current.dragging,
    handlers: {
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
