/**
 * Camera for the Social Graph — pan / zoom in world space via SVG viewBox.
 * CSS-scale of a tiny SVG is what made zoom look like a sticker sheet.
 */

export type Camera = {
  x: number;
  y: number;
  w: number;
  h: number;
};

export type Bounds = {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
};

export function boundsOf(
  points: Array<{ x: number; y: number; radius?: number }>,
  pad = 0,
): Bounds {
  if (points.length === 0) {
    return { minX: 0, minY: 0, maxX: 1, maxY: 1 };
  }
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const p of points) {
    const r = (p.radius ?? 0) + pad;
    minX = Math.min(minX, p.x - r);
    minY = Math.min(minY, p.y - r);
    maxX = Math.max(maxX, p.x + r);
    maxY = Math.max(maxY, p.y + r);
  }
  return { minX, minY, maxX, maxY };
}

/** Expand a bbox so its aspect matches the viewport (no SVG letterbox). */
export function fitCamera(bounds: Bounds, aspect: number, extraPad = 28): Camera {
  const bw = Math.max(1, bounds.maxX - bounds.minX) + extraPad * 2;
  const bh = Math.max(1, bounds.maxY - bounds.minY) + extraPad * 2;
  const a = aspect > 0 ? aspect : 1;
  let w = bw;
  let h = bh;
  if (w / h > a) {
    h = w / a;
  } else {
    w = h * a;
  }
  const cx = (bounds.minX + bounds.maxX) / 2;
  const cy = (bounds.minY + bounds.maxY) / 2;
  return { x: cx - w / 2, y: cy - h / 2, w, h };
}

/**
 * Screen → world. Assumes the SVG uses the camera as viewBox with
 * preserveAspectRatio="none" (we match camera aspect to the element).
 */
export function clientToWorld(
  cam: Camera,
  rect: { left: number; top: number; width: number; height: number },
  clientX: number,
  clientY: number,
): { x: number; y: number } {
  const w = Math.max(rect.width, 1);
  const h = Math.max(rect.height, 1);
  return {
    x: cam.x + ((clientX - rect.left) / w) * cam.w,
    y: cam.y + ((clientY - rect.top) / h) * cam.h,
  };
}

/**
 * Zoom window vs a fitted view. minW = most zoomed in, maxW = most zoomed out.
 * Must keep minW < fittedW < maxW so a fit can step both directions.
 */
export function zoomLimits(fittedW: number): { minW: number; maxW: number } {
  const fit = Math.max(fittedW, 1);
  const minW = Math.max(36, fit / 16);
  const maxW = Math.max(minW * 2, fit * 3.5);
  return { minW, maxW };
}

/**
 * One wheel/trackpad tick → a small multiplicative zoom.
 * Pixel, line, and page deltaModes normalize; a single event is clamped so
 * a coarse mouse wheel cannot jump the whole range.
 */
export function wheelZoomFactor(deltaY: number, deltaMode = 0): number {
  let dy = deltaY;
  if (deltaMode === 1) dy *= 16;
  if (deltaMode === 2) dy *= 48;
  dy = Math.max(-80, Math.min(80, dy));
  return Math.exp(-dy * 0.0024);
}

export function zoomCamera(
  cam: Camera,
  factor: number,
  worldX: number,
  worldY: number,
  minW: number,
  maxW: number,
): Camera {
  const lo = Math.min(minW, maxW);
  const hi = Math.max(minW, maxW);
  const nextW = Math.min(hi, Math.max(lo, cam.w / factor));
  const ratio = nextW / cam.w;
  if (ratio === 1) return cam;
  const nextH = cam.h * ratio;
  return {
    x: worldX - (worldX - cam.x) * ratio,
    y: worldY - (worldY - cam.y) * ratio,
    w: nextW,
    h: nextH,
  };
}

/** Screen-pixel hit test so zoomed-out seals stay tappable. */
export function hitTestNodes(
  nodes: Array<{ id: string; x: number; y: number; radius: number }>,
  cam: Camera,
  rect: { left: number; top: number; width: number; height: number },
  clientX: number,
  clientY: number,
  minPx = 22,
): string | null {
  const w = Math.max(rect.width, 1);
  const h = Math.max(rect.height, 1);
  const sx = clientX - rect.left;
  const sy = clientY - rect.top;
  let bestId: string | null = null;
  let bestD = Infinity;
  for (const n of nodes) {
    const px = ((n.x - cam.x) / Math.max(cam.w, 1e-6)) * w;
    const py = ((n.y - cam.y) / Math.max(cam.h, 1e-6)) * h;
    const d = Math.hypot(px - sx, py - sy);
    const rPx = Math.max((n.radius * w) / Math.max(cam.w, 1e-6), minPx);
    if (d <= rPx + 8 && d < bestD) {
      bestId = n.id;
      bestD = d;
    }
  }
  return bestId;
}

export function panCamera(cam: Camera, dxWorld: number, dyWorld: number): Camera {
  return { ...cam, x: cam.x - dxWorld, y: cam.y - dyWorld };
}

export function cameraCenter(cam: Camera): { x: number; y: number } {
  return { x: cam.x + cam.w / 2, y: cam.y + cam.h / 2 };
}
