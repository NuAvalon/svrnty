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

export function zoomCamera(
  cam: Camera,
  factor: number,
  worldX: number,
  worldY: number,
  minW: number,
  maxW: number,
): Camera {
  const nextW = Math.min(maxW, Math.max(minW, cam.w / factor));
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

export function panCamera(cam: Camera, dxWorld: number, dyWorld: number): Camera {
  return { ...cam, x: cam.x - dxWorld, y: cam.y - dyWorld };
}

export function cameraCenter(cam: Camera): { x: number; y: number } {
  return { x: cam.x + cam.w / 2, y: cam.y + cam.h / 2 };
}
