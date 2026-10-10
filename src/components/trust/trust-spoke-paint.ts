/** Geometry for one-way vs mutual spokes. No trust logic — paint only. */

export type SpokePair = {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
};

/** Two thin parallels. Mutual stays a single thick line. */
export function offsetSpokePair(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  gap = 1.35,
): [SpokePair, SpokePair] {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  const ox = (-dy / len) * gap;
  const oy = (dx / len) * gap;
  return [
    { x1: x1 + ox, y1: y1 + oy, x2: x2 + ox, y2: y2 + oy },
    { x1: x1 - ox, y1: y1 - oy, x2: x2 - ox, y2: y2 - oy },
  ];
}

/** Clip rect covering the half of a node toward a point (usually you). */
export function halfFillToward(
  cx: number,
  cy: number,
  r: number,
  towardX: number,
  towardY: number,
): { points: string; rotateDeg: number } {
  const ang = Math.atan2(towardY - cy, towardX - cx);
  const px = Math.cos(ang);
  const py = Math.sin(ang);
  const qx = -py;
  const qy = px;
  const ext = r * 1.45;
  const along = r * 1.45;
  const a = `${cx + qx * ext},${cy + qy * ext}`;
  const b = `${cx - qx * ext},${cy - qy * ext}`;
  const c = `${cx - qx * ext + px * along},${cy - qy * ext + py * along}`;
  const d = `${cx + qx * ext + px * along},${cy + qy * ext + py * along}`;
  return {
    points: `${a} ${b} ${c} ${d}`,
    rotateDeg: (ang * 180) / Math.PI,
  };
}
