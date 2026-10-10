/** Geometry for dual-thin spokes. No trust logic — paint only. */

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
