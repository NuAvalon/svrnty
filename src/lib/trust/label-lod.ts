/**
 * Screen-space label LOD for Trust Map — pure UI, no trust semantics.
 * Labels stay a fixed pixel size; collision suppresses overlaps at mid zoom.
 */

export type LabelCandidate = {
  id: string;
  name: string;
  /** Screen-space anchor (px). */
  x: number;
  y: number;
  /** Node radius in screen px (label sits below). */
  r: number;
  /** Force show: focus, lamped, search hit, hover. */
  priority: 'force' | 'trusted' | 'living' | 'known';
};

export type LabelPick = {
  id: string;
  name: string;
  x: number;
  y: number;
  /** Baseline y for text (below the node). */
  textY: number;
};

export type LabelLodOptions = {
  viewW: number;
  viewH: number;
  /** px per world unit — higher = more zoomed in. */
  pxPerWorld: number;
  maxLabels?: number;
  boxW?: number;
  boxH?: number;
  pad?: number;
};

function safeLabel(s: string, max = 22): string {
  return s
    .normalize('NFC')
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/[\x00-\x1f]/g, '')
    .slice(0, max);
}

/**
 * LOD gate from zoom:
 *  - far (<0.55): force-only
 *  - mid (0.55–1.15): trusted + limited living
 *  - near (>1.15): denser neighborhood labels
 */
export function labelBudget(pxPerWorld: number, maxLabels = 48): {
  allowTrusted: boolean;
  allowLiving: boolean;
  allowKnown: boolean;
  cap: number;
} {
  if (pxPerWorld < 0.55) {
    return { allowTrusted: false, allowLiving: false, allowKnown: false, cap: 0 };
  }
  if (pxPerWorld < 1.15) {
    return { allowTrusted: true, allowLiving: true, allowKnown: false, cap: Math.min(24, maxLabels) };
  }
  if (pxPerWorld < 2.0) {
    return { allowTrusted: true, allowLiving: true, allowKnown: true, cap: Math.min(40, maxLabels) };
  }
  return { allowTrusted: true, allowLiving: true, allowKnown: true, cap: maxLabels };
}

function inView(x: number, y: number, r: number, w: number, h: number, margin = 40): boolean {
  return x > -margin && y > -margin && x < w + margin && y < h + margin + r;
}

function overlaps(
  a: { x: number; y: number; w: number; h: number },
  b: { x: number; y: number; w: number; h: number },
  pad: number,
): boolean {
  return !(
    a.x + a.w + pad < b.x ||
    b.x + b.w + pad < a.x ||
    a.y + a.h + pad < b.y ||
    b.y + b.h + pad < a.y
  );
}

/**
 * Pick which labels to draw. Forced candidates always win; others fill by
 * priority until the zoom budget / collision grid fills.
 */
export function selectLabels(
  candidates: LabelCandidate[],
  opts: LabelLodOptions,
): LabelPick[] {
  const maxLabels = opts.maxLabels ?? 48;
  const boxW = opts.boxW ?? 72;
  const boxH = opts.boxH ?? 14;
  const pad = opts.pad ?? 4;
  const budget = labelBudget(opts.pxPerWorld, maxLabels);

  const force: LabelCandidate[] = [];
  const rest: LabelCandidate[] = [];
  for (const c of candidates) {
    if (!inView(c.x, c.y, c.r, opts.viewW, opts.viewH)) continue;
    if (c.priority === 'force') force.push(c);
    else {
      if (c.priority === 'trusted' && !budget.allowTrusted) continue;
      if (c.priority === 'living' && !budget.allowLiving) continue;
      if (c.priority === 'known' && !budget.allowKnown) continue;
      rest.push(c);
    }
  }

  const rank = (p: LabelCandidate['priority']) =>
    p === 'trusted' ? 0 : p === 'living' ? 1 : 2;
  rest.sort((a, b) => rank(a.priority) - rank(b.priority) || a.name.localeCompare(b.name));

  const placed: Array<{ x: number; y: number; w: number; h: number }> = [];
  const out: LabelPick[] = [];

  const tryPlace = (c: LabelCandidate, must: boolean) => {
    const textY = c.y + c.r + 12;
    const box = {
      x: c.x - boxW / 2,
      y: textY - boxH + 2,
      w: boxW,
      h: boxH,
    };
    if (!must) {
      for (const p of placed) {
        if (overlaps(box, p, pad)) return false;
      }
    }
    placed.push(box);
    out.push({
      id: c.id,
      name: safeLabel(c.name),
      x: c.x,
      y: c.y,
      textY,
    });
    return true;
  };

  for (const c of force) tryPlace(c, true);

  let nonForced = 0;
  for (const c of rest) {
    if (nonForced >= budget.cap) break;
    if (tryPlace(c, false)) nonForced++;
  }

  return out;
}

/** Short first name for dense mid-zoom plates. */
export function shortDisplayName(name: string, max = 14): string {
  const clean = safeLabel(name, 40);
  const first = clean.split(/\s+/)[0] || clean;
  return first.length > max ? first.slice(0, max - 1) + '…' : first;
}
