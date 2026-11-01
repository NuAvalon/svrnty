/**
 * scripts/claim-order.ts — the claim registry's `order` kind (Hypatia spec v1 91e8f2e7 + v2 1da9cf5f + v3 9cae8b68; Flint #3128/#3130).
 *
 * A row pins ONE known site where a status word must be written only after the event that makes it true (or only inside the branch
 * that event opens). The sweep fails CI if that site regresses. LIMIT, carried verbatim in every row: it protects these sites only and
 * cannot find a new one; the PR-template status line is the control for new sites.
 *
 * FAIL-CLOSED, in this order, BEFORE any order comparison (Flint #3128): a missing file → FAIL; an anchor matching ≠ 1 line → FAIL;
 * no parsed node starting on the anchor line → FAIL; any count ≠ the row's exact count → FAIL. Zero matches never passes, so a rename
 * turns the row RED, not silently green.
 * Bodies of .ts/.tsx come from the TypeScript PARSER (a '{' in a string, regex, template or JSX can't shift the end). Comments are blanked
 * before matching. Patterns are matched per LINE; counts are matching LINES inside the body.
 * Output on FAIL: row id + step + file:line. Never the matched text.
 */
import ts from 'typescript';

export const ORDER_LIMIT =
  'Protects this site only. It cannot find a new site that writes a status before its event; the PR-template status line is the control for new sites.';

export interface OrderPattern { pattern: string; count: number }
export interface OrderRow {
  id: string;
  kind: 'order';
  claim: string;
  file: string;
  anchor_kind: 'function' | 'block';
  function: string; // regex for the ONE line that opens the function / block
  event: OrderPattern;
  status: OrderPattern;
  rule: 'event-before-status' | 'status-only-on-branch';
  /** status-only-on-branch: how many of the status matches must sit INSIDE the event's then-branch (the rest elsewhere in the body) */
  in_branch?: number;
  /** status-only-on-branch: an optional second status that must sit (count times) inside the event's ELSE branch */
  else_status?: OrderPattern;
  limit: string;
  source: string[];
}
export interface OrderFailure { id: string; step: string; at: string }

export class OrderConfigError extends Error {}

const re = (id: string, tag: string, src: unknown): RegExp => {
  if (typeof src !== 'string' || !src) throw new OrderConfigError(`${id}: ${tag} must be a non-empty regex string`);
  try {
    return new RegExp(src);
  } catch (e) {
    throw new OrderConfigError(`${id}: ${tag} regex does not compile (${(e as Error).message})`);
  }
};
const exactCount = (id: string, tag: string, n: unknown): number => {
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 1) throw new OrderConfigError(`${id}: ${tag} must be an exact integer >= 1 (no ranges, no 0)`);
  return n;
};

/** Validates the row SHAPE (a malformed row is a config error = exit 2, never a pass). */
export function validateOrderRows(rows: unknown): OrderRow[] {
  if (!Array.isArray(rows) || rows.length === 0) throw new OrderConfigError('order_rows is missing or empty: refusing to pass (would be fake-green)');
  const seen = new Set<string>();
  return rows.map((r: any) => {
    if (!r || typeof r.id !== 'string' || !/^OR-\d+$/.test(r.id)) throw new OrderConfigError(`order row without a valid id (OR-<n>): ${JSON.stringify(r?.id)}`);
    const id = r.id;
    if (seen.has(id)) throw new OrderConfigError(`duplicate order row id ${id}`);
    seen.add(id);
    if (r.kind !== 'order') throw new OrderConfigError(`${id}: kind must be "order"`);
    if (typeof r.file !== 'string' || !r.file) throw new OrderConfigError(`${id}: no file`);
    if (r.anchor_kind !== 'function' && r.anchor_kind !== 'block') throw new OrderConfigError(`${id}: anchor_kind must be function|block`);
    re(id, 'function', r.function);
    re(id, 'event.pattern', r.event?.pattern);
    exactCount(id, 'event.count', r.event?.count);
    re(id, 'status.pattern', r.status?.pattern);
    exactCount(id, 'status.count', r.status?.count);
    if (r.rule !== 'event-before-status' && r.rule !== 'status-only-on-branch') throw new OrderConfigError(`${id}: unknown rule "${String(r.rule)}"`);
    if (r.rule === 'status-only-on-branch') {
      if (r.event.count !== 1) throw new OrderConfigError(`${id}: status-only-on-branch needs exactly ONE event (the branch condition)`);
      exactCount(id, 'in_branch', r.in_branch);
      if (r.in_branch > r.status.count) throw new OrderConfigError(`${id}: in_branch > status.count`);
      if (r.else_status !== undefined) {
        re(id, 'else_status.pattern', r.else_status.pattern);
        exactCount(id, 'else_status.count', r.else_status.count);
      }
    } else if (r.in_branch !== undefined || r.else_status !== undefined) {
      throw new OrderConfigError(`${id}: in_branch / else_status are only for status-only-on-branch`);
    }
    if (r.limit !== ORDER_LIMIT) throw new OrderConfigError(`${id}: limit must be the LIMIT sentence verbatim`);
    if (!Array.isArray(r.source) || r.source.length === 0) throw new OrderConfigError(`${id}: no source`);
    return r as OrderRow;
  });
}

/** The file's lines with every comment blanked (newlines kept, so line numbers hold). */
function codeLines(sf: ts.SourceFile): string[] {
  const text = sf.getFullText();
  const chars = text.split('');
  const seen = new Set<number>();
  const blank = (rs: readonly ts.CommentRange[] | undefined) => {
    for (const c of rs ?? []) {
      if (seen.has(c.pos)) continue;
      seen.add(c.pos);
      for (let i = c.pos; i < c.end; i++) if (chars[i] !== '\n' && chars[i] !== '\r') chars[i] = ' ';
    }
  };
  const visit = (n: ts.Node) => {
    blank(ts.getLeadingCommentRanges(text, n.pos));
    blank(ts.getTrailingCommentRanges(text, n.end));
    n.forEachChild(visit);
  };
  visit(sf);
  blank(ts.getLeadingCommentRanges(text, sf.endOfFileToken.pos));
  return chars.join('').split('\n');
}

const lineOf = (sf: ts.SourceFile, pos: number) => sf.getLineAndCharacterOfPosition(pos).line + 1;

const isFunctionLike = (n: ts.Node) =>
  ts.isFunctionDeclaration(n) || ts.isMethodDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isConstructorDeclaration(n);
const isBlockLike = (n: ts.Node) => ts.isIfStatement(n) || ts.isBlock(n) || ts.isForStatement(n) || ts.isForOfStatement(n) || ts.isWhileStatement(n) || ts.isTryStatement(n);

/** The OUTERMOST node of the requested kind that starts on `line` (1-based). */
function nodeStartingOn(sf: ts.SourceFile, line: number, kind: 'function' | 'block'): ts.Node | undefined {
  let found: ts.Node | undefined;
  const want = kind === 'function' ? isFunctionLike : isBlockLike;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (want(n) && lineOf(sf, n.getStart(sf)) === line) {
      found = n;
      return;
    }
    n.forEachChild(visit);
  };
  visit(sf);
  return found;
}

function linesMatching(lines: string[], rx: RegExp, from: number, to: number): number[] {
  const out: number[] = [];
  for (let l = from; l <= to; l++) if (rx.test(lines[l - 1] ?? '')) out.push(l);
  return out;
}

/** The IfStatement whose condition starts on `line` (the event line), inside `within`. */
function ifOn(sf: ts.SourceFile, within: ts.Node, line: number): ts.IfStatement | undefined {
  let found: ts.IfStatement | undefined;
  const visit = (n: ts.Node) => {
    if (found) return;
    if (ts.isIfStatement(n) && lineOf(sf, n.expression.getStart(sf)) === line) {
      found = n;
      return;
    }
    n.forEachChild(visit);
  };
  within.forEachChild(visit);
  return found;
}

const rangeOf = (sf: ts.SourceFile, n: ts.Node): [number, number] => [lineOf(sf, n.getStart(sf)), lineOf(sf, n.getEnd())];
const inRange = (l: number, [a, b]: [number, number]) => l >= a && l <= b;

/** Checks every row. `read(path)` returns the file text, or null if it does not exist. */
export function checkOrderRows(rows: OrderRow[], read: (path: string) => string | null): OrderFailure[] {
  const fails: OrderFailure[] = [];
  for (const r of rows) {
    const fail = (step: string, at: string | number = '') => fails.push({ id: r.id, step, at: at === '' ? r.file : `${r.file}:${at}` });
    const text = read(r.file);
    if (text === null) {
      fail('1 file missing');
      continue;
    }
    if (!/\.(ts|tsx)$/.test(r.file)) {
      fail('2 only .ts/.tsx bodies are supported (parser); .py/.sh not built yet');
      continue;
    }
    const sf = ts.createSourceFile(r.file, text, ts.ScriptTarget.Latest, true, r.file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const lines = codeLines(sf);
    const anchors = linesMatching(lines, new RegExp(r.function), 1, lines.length);
    if (anchors.length !== 1) {
      fail(`2 anchor matches ${anchors.length} lines (need exactly 1)`, anchors.join(','));
      continue;
    }
    const node = nodeStartingOn(sf, anchors[0], r.anchor_kind);
    if (!node) {
      fail(`2 no ${r.anchor_kind} node starts on the anchor line`, anchors[0]);
      continue;
    }
    const body = rangeOf(sf, node);
    const ev = linesMatching(lines, new RegExp(r.event.pattern), body[0], body[1]);
    const st = linesMatching(lines, new RegExp(r.status.pattern), body[0], body[1]);
    if (ev.length !== r.event.count) {
      fail(`3 event count ${ev.length} != ${r.event.count}`, ev.join(',') || body[0]);
      continue;
    }
    if (st.length !== r.status.count) {
      fail(`3 status count ${st.length} != ${r.status.count}`, st.join(',') || body[0]);
      continue;
    }
    if (r.rule === 'event-before-status') {
      const last = Math.max(...ev);
      const early = st.filter((l) => l <= last);
      if (early.length) fail(`4 status before (or on) the last event line ${last}`, early.join(','));
      continue;
    }
    // status-only-on-branch
    const branch = ifOn(sf, node, ev[0]);
    if (!branch) {
      fail('4 the event line opens no if-branch', ev[0]);
      continue;
    }
    const thenR = rangeOf(sf, branch.thenStatement);
    const inThen = st.filter((l) => inRange(l, thenR));
    if (inThen.length !== r.in_branch) fail(`4 status inside the event's branch ${inThen.length} != ${r.in_branch}`, st.join(','));
    if (r.else_status) {
      const es = linesMatching(lines, new RegExp(r.else_status.pattern), body[0], body[1]);
      if (es.length !== r.else_status.count) {
        fail(`3 else_status count ${es.length} != ${r.else_status.count}`, es.join(',') || body[0]);
        continue;
      }
      if (!branch.elseStatement) {
        fail('4 the event branch has no else', ev[0]);
        continue;
      }
      const elseR = rangeOf(sf, branch.elseStatement);
      const outside = es.filter((l) => !inRange(l, elseR));
      if (outside.length) fail('4 else_status outside the else branch', outside.join(','));
      const statusInElse = st.filter((l) => inRange(l, elseR));
      if (statusInElse.length) fail('4 status inside the else branch', statusInElse.join(','));
    }
  }
  return fails;
}

/** For the builder (spec v3): each row's parsed body range next to its event/status lines. Ids + line numbers only. */
export function describeOrderRows(rows: OrderRow[], read: (path: string) => string | null): string[] {
  return rows.map((r) => {
    const text = read(r.file);
    if (text === null) return `${r.id} ${r.file}: MISSING`;
    const sf = ts.createSourceFile(r.file, text, ts.ScriptTarget.Latest, true);
    const lines = codeLines(sf);
    const a = linesMatching(lines, new RegExp(r.function), 1, lines.length);
    const n = a.length === 1 ? nodeStartingOn(sf, a[0], r.anchor_kind) : undefined;
    const b = n ? rangeOf(sf, n) : undefined;
    const ev = b ? linesMatching(lines, new RegExp(r.event.pattern), b[0], b[1]) : [];
    const st = b ? linesMatching(lines, new RegExp(r.status.pattern), b[0], b[1]) : [];
    return `${r.id} ${r.file}: anchor ${a.join(',') || '-'} body ${b ? `${b[0]}-${b[1]}` : '-'} event ${ev.join(',') || '-'} status ${st.join(',') || '-'}`;
  });
}
