// scripts/claim-order.test.ts — the `order` kind (Hypatia spec 91e8f2e7 + 1da9cf5f + 9cae8b68; Flint #3128/#3130): every row GREEN on
// the real tree, and per row each regression the spec lists is RED (moved, renamed event, extra write, missing file, renamed anchor).
// Run: npx --no-install tsx --test scripts/claim-order.test.ts
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ORDER_LIMIT, OrderConfigError, checkOrderRows, validateOrderRows, type OrderRow } from './claim-order';

const ROOT = join(__dirname, '..');
const REG = JSON.parse(readFileSync(join(ROOT, 'scripts/claim-registry.json'), 'utf8'));
const ROWS = validateOrderRows(REG.order_rows);
const realRead = (p: string) => (existsSync(join(ROOT, p)) ? readFileSync(join(ROOT, p), 'utf8') : null);
/** The real tree, with ONE file's text replaced. */
const withFile = (file: string, text: string | null) => (p: string) => (p === file ? text : realRead(p));
const lines = (file: string) => (realRead(file) as string).split('\n');
const idx = (ls: string[], rx: RegExp) => ls.flatMap((l, i) => (rx.test(l) ? [i] : []));
const check = (r: OrderRow, read: (p: string) => string | null) => checkOrderRows([r], read);

describe('order rows: the real tree is GREEN (the control)', () => {
  it('every seeded row holds', () => {
    assert.ok(ROWS.length >= 5, `${ROWS.length} rows`);
    assert.deepEqual(checkOrderRows(ROWS, realRead), []);
  });
  it('every row carries the LIMIT verbatim (nobody may cite the sweep as "status lines are checked")', () => {
    for (const r of ROWS) assert.equal(r.limit, ORDER_LIMIT, r.id);
  });
});

for (const r of ROWS) {
  describe(`${r.id} (${r.file}): each regression is RED, never silently green`, () => {
    const ls = lines(r.file);
    const ev = idx(ls, new RegExp(r.event.pattern));
    const st = idx(ls, new RegExp(r.status.pattern));

    it('the status moved ABOVE its event (or out of its branch) → RED', () => {
      const m = [...ls];
      const [line] = m.splice(st[st.length - 1], 1); // the LAST status write (for a branch row: the in-branch one is the last of them)
      m.splice(ev[0], 0, line); // just above the (first) event line, so it precedes the event / sits outside its branch
      const f = check(r, withFile(r.file, m.join('\n')));
      assert.ok(f.length > 0, 'must be RED');
    });

    it('the event renamed (its pattern now matches fewer lines, possibly 0) → RED at the count step', () => {
      const m = [...ls];
      m[ev[0]] = m[ev[0]].replace(new RegExp(r.event.pattern), (s) => s.replace(/(\w+)(?!.*\w)/, '$1Renamed'));
      const f = check(r, withFile(r.file, m.join('\n')));
      assert.ok(f.length > 0, 'must be RED');
      assert.match(f[0].step, /^3 event count/);
    });

    it('a second status write → the count no longer matches → RED', () => {
      const m = [...ls];
      m.splice(st[0] + 1, 0, m[st[0]]);
      const f = check(r, withFile(r.file, m.join('\n')));
      assert.ok(f.length > 0, 'must be RED');
    });

    it('the file is missing → RED (step 1)', () => {
      const f = check(r, withFile(r.file, null));
      assert.equal(f.length, 1);
      assert.match(f[0].step, /^1 file missing/);
    });

    it('the anchor renamed → RED (step 2), never a vacuous pass over zero lines', () => {
      const a = idx(ls, new RegExp(r.function));
      assert.equal(a.length, 1);
      const m = [...ls];
      m[a[0]] = m[a[0]].replace(/(\w+)(\s*\()/, '$1Renamed$2');
      const f = check(r, withFile(r.file, m.join('\n')));
      assert.ok(f.length > 0, 'must be RED');
      assert.match(f[0].step, /^2 /);
    });
  });
}

describe('branch rows: the status must sit INSIDE its branch, its else-status inside the else', () => {
  it('OR-2: removing the non-list 2xx assignment → RED (the branch holds 0, the count drops)', () => {
    const r = ROWS.find((x) => x.id === 'OR-2')!;
    const ls = lines(r.file);
    const ev = idx(ls, new RegExp(r.event.pattern))[0];
    const inBranch = idx(ls, new RegExp(r.status.pattern)).find((i) => i > ev)!;
    const m = [...ls];
    m[inBranch] = m[inBranch].replace(/summary\.rejected = res\.status/, 'void res.status');
    assert.ok(check(r, withFile(r.file, m.join('\n'))).length > 0);
  });
  it('OR-3: UNREADABLE and REFUSED swapped (UNREADABLE in the else) → RED', () => {
    const r = ROWS.find((x) => x.id === 'OR-3')!;
    const src = (realRead(r.file) as string).replace('POLL UNREADABLE', '__SWAP__').replace('POLL REFUSED', 'POLL UNREADABLE').replace('__SWAP__', 'POLL REFUSED');
    assert.ok(check(r, withFile(r.file, src)).length > 0);
  });
});

describe('the body comes from the TypeScript parser (Flint #3130)', () => {
  const row = (over: Partial<OrderRow> = {}): OrderRow => ({
    id: 'OR-99', kind: 'order', claim: 'fixture', file: 'fixture.ts', anchor_kind: 'function', function: '^export function f\\(',
    event: { pattern: 'if \\(x > 0\\)', count: 1 }, status: { pattern: "return 'ok';", count: 1 }, rule: 'event-before-status',
    limit: ORDER_LIMIT, source: ['test'], ...over,
  });
  const SRC = [
    'export function f(x: number) {',
    "  const s = '{{{ an unbalanced brace in a string';",
    '  if (x > 0) {',
    "    return 'ok';",
    '  }',
    "  return 'no';",
    '}',
    "export function g() { return 'ok'; }",
  ].join('\n');
  it("an unbalanced '{' in a string right after the anchor still yields the right body (brace counting would swallow g)", () => {
    assert.deepEqual(checkOrderRows([row()], (p) => (p === 'fixture.ts' ? SRC : null)), []);
  });
  it('a status in a COMMENT does not count (comments are blanked)', () => {
    const src = SRC.replace("  const s = '{{{", "  // return 'ok';\n  const s = '{{{");
    assert.deepEqual(checkOrderRows([row()], (p) => (p === 'fixture.ts' ? src : null)), []);
  });
});

describe('a malformed row is a CONFIG error (exit 2), never a pass', () => {
  const base = () => JSON.parse(JSON.stringify(REG.order_rows[0]));
  it('empty or missing order_rows', () => {
    assert.throws(() => validateOrderRows([]), OrderConfigError);
    assert.throws(() => validateOrderRows(undefined), OrderConfigError);
  });
  it('a limit that is not the LIMIT sentence verbatim', () => {
    const r = base();
    r.limit = 'Protects this site.';
    assert.throws(() => validateOrderRows([r]), OrderConfigError);
  });
  it('a count that is not an exact integer >= 1 (no "≥1", no 0)', () => {
    for (const bad of [0, '≥1', 1.5, undefined]) {
      const r = base();
      r.status.count = bad;
      assert.throws(() => validateOrderRows([r]), OrderConfigError, String(bad));
    }
  });
  it('an unknown rule, or a regex that does not compile', () => {
    const r1 = base();
    r1.rule = 'before-ish';
    assert.throws(() => validateOrderRows([r1]), OrderConfigError);
    const r2 = base();
    r2.event.pattern = '(unclosed';
    assert.throws(() => validateOrderRows([r2]), OrderConfigError);
  });
  it('duplicate ids', () => {
    assert.throws(() => validateOrderRows([base(), base()]), OrderConfigError);
  });
});

describe('status-in-event-block (spec v4 b66cbec3): a status moved past the catch is RED (Flint #3152\'s exact mutant)', () => {
  it('OR-5: the held hop moved from inside try { await sink.settle(); … } to just after the catch → RED', () => {
    const r = ROWS.find((x) => x.id === 'OR-5')!;
    assert.equal(r.rule, 'status-in-event-block');
    const ls = lines(r.file);
    const st = idx(ls, new RegExp(r.status.pattern))[0];
    const catchAt = ls.findIndex((l, i) => i > st && /^\s*\} catch \{/.test(l));
    const closeAt = ls.findIndex((l, i) => i > catchAt && /^\s*\}\s*$/.test(l));
    assert.ok(catchAt > st && closeAt > catchAt, 'found the try/catch around the held hop');
    const m = [...ls];
    const [line] = m.splice(st, 1);
    m.splice(closeAt, 0, line); // closeAt shifted up by one after the splice: this lands right after the catch's closing brace
    assert.ok(check(r, withFile(r.file, m.join('\n'))).length > 0, 'a held hop that runs even when settle() threw must be RED');
    // the same move under the OLD rule passed: that is the hole this rule closes
    assert.deepEqual(check({ ...r, rule: 'event-before-status' }, withFile(r.file, m.join('\n'))), []);
  });
});
