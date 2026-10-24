// scripts/claim-sweep.test.ts — excuse-rule tests for the S42 claim-honesty gate (scripts/claim-sweep-lib.ts),
// run against the REAL registry (scripts/claim-registry.json). Gate values are injected so each rule is
// tested in isolation; one test also pins the real src/lib/claim-gates.ts values.
// Run: npx --no-install tsx --test scripts/claim-sweep.test.ts
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as realGates from '../src/lib/claim-gates';
import {
  loadRegistry, compileRegistry, scanText, parseAnnotation, hedgePhrases, checkRequires,
  type AnchorIndex, type CompiledClaim, type EvalContext,
} from './claim-sweep-lib';

const reg = loadRegistry();
const claims: CompiledClaim[] = compileRegistry(reg, () => true);
const byId = (id: string) => {
  const c = reg.claims.find((x) => x.id === id);
  assert.ok(c, `registry has ${id}`);
  return c;
};

const ALL_FALSE: EvalContext = { gateValue: () => false, requiresOk: () => false };
const realGateValue = (n: string) => Boolean(((realGates as Record<string, unknown>)[n] as () => boolean)());
const REAL: EvalContext = { gateValue: realGateValue, requiresOk: () => false };

function scan(text: string, ctx: EvalContext = ALL_FALSE) {
  return scanText('t.tsx', text, claims, ctx);
}
const ids = (r: ReturnType<typeof scan>) => r.violations.map((v) => v.claimId);

describe('kind=never — NO excuse', () => {
  it('a NEVER phrase fails', () => {
    assert.deepEqual(ids(scan('<p>svrnty is quantum-safe</p>')), ['NV-1']);
  });
  it('a NEVER phrase WITH a hedge still fails (gate-hedge wording, roadmap words, post-quantum-ready)', () => {
    assert.deepEqual(ids(scan('<p>quantum-safe messaging — coming soon, on the roadmap</p>')), ['NV-1']);
    assert.deepEqual(ids(scan('<p>phishing-proof login, blocked directly</p>')), ['NV-4']);
    assert.deepEqual(ids(scan('<p>unbreakable (post-quantum-ready, signed with a post-quantum key)</p>')), ['NV-1']);
  });
  it('a NEVER phrase WITH a reasoned claim-sweep:ok annotation still fails (same line and line above)', () => {
    const same = scan('<p>quantum-safe</p> {/* claim-sweep:ok: reviewed by copy owner */}');
    assert.deepEqual(ids(same), ['NV-1']);
    assert.equal(same.honored.length, 0);
    const above = scan('// claim-sweep:ok: reviewed by copy owner\n<p>send an anonymous note</p>');
    assert.deepEqual(ids(above), ['NV-3']);
    assert.equal(above.honored.length, 0);
    assert.match(above.violations[0].reason, /does NOT excuse kind=never/);
  });
  it('a NEVER phrase fails even when every gate is true and every anchor passes', () => {
    assert.deepEqual(ids(scan('<p>deleted for everyone</p>', { gateValue: () => true, requiresOk: () => true })), ['NV-5']);
  });
});

describe('kind=gated — gate true OR own hedge OR reasoned annotation', () => {
  it('G-5 "fully blocked" fails while isPiece2MutualBlockLive()=false', () => {
    assert.deepEqual(ids(scan('<p>They are fully blocked.</p>')), ['G-5']);
  });
  it('is excused when its gate is true', () => {
    const ctx: EvalContext = { gateValue: (n) => n === byId('G-5').gate, requiresOk: () => false };
    assert.deepEqual(ids(scan('<p>They are fully blocked.</p>', ctx)), []);
  });
  it("is excused by the entry's OWN hedge wording on the same line", () => {
    assert.deepEqual(hedgePhrases(byId('G-5').hedge), ['blocked directly']);
    assert.deepEqual(ids(scan('<p>fully blocked? no — blocked directly</p>')), []);
  });
  it('is NOT excused by generic hedge-ish words that are not its own hedge', () => {
    assert.deepEqual(ids(scan('<p>fully blocked — coming soon, not yet, on the roadmap</p>')), ['G-5']);
  });
  it("is NOT excused by another entry's hedge wording", () => {
    assert.deepEqual(ids(scan('<p>fully blocked; signed with a post-quantum key</p>')), ['G-5']);
  });
  it('a parenthetical (guidance) hedge gives no hedge wording — G-1 cannot be excused by "post-quantum-ready"', () => {
    assert.deepEqual(hedgePhrases(byId('G-1').hedge), []);
    assert.deepEqual(ids(scan('<p>post-quantum-ready messages</p>')), ['G-1']);
  });
  it('is excused by a REASONED annotation (same line or line above) and the annotation is reported', () => {
    const same = scan("{isPiece2MutualBlockLive() ? 'fully blocked' : 'blocked'} {/* claim-sweep:ok: gate-guarded ternary */}");
    assert.deepEqual(ids(same), []);
    assert.equal(same.honored.length, 1);
    assert.deepEqual({ ...same.honored[0] }, { file: 't.tsx', line: 1, annotationLine: 1, claimId: 'G-5', reason: 'gate-guarded ternary' });
    const above = scan("// claim-sweep:ok: gate-guarded ternary\n{live ? 'fully blocked' : 'blocked'}");
    assert.deepEqual(ids(above), []);
    assert.deepEqual(above.honored.map((h) => [h.line, h.annotationLine, h.claimId]), [[2, 1, 'G-5']]);
  });
  it('a REASONLESS annotation on a gated claim fails (bare, empty-colon, punctuation-only)', () => {
    for (const ann of ['// claim-sweep:ok', '// claim-sweep:ok:', '{/* claim-sweep:ok: */}', '// claim-sweep:ok: --']) {
      const r = scan(`<p>fully blocked</p> ${ann}`);
      assert.deepEqual(ids(r), ['G-5'], ann);
      assert.equal(r.honored.length, 0, ann);
      assert.match(r.violations[0].reason, /REASONLESS/, ann);
    }
    const above = scan('// claim-sweep:ok\n<p>fully blocked</p>');
    assert.deepEqual(ids(above), ['G-5']);
  });
  it('an annotation two lines above does not reach', () => {
    assert.deepEqual(ids(scan('// claim-sweep:ok: too far\n\n<p>fully blocked</p>')), ['G-5']);
  });
});

describe('kind=test_gated — anchors OR reasoned annotation', () => {
  it('TG-2 "secure session" fails while its anchors are unsatisfied', () => {
    assert.deepEqual(ids(scan('<p>secure session</p>')), ['TG-2']);
  });
  it('is excused when its anchors are satisfied', () => {
    assert.deepEqual(ids(scan('<p>secure session</p>', { gateValue: () => false, requiresOk: (id) => id === 'TG-2' })), []);
  });
  it('is excused by a reasoned annotation, not by a reasonless one', () => {
    assert.deepEqual(ids(scan('<p>secure session</p> // claim-sweep:ok: S50 anchors landed in #999')), []);
    assert.deepEqual(ids(scan('<p>secure session</p> // claim-sweep:ok')), ['TG-2']);
  });
  it('checkRequires: prose requirements are UNSATISFIED; file::"name" anchors need the file + name + not quarantined', () => {
    const idx: AnchorIndex = {
      files: ['src/lib/a/store.delete.test.ts', 'src/lib/b/store.bin.test.ts'],
      read: (f) => (f.endsWith('store.delete.test.ts') ? "it('delete makes no network call', …)" : "it('empty bin is all-or-nothing', …)"),
      quarantined: new Set(['src/lib/b/store.bin.test.ts']),
    };
    const st = checkRequires([
      'store.delete.test.ts :: "delete makes no network call" (I5)',
      'store.bin.test.ts :: "empty bin is all-or-nothing" (I12)',
      'store.archive.test.ts :: "multi-delete is all-or-nothing on mid-tx failure" (I4)',
      'store.delete.test.ts :: "some other name"',
      'Flint portal spec §6 tests (all)',
    ], idx);
    assert.deepEqual(st.map((s) => s.ok), [true, false, false, false, false]);
    assert.deepEqual(checkRequires([], idx).map((s) => s.ok), [false]);
  });
});

describe('kind=allowed — negative controls never flagged', () => {
  it('every allowed claim example passes a full scan at the real gate values', () => {
    const allowed = reg.claims.filter((c) => c.kind === 'allowed');
    assert.equal(allowed.length, 3);
    for (const c of allowed) for (const t of c.examples?.ok ?? []) {
      assert.deepEqual(ids(scan(`<p>${t}</p>`, REAL)), [], `${c.id}: "${t}"`);
    }
  });
  it('every registry ok-example passes a full scan at the real gate values', () => {
    for (const c of reg.claims) for (const t of c.examples?.ok ?? []) {
      assert.deepEqual(ids(scan(`<p>${t}</p>`, REAL)), [], `${c.id}: "${t}"`);
    }
  });
  it('every registry over-example of an enforceable non-allowed claim is flagged with all gates false', () => {
    for (const c of reg.claims) for (const t of c.examples?.over ?? []) {
      assert.ok(ids(scan(`<p>${t}</p>`)).includes(c.id), `${c.id}: "${t}"`);
    }
  });
});

describe('scanner mechanics', () => {
  it('pure comment lines are not copy (//, /* */ blocks, * continuation)', () => {
    assert.deepEqual(ids(scan('// quantum-safe\n/*\n unbreakable\n*/\n * phishing-proof')), []);
  });
  it('parseAnnotation', () => {
    assert.equal(parseAnnotation('const x = 1;'), null);
    assert.deepEqual(parseAnnotation('// claim-sweep:ok'), { reason: null });
    assert.deepEqual(parseAnnotation('{/* claim-sweep:ok: gate-guarded */}'), { reason: 'gate-guarded' });
    assert.deepEqual(parseAnnotation('<!-- claim-sweep:ok: roadmap row --> '), { reason: 'roadmap row' });
  });
  it('real claim-gates.ts values match the registry gate_value_at_sha (drift = flip without registry update)', () => {
    for (const c of reg.claims.filter((x) => x.kind === 'gated')) {
      assert.equal(realGateValue(c.gate as string), c.gate_value_at_sha, `${c.id} ${c.gate}`);
    }
  });
});

describe('developer log calls are not user copy (S42 ruling 2)', () => {
  it('an over-claim inside a console.*/logger.* call line is skipped', () => {
    assert.deepEqual(ids(scan("    console.warn('svrnty is quantum-safe', err);")), []);
    assert.deepEqual(ids(scan("logger.info('quantum-safe');")), []);
  });
  it('the same phrase in rendered copy still fails', () => {
    assert.deepEqual(ids(scan("<p>svrnty is quantum-safe</p>")), ['NV-1']);
    assert.deepEqual(ids(scan("toast('svrnty is quantum-safe');")), ['NV-1']);
  });
  it('only a line that STARTS a log call is skipped (assignment / continuation lines are scanned)', () => {
    assert.deepEqual(ids(scan("const msg = 'quantum-safe'; console.log(msg);")), ['NV-1']);
    assert.deepEqual(ids(scan("console.log(\n  'svrnty is quantum-safe',\n);")), ['NV-1']);
  });
});
