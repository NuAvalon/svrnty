// scripts/claim-sweep.test.ts — excuse-rule tests for the S42 claim-honesty gate (scripts/claim-sweep-lib.ts),
// run against the REAL registry (scripts/claim-registry.json, v1.1). Gate values are injected so each rule is
// tested in isolation; one test also pins the real src/lib/claim-gates.ts values.
// Run: npx --no-install tsx --test scripts/claim-sweep.test.ts
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as realGates from '../src/lib/claim-gates';
import {
  loadRegistry, compileRegistry, compileClaim, scanText, parseAnnotation, checkRequires, ConfigError,
  type AnchorIndex, type CompiledClaim, type EvalContext, type RegistryClaim,
} from './claim-sweep-lib';

const reg = loadRegistry();
const claims: CompiledClaim[] = compileRegistry(reg, () => true);
const byId = (id: string): RegistryClaim => {
  const c = reg.claims.find((x) => x.id === id);
  assert.ok(c, `registry has ${id}`);
  return c;
};

const ALL_FALSE: EvalContext = { gateValue: () => false, requiresOk: () => false };
const realGateValue = (n: string) => Boolean(((realGates as Record<string, unknown>)[n] as () => boolean)());
const REAL: EvalContext = { gateValue: realGateValue, requiresOk: () => false };

function scan(text: string, ctx: EvalContext = ALL_FALSE, root = 'A') {
  return scanText('t.tsx', text, claims, ctx, root);
}
const ids = (r: ReturnType<typeof scan>) => r.violations.map((v) => v.claimId);
const rootOf = (c: RegistryClaim) => c.scan_root ?? 'A';

describe('kind=never — only its listed disclaimers pass; no hedge, no annotation', () => {
  it('a NEVER phrase fails', () => {
    assert.deepEqual(ids(scan('<p>svrnty is quantum-safe</p>')), ['NV-1']);
  });
  it('a NEVER phrase WITH hedge-ish words (incl. other rows\' hedge phrases) still fails', () => {
    assert.deepEqual(ids(scan('<p>quantum-safe messaging — coming soon, not yet, multi-use, 7-day</p>')), ['NV-1']);
    assert.deepEqual(ids(scan('<p>phishing-proof login, directly only, pending confirm</p>')), ['NV-4']);
  });
  it('a NEVER phrase WITH a reasoned claim-sweep:ok annotation still fails (same line and line above, both forms)', () => {
    for (const ann of ['{/* claim-sweep:ok: reviewed by copy owner */}', '{/* claim-sweep:ok reviewed by copy owner */}']) {
      const same = scan(`<p>quantum-safe</p> ${ann}`);
      assert.deepEqual(ids(same), ['NV-1'], ann);
      assert.equal(same.honored.length, 0, ann);
    }
    const above = scan('// claim-sweep:ok reviewed by copy owner\n<p>send an anonymous note</p>');
    assert.deepEqual(ids(above), ['NV-3']);
    assert.equal(above.honored.length, 0);
    assert.match(above.violations[0].reason, /does NOT excuse kind=never/);
  });
  it('a NEVER phrase fails even when every gate is true and every anchor passes', () => {
    assert.deepEqual(ids(scan('<p>deleted for everyone</p>', { gateValue: () => true, requiresOk: () => true })), ['NV-5']);
  });
  it("passes only with THIS row's listed disclaimer phrase on the same line", () => {
    assert.deepEqual(ids(scan('<p>svrnty is not anonymous: the relay sees that you sent something</p>')), []);
    assert.deepEqual(ids(scan('<p>svrnty is not coercion-proof</p>')), []);
    // a disclaimer phrase of ANOTHER never row does not excuse this one
    assert.deepEqual(ids(scan('<p>not anonymous, and unbreakable</p>')), ['NV-1']);
  });
});

describe('kind=gated — gate true OR own hedge_phrases OR reasoned annotation', () => {
  it('G-5 "fully blocked" fails while isPiece2MutualBlockLive()=false', () => {
    assert.deepEqual(ids(scan('<p>They are fully blocked.</p>')), ['G-5']);
  });
  it('is excused when its gate is true', () => {
    const ctx: EvalContext = { gateValue: (n) => n === byId('G-5').gate, requiresOk: () => false };
    assert.deepEqual(ids(scan('<p>They are fully blocked.</p>', ctx)), []);
  });
  it("is excused by THIS row's hedge_phrases on the same line", () => {
    assert.deepEqual(ids(scan('<p>fully blocked (direct connections only)</p>')), []);
    assert.deepEqual(ids(scan('<p>fully blocked — not yet</p>')), []);
  });
  it("is NOT excused by another row's hedge phrase", () => {
    // multi-use / 7-day are H-4's; signed with a post-quantum key is G-2's
    assert.deepEqual(ids(scan('<p>fully blocked; multi-use, 7-day, signed with a post-quantum key</p>')), ['G-5']);
  });
  it('G-1 (encrypt badge) is flagged on the old JoinerCeremony copy and on the new copy without its annotation', () => {
    assert.deepEqual(ids(scan('✓ Post-quantum protected — a signed card carrying a verified encryption key.')), ['G-1']);
    assert.deepEqual(ids(scan('✓ Post-quantum (hybrid) encryption — a signed card carrying a verified encryption key.')), ['G-1']);
  });
  it('the ruled JoinerCeremony form (JSX annotation on the line above) is honored and reported', () => {
    const r = scan('{/* claim-sweep:ok gated-by=isPQEncapLive: true-branch of the ternary */}\n✓ Post-quantum (hybrid) encryption — a signed card carrying a verified encryption key.');
    assert.deepEqual(ids(r), []);
    assert.deepEqual(r.honored.map((h) => [h.line, h.annotationLine, h.claimId, h.reason]), [[2, 1, 'G-1', 'gated-by=isPQEncapLive: true-branch of the ternary']]);
  });
  it('is excused by a REASONED annotation (same line or line above) and the annotation is reported', () => {
    const same = scan("{live ? 'fully blocked' : 'blocked'} {/* claim-sweep:ok: gate-guarded ternary */}");
    assert.deepEqual(ids(same), []);
    assert.deepEqual({ ...same.honored[0] }, { file: 't.tsx', line: 1, annotationLine: 1, claimId: 'G-5', reason: 'gate-guarded ternary' });
    const above = scan("// claim-sweep:ok gate-guarded ternary\n{live ? 'fully blocked' : 'blocked'}");
    assert.deepEqual(ids(above), []);
    assert.deepEqual(above.honored.map((h) => [h.line, h.annotationLine, h.claimId]), [[2, 1, 'G-5']]);
  });
  it('a REASONLESS annotation on a gated claim fails (bare, empty-colon, punctuation-only, glued suffix)', () => {
    for (const ann of ['// claim-sweep:ok', '// claim-sweep:ok:', '{/* claim-sweep:ok */}', '{/* claim-sweep:ok: */}', '// claim-sweep:ok: --', '// claim-sweep:ok-because']) {
      const r = scan(`<p>fully blocked</p> ${ann}`);
      assert.deepEqual(ids(r), ['G-5'], ann);
      assert.equal(r.honored.length, 0, ann);
      assert.match(r.violations[0].reason, /REASONLESS/, ann);
    }
    assert.deepEqual(ids(scan('// claim-sweep:ok\n<p>fully blocked</p>')), ['G-5']);
  });
  it('an annotation two lines above does not reach', () => {
    assert.deepEqual(ids(scan('// claim-sweep:ok too far\n\n<p>fully blocked</p>')), ['G-5']);
  });
});

describe('kind=hedge_required — own hedge_phrases OR reasoned annotation', () => {
  it('H-4: the old ContactShareDialog copy fails; the new honest copy passes', () => {
    assert.deepEqual(ids(scan('Link expires after first use or 15 minutes. The server cannot read your data.')), ['H-4']);
    assert.deepEqual(ids(scan('Multi-use link, valid ~7 days; the server can&apos;t read its content.')), []);
    assert.deepEqual(ids(scan('Creates a private, multi-use link, valid ~7 days, and shows it as a QR to scan. The server can&apos;t read its content.')), []);
    assert.deepEqual(ids(scan('it&apos;s a multi-use link, valid ~7 days.')), []);
  });
  it('is excused by a reasoned annotation (reported), not by a reasonless one', () => {
    const r = scan('<p>this link is single-use</p> // claim-sweep:ok owner-verified consume-on-read path');
    assert.deepEqual(ids(r), []);
    assert.equal(r.honored.length, 1);
    assert.deepEqual(ids(scan('<p>this link is single-use</p> // claim-sweep:ok')), ['H-4']);
  });
});

describe('kind=caveat_required (root B) — the FILE must carry the timing caveat; no annotation', () => {
  it('CR-1 fails without the caveat, passes with it anywhere in the file, ignores annotations', () => {
    assert.ok(ids(scan('<p>fully unlinkable migration</p>', ALL_FALSE, 'B')).includes('CR-1'));
    assert.ok(!ids(scan('<p>unlinkable to the relay.</p>\n<p>someone who can watch both relays could still correlate you by timing</p>', ALL_FALSE, 'B')).includes('CR-1'));
    assert.ok(ids(scan('<p>unlinkable</p> <!-- claim-sweep:ok reviewed -->', ALL_FALSE, 'B')).includes('CR-1'));
  });
  it('scan_root scoping: a root-B row does not fire on root A and vice versa', () => {
    assert.ok(!ids(scan('<p>run your own relay</p>', ALL_FALSE, 'A')).includes('H-6'));
    assert.ok(ids(scan('<p>run your own relay</p>', ALL_FALSE, 'B')).includes('H-6'));
    assert.ok(!ids(scan('<p>this link is single-use</p>', ALL_FALSE, 'B')).includes('H-4'));
  });
  it('a row with NO scan_root applies to every root (fail-closed)', () => {
    assert.equal(byId('NV-8').scan_root, undefined);
    assert.deepEqual(ids(scan('<p>coercion-proof by design</p>', ALL_FALSE, 'A')), ['NV-8']);
    assert.deepEqual(ids(scan('<p>coercion-proof by design</p>', ALL_FALSE, 'B')), ['NV-8']);
  });
});

describe('kind=test_gated — resolved anchors OR own hedge OR reasoned annotation', () => {
  it('TG-2 "secure session" fails while its anchors are unsatisfied', () => {
    assert.deepEqual(ids(scan('<p>secure session</p>')), ['TG-2']);
  });
  it('is excused when its anchors are satisfied', () => {
    assert.deepEqual(ids(scan('<p>secure session</p>', { gateValue: () => false, requiresOk: (id) => id === 'TG-2' })), []);
  });
  it("TG-3 is excused by its own hedge phrase", () => {
    assert.deepEqual(ids(scan('<p>messages are permanently deleted</p>')), ['TG-3']);
    assert.deepEqual(ids(scan('<p>messages are permanently deleted from this device</p>')), []);
  });
  it('is excused by a reasoned annotation, not by a reasonless one', () => {
    assert.deepEqual(ids(scan('<p>secure session</p> // claim-sweep:ok S50 anchors landed in #999')), []);
    assert.deepEqual(ids(scan('<p>secure session</p> // claim-sweep:ok')), ['TG-2']);
  });
  it('checkRequires: resolved:false is UNSATISFIED without looking; resolved:true needs file + name + not quarantined', () => {
    const idx: AnchorIndex = {
      files: ['src/lib/a/store.delete.test.ts', 'src/lib/b/store.bin.test.ts'],
      read: (f) => (f.endsWith('store.delete.test.ts') ? "it('delete makes no network call', …)" : "it('empty bin is all-or-nothing', …)"),
      quarantined: new Set(['src/lib/b/store.bin.test.ts']),
    };
    const R = (file: string | null, test: string, resolved: boolean) => ({ file, test, invariant: null, resolved });
    const st = checkRequires([
      R('store.delete.test.ts', 'delete makes no network call', true),
      R('store.delete.test.ts', 'delete makes no network call', false),
      R('store.bin.test.ts', 'empty bin is all-or-nothing', true),
      R('store.archive.test.ts', 'multi-delete is all-or-nothing on mid-tx failure', true),
      R('store.delete.test.ts', 'some other name', true),
      R(null, 'Flint portal spec §6 tests (all)', true),
    ], idx);
    assert.deepEqual(st.map((s) => s.ok), [true, false, false, false, false, false]);
    assert.deepEqual(checkRequires([], idx).map((s) => s.ok), [false]);
    // every requires entry in the shipped registry is resolved:false today → all three TG rows unsatisfied
    for (const id of ['TG-1', 'TG-2', 'TG-3']) assert.ok(checkRequires(byId(id).requires, idx).every((s) => !s.ok), id);
  });
});

describe('registry v1.1 schema handling', () => {
  it('detector_mode present_unhedged makes the pqBadge detector fire (the v1 G-2 dead-detector bug)', () => {
    assert.equal(byId('G-1').detector_mode, 'present_unhedged');
    assert.deepEqual(compileClaim(byId('G-1')).match('✓ post-quantum'), ['detector:pqBadgeOverclaim']);
  });
  it('a detector with no .overclaim and no detector_mode is a CONFIG ERROR, not a silent never-fires', () => {
    assert.throws(() => compileClaim({ id: 'X', kind: 'gated', claim: 'x', gate: 'g', detector: 'pqBadgeOverclaim', hedge_phrases: ['x'] }), ConfigError);
  });
  it('gated/hedge_required rows without hedge_phrases, and NEVER rows with hedge_phrases, are CONFIG ERRORS', () => {
    assert.throws(() => compileClaim({ id: 'X', kind: 'hedge_required', claim: 'x', patterns: ['x'] }), ConfigError);
    assert.throws(() => compileClaim({ id: 'X', kind: 'never', claim: 'x', patterns: ['x'], hedge_phrases: ['y'] }), ConfigError);
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
  it('every registry ok / disclaimer_ok example passes a full scan of its root at the real gate values', () => {
    for (const c of reg.claims) for (const t of [...(c.examples?.ok ?? []), ...(c.examples?.disclaimer_ok ?? [])]) {
      assert.deepEqual(ids(scan(`<p>${t}</p>`, REAL, rootOf(c))), [], `${c.id}: "${t}"`);
    }
  });
  it('every registry over-example of an enforceable non-allowed claim is flagged (all gates false, its root)', () => {
    for (const c of reg.claims) for (const t of c.examples?.over ?? []) {
      assert.ok(ids(scan(`<p>${t}</p>`, ALL_FALSE, rootOf(c))).includes(c.id), `${c.id}: "${t}"`);
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
    assert.deepEqual(parseAnnotation('// claim-sweep:ok gated-by=isPQEncapLive: true-branch of the ternary'), { reason: 'gated-by=isPQEncapLive: true-branch of the ternary' });
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

describe('registry v1.1.3+: sweep_gate_override replaces the claim-gates.ts value', () => {
  const ALL_TRUE: EvalContext = { gateValue: () => true, requiresOk: () => true };
  it('G-4 (PSI discovery): override false beats a gate that is true in code', () => {
    assert.equal(byId('G-4').sweep_gate_override, false);
    const r = scan('<p>find your mutual contacts</p>', ALL_TRUE);
    assert.deepEqual(ids(r), ['G-4']);
    assert.match(r.violations[0].reason, /overridden to false by the registry/);
  });
  it('G-6 (Peter hard gate #179867): mutual-trust copy fails even with every gate true', () => {
    assert.ok((reg.hard_gates ?? []).some((h) => h.id === 'G-6' && h.requires_override === false));
    assert.deepEqual(ids(scan('<p>mutual trust confirmed</p>', ALL_TRUE)), ['G-6']);
  });
  it('the row\'s own hedge still excuses an overridden row', () => {
    assert.deepEqual(ids(scan('<p>find your mutual contacts (preview)</p>', ALL_TRUE)), []);
  });
  it('a non-boolean override is a config error', () => {
    assert.throws(() => compileRegistry({ claims: [{ ...byId('G-4'), sweep_gate_override: 'false' as unknown as boolean }] }, () => true), ConfigError);
  });
  it('one line per ternary arm: the false arm\'s hedge must not excuse the true arm', () => {
    const same = "{live ? 'mutual trust confirmed' : 'Mutual confirmation is coming.'}";
    assert.deepEqual(ids(scan(same, ALL_FALSE)), [], 'documents the same-line limit: split arms onto their own lines');
    const split = "{live\n  ? 'mutual trust confirmed'\n  : 'Mutual confirmation is coming.'}";
    assert.deepEqual(ids(scan(split, ALL_FALSE)), ['G-6']);
  });
});
