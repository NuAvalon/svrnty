#!/usr/bin/env tsx
/**
 * scripts/claim-sweep.ts — launch-honesty copy-gate (#521 / Chaos #110 / S42).
 *
 * Asserts no user-facing copy claims a capability that isn't real. SHIP-BLOCKS (exit 1) on a dishonest
 * claim. Honest counterpart to src/lib/claim-gates.ts — one source of truth, CI-enforced (a step of the
 * required `unified` job in .github/workflows/qa.yml), copy can't run ahead of the wire.
 *
 * CLAIMS: scripts/claim-registry.json (Hypatia's registry v1; kinds never / gated / test_gated / allowed).
 * Detectors it names: scripts/claim-detectors.ts. Rule engine: scripts/claim-sweep-lib.ts.
 *
 * EXCUSES (FAIL-CLOSED, Flint #157069 — proximity fails OPEN and is NOT used):
 *   never      → NO excuse. A same-line hedge or a `claim-sweep:ok` annotation does NOT excuse it.
 *   gated      → excused IFF gate()===true  OR  the line carries THIS entry's own hedge wording
 *                OR  a reasoned `claim-sweep:ok: <reason>` annotation on the same line / line directly above.
 *   test_gated → excused IFF every `requires` anchor is present (and not quarantined) OR a reasoned annotation.
 *   allowed    → negative controls; never flagged.
 *   A reasonless `claim-sweep:ok` is treated as no annotation. Every HONORED annotation is printed
 *   (count + file:line) so reviewers see each escape hatch used.
 *   A gate-GUARDED claim (isXLive() ? <claim> : <hedge>) is honest but NOT auto-excused (no AST); the
 *   author annotates it, which is the reviewed escape hatch.
 *
 * COVERAGE-ASSERTION (Flint hard requirement): every asserted root must be reachable; a
 * required-but-unreachable root => CONFIG-ERROR (exit 2), NEVER a silent green. Prints coverage.
 * An --assert-root id that names no known root is also a CONFIG-ERROR (it would assert nothing).
 *   Two-run plan: svrnty CI `--assert-root=A`; svrnty_deploy pre-deploy `--assert-root=B`.
 *   Root B (autobots infra/satellite) path override: SATELLITE_HTML_DIR.
 *
 * Trusted-side only + branch-protect the inputs (claim-gates.ts, claim-registry.json, claim-detectors.ts,
 * annotations) so a PR can't flip a boolean / delete a claim / self-add an annotation to pass itself.
 * (scripts/ and src/lib/ are CODEOWNERS-fenced.)
 *
 * Invocation (from repo root): npx --no-install tsx scripts/claim-sweep.ts [--assert-root=A,B]
 * Exit: 0 clean · 1 claim violations · 2 config error.
 */
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import * as gates from '../src/lib/claim-gates';
import { SCAN_ROOTS } from './claim-sweep.map';
import {
  ConfigError, loadRegistry, compileRegistry, buildAnchorIndex, checkRequires, scanText,
  type AnchorStatus, type Violation, type HonoredAnnotation, type CompiledClaim, type RegistryClaim,
} from './claim-sweep-lib';

const cwd = process.cwd();

function configError(msg: string): never {
  console.error(`CONFIG ERROR: ${msg}`);
  process.exit(2);
}

function hasGate(name: string): boolean {
  return typeof (gates as Record<string, unknown>)[name] === 'function';
}

function gateValue(name: string): boolean {
  if (!hasGate(name)) configError(`unknown gate "${name}" — not exported by src/lib/claim-gates.ts`);
  return Boolean(((gates as Record<string, unknown>)[name] as () => boolean)());
}

interface ResolvedFile { root: string; rel: string; abs: string; }

function parseAssertRoots(): Set<string> {
  const arg = process.argv.find((a) => a.startsWith('--assert-root='));
  const ids = arg ? arg.split('=')[1].split(',').map((s) => s.trim()).filter(Boolean) : SCAN_ROOTS.map((r) => r.id);
  if (ids.length === 0) configError('--assert-root is empty — refusing to assert nothing');
  const known = new Set(SCAN_ROOTS.map((r) => r.id));
  const unknown = ids.filter((id) => !known.has(id));
  if (unknown.length) configError(`--assert-root names unknown root(s) [${unknown.join(',')}] (known: ${[...known].join(',')})`);
  return new Set(ids);
}

function resolveRoots(assertRoots: Set<string>): ResolvedFile[] {
  const reachable: ResolvedFile[] = [];
  const coverage: string[] = [];
  for (const root of SCAN_ROOTS) {
    const present = root.files
      .map((f) => ({ root: root.id, rel: `${root.baseDir}/${f}`, abs: resolve(cwd, root.baseDir, f) }))
      .filter((rf) => existsSync(rf.abs));
    const asserted = assertRoots.has(root.id);
    coverage.push(`  root ${root.id} [${root.label}] ${asserted ? 'ASSERTED' : 'bonus'}: ${present.length}/${root.files.length} files at ${root.baseDir}`);
    if (asserted && present.length === 0) {
      console.error(coverage.join('\n'));
      configError(`required root ${root.id} (${root.label}) is UNREACHABLE at "${root.baseDir}". Refusing to pass — a gate blind to a required surface is a silent false-green. (Set SATELLITE_HTML_DIR, or run this root where its repo is checked out.)`);
    }
    reachable.push(...present);
  }
  console.log(`  asserting roots [${[...assertRoots].join(',')}]`);
  console.log(coverage.join('\n'));
  return reachable;
}

function main(): void {
  let compiled: CompiledClaim[];
  let registryClaims: RegistryClaim[];
  try {
    const reg = loadRegistry();
    registryClaims = reg.claims;
    compiled = compileRegistry(reg, hasGate);
  } catch (e) {
    if (e instanceof ConfigError) configError(e.message);
    throw e;
  }
  const byKind = (k: string) => registryClaims.filter((c) => c.kind === k).length;
  console.log(`claim-sweep: registry ${registryClaims.length} claims (never ${byKind('never')} · gated ${byKind('gated')} · test_gated ${byKind('test_gated')} · allowed ${byKind('allowed')})`);

  const enforced = compiled.filter((cc) => cc.claim.kind !== 'allowed' && !cc.unenforceable);
  if (enforced.length === 0) configError('no enforceable claims (no patterns/detectors) — refusing to pass (would be fake-green)');
  const blind = compiled.filter((cc) => cc.claim.kind !== 'allowed' && cc.unenforceable).map((cc) => cc.claim.id);
  if (blind.length) console.log(`  ⚠ NOT SCANNABLE (registry gives no patterns/detector — copy for these is NOT checked): ${blind.join(', ')}`);

  const files = resolveRoots(parseAssertRoots());

  const gateNames = Array.from(new Set(compiled.filter((cc) => cc.claim.kind === 'gated').map((cc) => cc.claim.gate as string)));
  console.log(`  gate snapshot: ${gateNames.map((g) => `${g}=${gateValue(g)}`).join(', ')}`);

  const idx = buildAnchorIndex();
  const anchorOk = new Map<string, boolean>();
  for (const cc of compiled.filter((x) => x.claim.kind === 'test_gated')) {
    const st: AnchorStatus[] = checkRequires(cc.claim.requires, idx);
    const ok = st.every((s) => s.ok);
    anchorOk.set(cc.claim.id, ok);
    console.log(`  test_gated ${cc.claim.id}: anchors ${ok ? 'SATISFIED' : 'NOT satisfied'}${cc.unenforceable ? ' (not scannable)' : ''}`);
    for (const s of st) console.log(`      ${s.ok ? '✓' : '✗'} ${s.requirement} — ${s.why}`);
  }

  const ctx = { gateValue, requiresOk: (id: string) => anchorOk.get(id) === true };
  const violations: Violation[] = [];
  const honored: HonoredAnnotation[] = [];
  for (const rf of files) {
    const r = scanText(rf.rel, readFileSync(rf.abs, 'utf8'), compiled, ctx);
    violations.push(...r.violations);
    honored.push(...r.honored);
  }

  console.log(`\nhonored claim-sweep:ok annotations: ${honored.length}`);
  for (const h of honored) console.log(`  ${h.file}:${h.line}  [${h.claimId}]  annotation @${h.annotationLine}: "${h.reason}"`);

  if (violations.length === 0) {
    console.log(`\n✅ claim-sweep PASS — ${files.length} files, ${enforced.length} enforced claims, no dishonest claims.`);
    process.exit(0);
  }
  console.error(`\n❌ claim-sweep SHIP-BLOCK — ${violations.length} dishonest claim(s):\n`);
  const claimText = new Map(registryClaims.map((c) => [c.id, c.claim]));
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  [${v.claimId} · ${v.kind}]  ${v.evidence.map((e) => `"${e}"`).join(', ')}`);
    console.error(`      ${v.reason}`);
    console.error(`      → ${claimText.get(v.claimId)}\n`);
  }
  process.exit(1);
}

main();
