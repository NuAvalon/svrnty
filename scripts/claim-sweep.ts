#!/usr/bin/env tsx
/**
 * scripts/claim-sweep.ts — launch-honesty copy-gate (#521 / Chaos #110 / S42).
 *
 * Asserts no user-facing copy claims a capability that isn't real. SHIP-BLOCKS (exit 1) on a dishonest
 * claim. Honest counterpart to src/lib/claim-gates.ts — one source of truth, CI-enforced (a step of the
 * required `unified` job in .github/workflows/qa.yml), copy can't run ahead of the wire.
 *
 * CLAIMS: scripts/claim-registry.json (Hypatia's registry v1.1; kinds never / gated / test_gated /
 * hedge_required / caveat_required / allowed; each row has a scan_root). Detectors it names:
 * scripts/claim-detectors.ts. Rule engine + full excuse rules: scripts/claim-sweep-lib.ts.
 *
 * EXCUSES (FAIL-CLOSED, Flint #157069 — proximity fails OPEN and is NOT used):
 *   never           → only THIS row's listed disclaimer_phrases on the same line. NO annotation.
 *   gated           → gate()===true OR THIS row's hedge_phrases on the same line OR a reasoned annotation.
 *   hedge_required  → THIS row's hedge_phrases on the same line OR a reasoned annotation.
 *   test_gated      → every requires anchor resolved:true + present (not quarantined) OR THIS row's
 *                     hedge_phrases on the same line OR a reasoned annotation.
 *   caveat_required → the same FILE carries one of required_caveat. NO annotation.
 *   allowed         → negative controls; never flagged.
 *   Annotation = `claim-sweep:ok <reason>` on the same line or the line directly above (in JSX children
 *   use `{/* claim-sweep:ok <reason> *\/}` — a bare // there would render as text). Reasonless = ignored.
 *   Every HONORED annotation is printed (count + file:line). console.* / logger.* call lines are skipped.
 *   A gate-GUARDED claim (isXLive() ? <claim> : <hedge>) is honest but NOT auto-excused (no AST); the
 *   author annotates it, which is the reviewed escape hatch.
 *
 * COVERAGE-ASSERTION (Flint hard requirement): every asserted root must be reachable; a
 * required-but-unreachable (or empty) root => CONFIG-ERROR (exit 2), NEVER a silent green. Prints
 * coverage. A run scans ONLY the root(s) it asserts (default: all), so local output == CI output.
 * An --assert-root id that names no known root is also a CONFIG-ERROR (it would assert nothing).
 *   Two-run plan: svrnty CI `--assert-root=A`; svrnty_deploy pre-deploy `--assert-root=B`.
 *   Root B (autobots infra/satellite) path override: SATELLITE_HTML_DIR.
 *
 * Trusted-side only + branch-protect the inputs (claim-gates.ts, claim-registry.json, claim-detectors.ts,
 * annotations) so a PR can't flip a boolean / delete a claim / self-add an annotation to pass itself.
 * (scripts/ and src/lib/ are CODEOWNERS-fenced.)
 *
 * ORDER ROWS (`order_rows`, kind `order`, scripts/claim-order.ts; Hypatia spec 91e8f2e7 + 1da9cf5f + 9cae8b68): each pins ONE known site
 * where a status word may be written only after (or only inside the branch of) the event that makes it true. A malformed row = exit 2;
 * a regressed site = exit 1. They protect THOSE sites only; the PR-template status line is the control for new ones.
 * REQUIRED IDS (REQUIRED_ORDER_IDS in claim-order.ts): every pinned id must be present, or exit 2. Deleting a row is therefore not impossible,
 * it is a TWO-place edit (the row + the pinned list) that shows in the diff and is RED if only one is done; retiring a row stays a reviewer's call.
 *
 * Invocation (from repo root): npx --no-install tsx scripts/claim-sweep.ts [--assert-root=A,B]
 * Exit: 0 clean · 1 claim violations · 2 config error.
 */
import { readFileSync, existsSync } from 'fs';
import { resolve, relative, sep } from 'path';
import { OrderConfigError, checkOrderRows, validateOrderRows, type OrderFailure } from './claim-order';
import * as gates from '../src/lib/claim-gates';
import { SCAN_ROOTS } from './claim-sweep.map';
import {
  ConfigError, REGISTRY_PATH, loadRegistry, compileRegistry, buildAnchorIndex, checkRequires, scanText, walkFiles,
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
    const asserted = assertRoots.has(root.id);
    const present: ResolvedFile[] = [];
    for (const d of root.dirs) {
      const absDir = resolve(cwd, root.baseDir, d);
      if (!existsSync(absDir)) continue;
      for (const abs of walkFiles(absDir, root.include, root.recursive)) {
        present.push({ root: root.id, rel: relative(cwd, abs).split(sep).join('/'), abs });
      }
    }
    coverage.push(`  root ${root.id} [${root.label}] ${asserted ? 'ASSERTED' : 'not asserted (skipped)'}: ${present.length} files under ${root.baseDir} (${root.dirs.join(', ')})`);
    if (asserted && present.length === 0) {
      console.error(coverage.join('\n'));
      configError(`required root ${root.id} (${root.label}) is UNREACHABLE or EMPTY at "${root.baseDir}". Refusing to pass — a gate blind to a required surface is a silent false-green. (Set SATELLITE_HTML_DIR, or run this root where its repo is checked out.)`);
    }
    // Each run scans only the root(s) it asserts (registry v1.1: "a run asserts its OWN root"), so a
    // local run sees exactly what CI sees.
    if (asserted) reachable.push(...present);
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
  console.log(`claim-sweep: registry ${registryClaims.length} claims (never ${byKind('never')} · gated ${byKind('gated')} · test_gated ${byKind('test_gated')} · hedge_required ${byKind('hedge_required')} · caveat_required ${byKind('caveat_required')} · allowed ${byKind('allowed')})`);
  const rootless = registryClaims.filter((c) => c.kind !== 'allowed' && !c.scan_root).map((c) => c.id);
  if (rootless.length) console.log(`  ⚠ no scan_root (applied to EVERY root, fail-closed): ${rootless.join(', ')}`);

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
    const r = scanText(rf.rel, readFileSync(rf.abs, 'utf8'), compiled, ctx, rf.root);
    violations.push(...r.violations);
    honored.push(...r.honored);
  }

  // order rows (fail-closed: a malformed row is a config error; any regressed site ship-blocks)
  let orderFails: OrderFailure[];
  let orderCount: number;
  try {
    const raw = JSON.parse(readFileSync(REGISTRY_PATH, 'utf8')) as { order_rows?: unknown };
    const rows = validateOrderRows(raw.order_rows); // shape, then every REQUIRED_ORDER_IDS present (default ON; deleting a row alone = exit 2)
    orderCount = rows.length;
    const repo = resolve(REGISTRY_PATH, '..', '..');
    orderFails = checkOrderRows(rows, (p) => {
      const abs = resolve(repo, p);
      return existsSync(abs) ? readFileSync(abs, 'utf8') : null;
    });
  } catch (e) {
    if (e instanceof OrderConfigError) configError(`order rows: ${e.message}`);
    throw e;
  }
  console.log(`  order rows: ${orderCount} (${orderFails.length === 0 ? 'every pinned site holds' : `${orderFails.length} FAILED`}; they protect these sites only, not new ones)`);

  console.log(`\nhonored claim-sweep:ok annotations: ${honored.length}`);
  for (const h of honored) console.log(`  ${h.file}:${h.line}  [${h.claimId}]  annotation @${h.annotationLine}: "${h.reason}"`);

  if (violations.length === 0 && orderFails.length === 0) {
    console.log(`\n✅ claim-sweep PASS — ${files.length} files, ${enforced.length} enforced claims, ${orderCount} order rows: no registered claim violations.`);
    process.exit(0);
  }
  for (const f of orderFails) console.error(`  ❌ order ${f.id} step ${f.step} at ${f.at}`);
  console.error(`\n❌ claim-sweep SHIP-BLOCK — ${violations.length} registered claim violation(s), ${orderFails.length} order row failure(s):\n`);
  const claimText = new Map(registryClaims.map((c) => [c.id, c.claim]));
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  [${v.claimId} · ${v.kind}]  ${v.evidence.map((e) => `"${e}"`).join(', ')}`);
    console.error(`      ${v.reason}`);
    console.error(`      → ${claimText.get(v.claimId)}\n`);
  }
  process.exit(1);
}

main();
