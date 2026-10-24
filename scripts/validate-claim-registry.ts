#!/usr/bin/env tsx
// scripts/validate-claim-registry.ts — in-repo port of Hypatia's validate_registry.cjs (claim registry v1.1).
//
// Validates scripts/claim-registry.json against (a) the detectors it names (scripts/claim-detectors.ts),
// (b) THIS repo's src/lib/claim-gates.ts, (c) its own examples, (d) Oct-3 CLAIM_MAP coverage. Exit non-zero
// on any failure. Same checks, same control flow and same counting as the v1.1 original (✅ 734 checks with
// gates, 719 without, at main f9841a4 / dev e2b5d82). Differences, all fail-closed:
//   • paths are repo-relative (registry, detectors, claim-gates.ts) — no /app paths;
//   • claim-gates.ts is checked BY DEFAULT and is REQUIRED (missing file = failure). `--no-gates` exists only
//     to reproduce the original's no-path count and prints that gates were NOT checked.
// The v1 skip-bug (gated rows `continue`d past their example checks when the gate path was absent or the
// gate was missing, while still printing ✅) is fixed here exactly as in v1.1: the gate block returns from
// an inner function, never skips the example checks.
// Usage (repo root): npx --no-install tsx scripts/validate-claim-registry.ts [--registry=<json>] [--gates=<ts>] [--no-gates]
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { REPO_ROOT, REGISTRY_PATH, normalize as norm, type Registry, type RegistryClaim } from './claim-sweep-lib';
import * as det from './claim-detectors';

const arg = (k: string) => process.argv.find((a) => a.startsWith(`--${k}=`))?.slice(k.length + 3);
const regPath = arg('registry') ? resolve(arg('registry') as string) : REGISTRY_PATH;
const noGates = process.argv.includes('--no-gates');
const gatesPath = arg('gates') ? resolve(arg('gates') as string) : resolve(REPO_ROOT, 'src/lib/claim-gates.ts');

let fails = 0;
let checks = 0;
const fail = (m: string) => { fails++; console.log('FAIL ' + m); };
const ok = () => { checks++; };

type DetFn = (t: string) => { overclaim?: boolean; present?: boolean; hedged?: boolean };
const detectors = det as unknown as Record<string, DetFn | undefined>;

function main(): void {
  let reg: Registry;
  try {
    reg = JSON.parse(readFileSync(regPath, 'utf8')) as Registry;
  } catch (e) {
    console.log(`FAIL cannot read/parse registry ${regPath}: ${(e as Error).message}`);
    process.exit(1);
  }
  let gatesSrc: string | null = null;
  if (!noGates) {
    if (!existsSync(gatesPath)) {
      console.log(`FAIL claim-gates.ts not found at ${gatesPath}`);
      process.exit(1);
    }
    gatesSrc = readFileSync(gatesPath, 'utf8');
  }

  function matcher(c: RegistryClaim): ((t: string) => boolean) | null {
    const fns: Array<(t: string) => boolean> = [];
    if (c.detector) {
      const fn = detectors[c.detector];
      if (typeof fn !== 'function') { fail(`${c.id}: detector ${c.detector} not exported by claim-detectors.ts`); }
      else if (c.detector_mode === 'present_unhedged') fns.push((t) => { const r = fn(t); return !!r.present && !r.hedged; });
      else fns.push((t) => { const r = fn(t); if (!('overclaim' in r)) fail(`${c.id}: detector ${c.detector} returns no .overclaim; set detector_mode`); return !!r.overclaim; });
    }
    for (const src of c.patterns || []) {
      try { const re = new RegExp(src, 'i'); fns.push((t) => re.test(norm(t))); ok(); }
      catch (e) { fail(`${c.id}: regex does not compile in JS: ${src} (${(e as Error).message})`); }
    }
    if (!fns.length) return null;
    const rx = (arr: string[] | undefined, tag: string) => (arr || []).map((src) => { try { ok(); return new RegExp(src, 'i'); } catch { fail(`${c.id}: ${tag} regex does not compile: ${src}`); return /$^/; } });
    const excuses = c.kind === 'never' ? rx(c.disclaimer_phrases, 'disclaimer') : rx(c.hedge_phrases, 'hedge');
    // flag = matched AND not excused by THIS row's own phrases (same line). The gate is assumed FALSE here.
    return (t) => fns.some((f) => f(t)) && !excuses.some((re) => re.test(norm(t)));
  }

  const ms: Record<string, ((t: string) => boolean) | null> = {};
  for (const c of reg.claims) {
    ms[c.id] = matcher(c);
    if (['gated', 'hedge_required'].includes(c.kind) && !(c.hedge_phrases || []).length) fail(`${c.id}: ${c.kind} row has no hedge_phrases`); else ok();
    if (c.kind !== 'never' && c.disclaimer_phrases) fail(`${c.id}: disclaimer_phrases are for NEVER rows only`);
    if (c.kind === 'never' && c.hedge_phrases) fail(`${c.id}: NEVER rows take no hedge (use disclaimer_phrases for honest negations)`);
    if (c.kind === 'test_gated') for (const r of c.requires || []) {
      if (typeof r !== 'object' || r === null || !('test' in r) || !('resolved' in r)) fail(`${c.id}: requires must be [{file,test,invariant,resolved}]`); else ok();
    }
    for (const t of (c.examples && c.examples.disclaimer_ok) || []) { const m0 = ms[c.id]; if (m0 && m0(t)) fail(`${c.id}: disclaimer should pass "${t}"`); else ok(); }
    if (c.kind === 'caveat_required') {
      const cav = (c.required_caveat || []).map((s) => new RegExp(s, 'i'));
      const m0 = ms[c.id];
      const fileOk = (t: string) => !(m0 && m0(t)) || cav.some((re) => re.test(norm(t)));
      for (const t of c.caveat_examples?.pass ?? []) { if (fileOk(t)) ok(); else fail(`${c.id}: caveat file should PASS "${t}"`); }
      for (const t of c.caveat_examples?.fail ?? []) { if (!fileOk(t)) ok(); else fail(`${c.id}: caveat file should FAIL "${t}"`); }
    }
    // (v1 bug, fixed 1.1: this block used `continue`, which SKIPPED the example checks below for every gated row
    //  whenever no claim-gates.ts path was passed, or the gate was missing, while still printing ✅.)
    if (c.kind === 'gated' && gatesSrc) ((src: string) => {
      const m = src.match(new RegExp(`export function ${c.gate}\\(\\)[^{]*\\{\\s*return ([^;]+);`));
      const reexport = new RegExp(`export \\{[^}]*\\b${c.gate}\\b`).test(src);
      if (!m && !reexport) { fail(`${c.id}: gate ${c.gate} not found in claim-gates.ts`); return; }
      ok();
      if (m) {
        const lit = m[1].trim();
        if (lit === 'true' || lit === 'false') {
          if ((lit === 'true') !== c.gate_value_at_sha) fail(`${c.id}: gate_value_at_sha=${c.gate_value_at_sha} but claim-gates.ts returns ${lit}`); else ok();
        } else if (/process\.env\./.test(lit)) {
          // env-gated (e.g. NEXT_PUBLIC_*_LIVE === 'true'): the value is per-BUILD, not per-commit.
          if (c.gate_value_at_sha !== 'env') fail(`${c.id}: gate ${c.gate} is env-gated in claim-gates.ts; set gate_value_at_sha to "env"`); else ok();
        } else {
          // derived gate, e.g. isPQWireLive(){ return isPSIDiscoveryLive(); }
          const dep = reg.claims.find((x) => x.gate && lit.startsWith(x.gate + '('));
          if (dep && dep.gate_value_at_sha !== c.gate_value_at_sha) fail(`${c.id}: derived from ${dep.gate}=${dep.gate_value_at_sha} but recorded ${c.gate_value_at_sha}`); else ok();
        }
      }
    })(gatesSrc);
    const m = ms[c.id];
    for (const t of (c.examples && c.examples.over) || []) {
      if (!m) { fail(`${c.id}: has 'over' examples but no detector/patterns`); break; }
      if (m(t)) ok(); else fail(`${c.id}: should FLAG "${t}"`);
    }
    for (const t of (c.examples && c.examples.ok) || []) {
      if (m && m(t)) fail(`${c.id}: should NOT flag "${t}"`); else ok();
    }
  }
  // Cross-check: no 'allowed' or 'ok' example may be flagged by any NEVER claim.
  const nevers = reg.claims.filter((c) => c.kind === 'never' && ms[c.id]);
  for (const c of reg.claims) for (const t of (c.examples && c.examples.ok) || []) {
    for (const n of nevers) { if ((ms[n.id] as (t: string) => boolean)(t)) fail(`cross: "${t}" (${c.id} ok-example) is flagged by NEVER ${n.id}`); else ok(); }
  }
  // Allowed examples must pass EVERY row (gates assumed false): honest-now copy can never trip the sweep.
  for (const a of reg.claims.filter((c) => c.kind === 'allowed')) for (const t of (a.examples && a.examples.ok) || []) {
    for (const c of reg.claims) { const m = ms[c.id]; if (m && c.kind !== 'caveat_required') { if (m(t)) fail(`allowed: "${t}" (${a.id}) is flagged by ${c.id}`); else ok(); } }
  }
  // v1.1.3/4: an override reason without the override itself = a hold half-removed.
  for (const c of reg.claims) {
    if (c.override_reason && !('sweep_gate_override' in c)) fail(`${c.id}: override_reason present but sweep_gate_override missing (hold half-removed)`); else ok();
  }
  // Hard gates (principal/security holds) may not be silently removed. LIMIT: deleting a row's override AND its
  // reason AND its hard_gates entry is undetectable from inside the registry; that defence is CODEOWNERS.
  for (const h of reg.hard_gates || []) {
    const c = reg.claims.find((x) => x.id === h.id);
    if (!c) { fail(`hard gate ${h.id}: row missing`); continue; }
    if (c.sweep_gate_override !== h.requires_override) fail(`hard gate ${h.id} (${h.source}): sweep_gate_override must be ${h.requires_override}`); else ok();
    if (!c.override_reason) fail(`hard gate ${h.id}: override_reason missing`); else ok();
  }
  // Oct-3 coverage: no row of the Flint-blessed CLAIM_MAP v1.3 may be dropped.
  if (reg.oct3_coverage) {
    const ids = new Set(reg.claims.map((c) => c.id));
    const rows = Object.keys(reg.oct3_coverage);
    if (rows.length !== 18) fail(`oct3_coverage maps ${rows.length}/18 rows`); else ok();
    for (const [r, id] of Object.entries(reg.oct3_coverage)) { if (ids.has(id)) ok(); else fail(`oct3 row ${r} -> ${id} not in registry`); }
  }
  console.log(`${fails ? '❌' : '✅'} ${checks} checks, ${fails} failures, ${reg.claims.length} claims${gatesSrc ? '' : ' (gates NOT checked: --no-gates)'}`);
  process.exit(fails ? 1 : 0);
}

main();
