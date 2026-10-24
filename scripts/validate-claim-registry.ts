#!/usr/bin/env tsx
// scripts/validate-claim-registry.ts — in-repo port of Hypatia's validate_registry.cjs (claim registry v1).
//
// Validates scripts/claim-registry.json against (a) the detectors it names (scripts/claim-detectors.ts),
// (b) THIS repo's src/lib/claim-gates.ts, (c) its own examples. Exit non-zero on any failure.
// Same checks + same counting as the original (158 checks at aca4d4f). Differences, all fail-closed:
//   • paths are repo-relative (registry, detectors, claim-gates.ts) — no argv path, no /app paths;
//   • claim-gates.ts is REQUIRED (the original skipped gate checks when no path was given);
//   • detector results go through detectorFlags() (scripts/claim-sweep-lib.ts) — `.overclaim`, falling back
//     to `.present` for pqBadgeOverclaim / pqResistantIdentityOverclaim, which have no `overclaim` field
//     (the original read `.overclaim` only, so those two could never flag). No registry example exercises
//     them today, so the check count is unchanged.
// Usage (repo root): npx --no-install tsx scripts/validate-claim-registry.ts
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { REPO_ROOT, REGISTRY_PATH, ConfigError, loadRegistry, detectorFlags, normalize, type Registry, type RegistryClaim } from './claim-sweep-lib';
import * as det from './claim-detectors';

const GATES_PATH = resolve(REPO_ROOT, 'src/lib/claim-gates.ts');

let fails = 0;
let checks = 0;
const fail = (m: string) => { fails++; console.log('FAIL ' + m); };
const ok = () => { checks++; };

function main(): void {
  let reg: Registry;
  try {
    reg = loadRegistry(REGISTRY_PATH);
  } catch (e) {
    console.log(`FAIL ${(e as ConfigError).message}`);
    process.exit(1);
  }
  if (!existsSync(GATES_PATH)) {
    console.log(`FAIL claim-gates.ts not found at ${GATES_PATH}`);
    process.exit(1);
  }
  const gatesSrc = readFileSync(GATES_PATH, 'utf8');

  function matcher(c: RegistryClaim): ((t: string) => boolean) | null {
    const fns: Array<(t: string) => boolean> = [];
    if (c.detector) {
      const name = c.detector;
      if (typeof (det as Record<string, unknown>)[name] !== 'function') { fail(`${c.id}: detector ${name} not exported by claim-detectors.ts`); }
      else fns.push((t) => detectorFlags(name, t));
    }
    for (const src of c.patterns || []) {
      try { const re = new RegExp(src, 'i'); fns.push((t) => re.test(normalize(t))); ok(); }
      catch (e) { fail(`${c.id}: regex does not compile in JS: ${src} (${(e as Error).message})`); }
    }
    return fns.length ? (t) => fns.some((f) => f(t)) : null;
  }

  const ms: Record<string, ((t: string) => boolean) | null> = {};
  for (const c of reg.claims) {
    ms[c.id] = matcher(c);
    if (c.kind === 'gated') {
      const m = gatesSrc.match(new RegExp(`export function ${c.gate}\\(\\)[^{]*\\{\\s*return ([^;]+);`));
      const reexport = new RegExp(`export \\{[^}]*\\b${c.gate}\\b`).test(gatesSrc);
      if (!m && !reexport) { fail(`${c.id}: gate ${c.gate} not found in claim-gates.ts`); continue; }
      ok();
      if (m) {
        const lit = m[1].trim();
        if (lit === 'true' || lit === 'false') {
          if ((lit === 'true') !== c.gate_value_at_sha) fail(`${c.id}: gate_value_at_sha=${c.gate_value_at_sha} but claim-gates.ts returns ${lit}`); else ok();
        } else {
          // derived gate, e.g. isPQWireLive(){ return isPSIDiscoveryLive(); }
          const dep = reg.claims.find((x) => x.gate && lit.startsWith(x.gate + '('));
          if (dep && dep.gate_value_at_sha !== c.gate_value_at_sha) fail(`${c.id}: derived from ${dep.gate}=${dep.gate_value_at_sha} but recorded ${c.gate_value_at_sha}`); else ok();
        }
      }
    }
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
  console.log(`${fails ? '❌' : '✅'} ${checks} checks, ${fails} failures, ${reg.claims.length} claims`);
  process.exit(fails ? 1 : 0);
}

main();
