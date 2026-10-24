// scripts/claim-sweep-lib.ts — rule engine for the S42 claim-honesty gate (scripts/claim-sweep.ts).
//
// Pure (no process.exit, no gate import) so the excuse rules can be unit-tested with injected gate values
// (scripts/claim-sweep.test.ts). The CLI wires in the REAL src/lib/claim-gates.ts.
//
// SOURCE OF CLAIMS: scripts/claim-registry.json (Hypatia's svrnty claim registry v1.1 — content owner
// Hypatia; this repo reads it, never re-words it). Detectors named by the registry come from
// scripts/claim-detectors.ts (a faithful port of pq_overclaim.cjs).
//
// EXCUSE RULES (registry v1.1 `how_to_read`, mandatory — so the excuse paths can't reopen the NEVER list).
// A row FLAGS a line when one of its patterns / its detector matches the normalized line, and then:
//   never           → violation unless THIS row's `disclaimer_phrases` match the same line (listed honest
//                     negations, e.g. "not anonymous"). NO annotation ever excuses it.
//   gated           → excused iff the named claim-gates.ts function returns true, OR THIS row's
//                     `hedge_phrases` match the same line, OR a reasoned annotation.
//   hedge_required  → excused iff THIS row's `hedge_phrases` match the same line, OR a reasoned annotation.
//   test_gated      → excused iff every `requires` anchor is resolved:true AND present (checkRequires),
//                     OR THIS row's `hedge_phrases` match the same line, OR a reasoned annotation.
//   caveat_required → excused iff the same FILE carries one of `required_caveat`. NO annotation.
//   allowed         → negative controls; never matched, never flagged.
//   Annotation = `claim-sweep:ok <reason>` (or `claim-sweep:ok: <reason>`) on the same line or the line
//   directly above. A reasonless `claim-sweep:ok` is treated as NO annotation. Every honored annotation is
//   returned so the CLI prints it (count + file:line).
// SCOPE: a row applies to files of its `scan_root` (A/B). A row WITHOUT scan_root applies to EVERY root
// (fail-closed: a missing field must not silently exempt a surface).
import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { resolve, join, relative, sep } from 'path';
import * as detectors from './claim-detectors';

export const REPO_ROOT = resolve(__dirname, '..');
export const REGISTRY_PATH = resolve(REPO_ROOT, 'scripts/claim-registry.json');
export const QUARANTINE_PATH = resolve(REPO_ROOT, 'qa/quarantine.json');

export type Kind = 'never' | 'gated' | 'test_gated' | 'hedge_required' | 'caveat_required' | 'allowed';
const KINDS: readonly Kind[] = ['never', 'gated', 'test_gated', 'hedge_required', 'caveat_required', 'allowed'];
/** kinds a reasoned `claim-sweep:ok` annotation may excuse (registry how_to_read.annotations) */
const ANNOTATABLE: readonly Kind[] = ['gated', 'test_gated', 'hedge_required'];

export interface Requirement {
  file: string | null;
  test: string;
  invariant: string | null;
  resolved: boolean;
  [k: string]: unknown;
}

export interface RegistryClaim {
  id: string;
  kind: Kind;
  claim: string;
  scan_root?: string;
  detector?: string;
  detector_mode?: 'overclaim' | 'present_unhedged';
  patterns?: string[];
  gate?: string;
  gate_value_at_sha?: boolean | 'env';
  /** registry v1.1.3: if present, the sweep uses THIS instead of the claim-gates.ts value (a gate that is
   *  true in code without the capability being real must not excuse a claim; Peter hard gates use it too). */
  sweep_gate_override?: boolean;
  override_reason?: string;
  hedge_phrases?: string[];
  disclaimer_phrases?: string[];
  required_caveat?: string[];
  requires?: Requirement[];
  examples?: { over?: string[]; ok?: string[]; disclaimer_ok?: string[] };
  caveat_examples?: { pass: string[]; fail: string[] };
  [k: string]: unknown;
}

export interface Registry {
  claims: RegistryClaim[];
  oct3_coverage?: Record<string, string>;
  /** principal/security holds: each row must keep sweep_gate_override === requires_override (+ a reason). */
  hard_gates?: { id: string; source?: string; requires_override: boolean }[];
  [k: string]: unknown;
}

/** A misconfiguration (unparseable registry, unknown detector/gate/kind, bad regex). CLI → exit 2. */
export class ConfigError extends Error {}

export const normalize = detectors.normalize;

export function loadRegistry(path: string = REGISTRY_PATH): Registry {
  let reg: Registry;
  try {
    reg = JSON.parse(readFileSync(path, 'utf8')) as Registry;
  } catch (e) {
    throw new ConfigError(`cannot read/parse claim registry at ${path}: ${(e as Error).message}`);
  }
  if (!reg || !Array.isArray(reg.claims) || reg.claims.length === 0) {
    throw new ConfigError(`claim registry at ${path} has no claims — refusing to pass (would be fake-green)`);
  }
  return reg;
}

type DetectorResult = { overclaim?: boolean; present?: boolean; hedged?: boolean };

/**
 * Does the named detector flag `text` under the row's `detector_mode`?
 *   'overclaim' (default)  → result.overclaim; a detector whose result has NO overclaim field is a CONFIG ERROR
 *                            (the v1 bug: reading .overclaim off pqBadgeOverclaim was always undefined → never fired).
 *   'present_unhedged'     → result.present && !result.hedged (pqBadgeOverclaim / pqResistantIdentityOverclaim).
 */
export function detectorFlags(name: string, text: string, mode: RegistryClaim['detector_mode'] = 'overclaim'): boolean {
  const fn = (detectors as Record<string, unknown>)[name];
  if (typeof fn !== 'function') throw new ConfigError(`unknown detector "${name}" — not exported by scripts/claim-detectors.ts`);
  const res = (fn as (t: string) => DetectorResult)(text);
  if (mode === 'present_unhedged') return Boolean(res.present) && !res.hedged;
  if (mode !== 'overclaim') throw new ConfigError(`unknown detector_mode "${String(mode)}"`);
  if (!('overclaim' in res)) throw new ConfigError(`detector ${name} returns no .overclaim; the registry row must set detector_mode`);
  return Boolean(res.overclaim);
}

function compileList(id: string, tag: string, srcs: string[] | undefined): RegExp[] {
  return (srcs ?? []).map((src) => {
    try {
      return new RegExp(src, 'i');
    } catch (e) {
      throw new ConfigError(`${id}: ${tag} regex does not compile: ${src} (${(e as Error).message})`);
    }
  });
}

export interface CompiledClaim {
  claim: RegistryClaim;
  /** true when the registry gives this claim no patterns and no detector — the scanner cannot see it. */
  unenforceable: boolean;
  /** Evidence strings for every pattern/detector hit on this line (empty = no match). */
  match(line: string): string[];
  /** THIS row's same-line excuse phrases (hedge_phrases, or disclaimer_phrases for never) match the line. */
  excusedByPhrase(line: string): boolean;
  /** caveat_required: the FILE carries one of required_caveat. */
  fileHasCaveat(content: string): boolean;
  appliesTo(root: string): boolean;
}

export function compileClaim(c: RegistryClaim): CompiledClaim {
  if (!c || typeof c.id !== 'string') throw new ConfigError(`registry claim without an id: ${JSON.stringify(c)}`);
  if (!KINDS.includes(c.kind)) throw new ConfigError(`${c.id}: unknown kind "${String(c.kind)}" (expected ${KINDS.join('/')})`);
  const regs = compileList(c.id, 'pattern', c.patterns);
  if (c.kind === 'never' && c.hedge_phrases) throw new ConfigError(`${c.id}: NEVER rows take no hedge_phrases (disclaimer_phrases only)`);
  if (c.kind !== 'never' && c.disclaimer_phrases) throw new ConfigError(`${c.id}: disclaimer_phrases are for NEVER rows only`);
  const excuses = compileList(c.id, c.kind === 'never' ? 'disclaimer' : 'hedge', c.kind === 'never' ? c.disclaimer_phrases : c.hedge_phrases);
  if ((c.kind === 'gated' || c.kind === 'hedge_required') && excuses.length === 0) {
    throw new ConfigError(`${c.id}: ${c.kind} row has no hedge_phrases`);
  }
  const caveats = compileList(c.id, 'required_caveat', c.required_caveat);
  if (c.kind === 'caveat_required' && caveats.length === 0) throw new ConfigError(`${c.id}: caveat_required row has no required_caveat`);
  const detector = c.detector;
  const mode = c.detector_mode ?? 'overclaim';
  if (detector) detectorFlags(detector, '', mode); // existence + mode check → ConfigError
  return {
    claim: c,
    unenforceable: regs.length === 0 && !detector,
    match(line: string): string[] {
      const t = normalize(line);
      const ev: string[] = [];
      for (const re of regs) {
        const m = re.exec(t);
        if (m) ev.push(m[0]);
      }
      if (detector && detectorFlags(detector, line, mode)) ev.push(`detector:${detector}`);
      return ev;
    },
    excusedByPhrase(line: string): boolean {
      const t = normalize(line);
      return excuses.some((re) => re.test(t));
    },
    fileHasCaveat(content: string): boolean {
      const t = normalize(content);
      return caveats.some((re) => re.test(t));
    },
    appliesTo(root: string): boolean {
      return !c.scan_root || c.scan_root === root;
    },
  };
}

/** Compile every claim and check gated claims name a gate the caller can evaluate. */
export function compileRegistry(reg: Registry, hasGate: (name: string) => boolean): CompiledClaim[] {
  const seen = new Set<string>();
  return reg.claims.map((c) => {
    const cc = compileClaim(c);
    if (seen.has(c.id)) throw new ConfigError(`duplicate claim id ${c.id}`);
    seen.add(c.id);
    if (c.kind === 'gated') {
      if (typeof c.gate !== 'string' || !c.gate) throw new ConfigError(`${c.id}: kind=gated but no gate named`);
      if (!hasGate(c.gate)) throw new ConfigError(`${c.id}: gate "${c.gate}" is not exported by src/lib/claim-gates.ts`);
    }
    if ('sweep_gate_override' in c && typeof c.sweep_gate_override !== 'boolean') {
      throw new ConfigError(`${c.id}: sweep_gate_override must be a boolean`);
    }
    if (c.kind === 'test_gated' && !Array.isArray(c.requires)) throw new ConfigError(`${c.id}: test_gated row has no requires array`);
    return cc;
  });
}

// ---- annotations ----------------------------------------------------------------------------------

const ANNOTATION_RE = /claim-sweep:ok\b(.*)$/;

/**
 * null = no annotation on this line; {reason:null} = annotation present but REASONLESS (not honored).
 * Accepts `claim-sweep:ok <reason>` (registry v1.1 form) and `claim-sweep:ok: <reason>`; a trailing
 * comment closer (`*\/`, `*\/}`, `-->`) is not part of the reason; the reason must contain a letter/digit.
 */
export function parseAnnotation(line: string): { reason: string | null } | null {
  const m = ANNOTATION_RE.exec(line);
  if (!m) return null;
  let rest = m[1];
  if (rest.startsWith(':')) rest = rest.slice(1);
  else if (rest !== '' && !/^\s/.test(rest)) return { reason: null };
  const reason = rest.replace(/\s*(?:\*\/\s*\}?|-->)\s*$/, '').trim();
  return { reason: /[a-z0-9]/i.test(reason) ? reason : null };
}

// ---- test_gated anchors ---------------------------------------------------------------------------

export interface AnchorStatus {
  requirement: string;
  ok: boolean;
  why: string;
}

export interface AnchorIndex {
  /** repo-relative paths (forward slashes) of every *.test.* / *.spec.* file */
  files: string[];
  read(rel: string): string;
  quarantined: Set<string>;
}

/**
 * A `requires` entry ({file, test, invariant, resolved}) is satisfied iff resolved === true AND a test/spec
 * file with that path (or path suffix) exists, contains the test name verbatim, and is not in
 * qa/quarantine.json (the unified gate skips quarantined files, so their tests do not have to pass).
 * resolved:false (the anchor is not yet named in a real test file) → UNSATISFIED, without looking.
 * Running the anchors is NOT done here: src/**\/*.test.ts anchors are run by the unified gate step that
 * precedes this sweep in CI; e2e/*.spec.ts anchors are run only by ci.yml (not a required check).
 */
export function checkRequires(requires: Requirement[] | undefined, idx: AnchorIndex): AnchorStatus[] {
  if (!requires || requires.length === 0) {
    return [{ requirement: '(none listed)', ok: false, why: 'test_gated claim lists no requires anchors' }];
  }
  return requires.map((r) => {
    const label = `${r.file ?? '(no file)'} :: "${r.test}"${r.invariant ? ` (${r.invariant})` : ''}`;
    if (r.resolved !== true) return { requirement: label, ok: false, why: 'resolved:false — anchor not yet named in a real test file' };
    if (!r.file || !/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(r.file)) return { requirement: label, ok: false, why: 'resolved:true but file is not a test/spec path' };
    const file = r.file;
    const cands = idx.files.filter((f) => f === file || f.endsWith('/' + file));
    if (cands.length === 0) return { requirement: label, ok: false, why: `anchor file ${file} not found` };
    const live = cands.filter((f) => !idx.quarantined.has(f) && idx.read(f).includes(r.test));
    if (live.length) return { requirement: label, ok: true, why: `found in ${live.join(', ')}` };
    const quarantinedHit = cands.filter((f) => idx.quarantined.has(f) && idx.read(f).includes(r.test));
    if (quarantinedHit.length) return { requirement: label, ok: false, why: `anchor only in quarantined ${quarantinedHit.join(', ')}` };
    return { requirement: label, ok: false, why: `test name not found in ${cands.join(', ')}` };
  });
}

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'test-results', 'playwright-report', 'coverage', 'out', 'build']);

/** Recursively list files under `dir` (skipping build/vendor dirs) whose name passes `keep`. */
export function walkFiles(dir: string, keep: (name: string) => boolean, recursive = true): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const name of readdirSync(d)) {
      if (SKIP_DIRS.has(name)) continue;
      const abs = join(d, name);
      const st = statSync(abs);
      if (st.isDirectory()) { if (recursive) walk(abs); }
      else if (keep(name)) out.push(abs);
    }
  };
  walk(dir);
  return out.sort();
}

export function buildAnchorIndex(root: string = REPO_ROOT): AnchorIndex {
  const files = walkFiles(root, (n) => /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(n)).map((abs) => relative(root, abs).split(sep).join('/'));
  const quarantined = new Set<string>();
  if (existsSync(resolve(root, 'qa/quarantine.json'))) {
    const q = JSON.parse(readFileSync(resolve(root, 'qa/quarantine.json'), 'utf8')) as { quarantined?: Array<{ file?: string }> };
    for (const e of q.quarantined ?? []) if (e.file) quarantined.add(e.file);
  }
  return { files, quarantined, read: (rel) => readFileSync(resolve(root, rel), 'utf8') };
}

// ---- scanning -------------------------------------------------------------------------------------

export interface Violation {
  file: string;
  line: number;
  claimId: string;
  kind: Kind;
  evidence: string[];
  reason: string;
}

export interface HonoredAnnotation {
  file: string;
  line: number;
  annotationLine: number;
  claimId: string;
  reason: string;
}

export interface EvalContext {
  gateValue(name: string): boolean;
  /** precomputed anchor status for test_gated claims, keyed by claim id */
  requiresOk(claimId: string): boolean;
}

/**
 * Lines that are PURE comments (not user-facing copy) are skipped so the gate doesn't cry wolf on dev
 * comments. Tracks /* *\/ blocks and lines whose trimmed form starts with // or *. (Carried over verbatim
 * from the Oct-18 v1 runner; an inline trailing // on a copy line is still scanned.)
 */
const LOG_CALL = /^(console|logger)\.(log|info|warn|error|debug|trace)\s*\(/;

export function commentMask(lines: string[]): boolean[] {
  const isComment: boolean[] = [];
  let inBlock = false;
  for (const raw of lines) {
    const t = raw.trim();
    let comment = false;
    if (inBlock) { comment = true; if (t.includes('*/')) inBlock = false; }
    else if (t.startsWith('/*')) { comment = true; if (!t.includes('*/')) inBlock = true; }
    else if (t.startsWith('//') || t.startsWith('*')) { comment = true; }
    // Developer log calls are not user-facing copy (Archie/Hypatia S42 ruling (2), 2026-10-24): skip a
    // line that STARTS a console.*/logger.* call. Continuation lines of a multi-line call are still
    // scanned (fail-closed); copy that reaches the user (JSX, toasts, alerts) is never skipped.
    else if (LOG_CALL.test(t)) { comment = true; }
    isComment.push(comment);
  }
  return isComment;
}

export function scanText(
  file: string,
  content: string,
  claims: CompiledClaim[],
  ctx: EvalContext,
  root = 'A',
): { violations: Violation[]; honored: HonoredAnnotation[] } {
  const lines = content.split(/\r?\n/);
  const isComment = commentMask(lines);
  const violations: Violation[] = [];
  const honored: HonoredAnnotation[] = [];
  const active = claims.filter((cc) => cc.claim.kind !== 'allowed' && !cc.unenforceable && cc.appliesTo(root));
  const caveatCache = new Map<string, boolean>();
  for (let i = 0; i < lines.length; i++) {
    if (isComment[i]) continue;
    const line = lines[i];
    const here = parseAnnotation(line);
    const above = i > 0 ? parseAnnotation(lines[i - 1]) : null;
    const annotation = here?.reason ? { reason: here.reason, at: i + 1 } : above?.reason ? { reason: above.reason, at: i } : null;
    const reasonless = !annotation && (here !== null || above !== null);
    for (const cc of active) {
      const c = cc.claim;
      const evidence = cc.match(line);
      if (evidence.length === 0) continue;
      const push = (reason: string) => violations.push({ file, line: i + 1, claimId: c.id, kind: c.kind, evidence, reason });
      if (c.kind === 'never') {
        if (cc.excusedByPhrase(line)) continue; // a listed honest negation (disclaimer_phrases), same line
        const extra = annotation || reasonless ? ' (a claim-sweep:ok annotation does NOT excuse kind=never)' : '';
        push(`kind=never: forbidden at any scope — only this row's listed disclaimer phrases pass${extra}`);
        continue;
      }
      if (c.kind === 'caveat_required') {
        if (!caveatCache.has(c.id)) caveatCache.set(c.id, cc.fileHasCaveat(content));
        if (caveatCache.get(c.id)) continue;
        push('kind=caveat_required: this FILE carries none of the required caveats (annotations do not apply)');
        continue;
      }
      let why = '';
      if (cc.excusedByPhrase(line)) continue;
      if (c.kind === 'gated') {
        const gate = c.gate as string;
        const overridden = typeof c.sweep_gate_override === 'boolean';
        if (overridden ? c.sweep_gate_override : ctx.gateValue(gate)) continue;
        why = overridden
          ? `kind=gated: ${gate}() overridden to false by the registry (sweep_gate_override; see override_reason) and no same-line hedge phrase from this row`
          : `kind=gated: ${gate}()=false and no same-line hedge phrase from this row`;
      } else if (c.kind === 'test_gated') {
        if (ctx.requiresOk(c.id)) continue;
        why = 'kind=test_gated: requires anchors not satisfied and no same-line hedge phrase from this row';
      } else {
        why = 'kind=hedge_required: no same-line hedge phrase from this row';
      }
      let annotationNote = reasonless ? '; a REASONLESS claim-sweep:ok annotation is ignored (write `claim-sweep:ok <reason>`)' : '; no claim-sweep:ok annotation';
      if (annotation && ANNOTATABLE.includes(c.kind)) {
        // Gated rows (Flint lane:svrnty #195, Hypatia #277 review): the annotation must NAME this row's gate
        // AND that gate must be FALSE in code: a gate-guarded branch that can't render today. Never when the
        // registry overrides a gate that is TRUE in code (e.g. G-4 PSI): the branch DOES render.
        const gate = c.kind === 'gated' ? (c.gate as string) : null;
        const namesGate = !gate || new RegExp(`\\b${gate}\\b`).test(annotation.reason);
        const codeFalse = !gate || !ctx.gateValue(gate);
        if (namesGate && codeFalse) {
          honored.push({ file, line: i + 1, annotationLine: annotation.at, claimId: c.id, reason: annotation.reason });
          continue;
        }
        annotationNote = !namesGate
          ? `; the claim-sweep:ok annotation does not name this row's gate (${gate}), so it is NOT honored`
          : `; the claim-sweep:ok annotation is NOT honored: ${gate}() is TRUE in code (overridden to not-live), so the branch renders`;
      }
      push(`${why}${annotationNote}`);
    }
  }
  return { violations, honored };
}
