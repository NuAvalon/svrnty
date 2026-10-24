// scripts/claim-sweep-lib.ts — rule engine for the S42 claim-honesty gate (scripts/claim-sweep.ts).
//
// Pure (no process.exit, no gate import) so the excuse rules can be unit-tested with injected gate values
// (scripts/claim-sweep.test.ts). The CLI wires in the REAL src/lib/claim-gates.ts.
//
// SOURCE OF CLAIMS: scripts/claim-registry.json (Hypatia's svrnty claim registry v1 — content owner
// Hypatia; this repo reads it, never re-words it). Detectors named by the registry come from
// scripts/claim-detectors.ts (a faithful port of pq_overclaim.cjs).
//
// EXCUSE RULES (registry owner, mandatory — so the excuse paths can't reopen the NEVER list):
//   kind=never      → FORBIDDEN, NO excuse: neither a same-line hedge nor a `claim-sweep:ok` annotation.
//   kind=gated      → excused iff the named claim-gates.ts function returns true, OR the line carries THIS
//                     entry's own hedge wording (not any hedge-ish word), OR a reasoned annotation.
//   kind=test_gated → excused iff every `requires` anchor is present (see checkRequires), OR a reasoned
//                     annotation.
//   kind=allowed    → negative controls; never matched, never flagged.
//   Annotation = `claim-sweep:ok: <reason>` on the same line or the line directly above. A reasonless
//   `claim-sweep:ok` (or `claim-sweep:ok:` with nothing after it) is treated as NO annotation. Every
//   honored annotation is returned so the CLI prints it (count + file:line).
import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { resolve, join, relative, sep } from 'path';
import * as detectors from './claim-detectors';

export const REPO_ROOT = resolve(__dirname, '..');
export const REGISTRY_PATH = resolve(REPO_ROOT, 'scripts/claim-registry.json');
export const QUARANTINE_PATH = resolve(REPO_ROOT, 'qa/quarantine.json');

export type Kind = 'never' | 'gated' | 'test_gated' | 'allowed';
const KINDS: readonly Kind[] = ['never', 'gated', 'test_gated', 'allowed'];

export interface RegistryClaim {
  id: string;
  kind: Kind;
  claim: string;
  detector?: string;
  patterns?: string[];
  gate?: string;
  gate_value_at_sha?: boolean;
  hedge?: string;
  requires?: string[];
  examples?: { over?: string[]; ok?: string[] };
  [k: string]: unknown;
}

export interface Registry {
  claims: RegistryClaim[];
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

type DetectorResult = { overclaim?: boolean; present?: boolean };

/**
 * Does the named detector flag `text`? Uses `.overclaim`; for the two detectors whose result has no
 * `overclaim` field (pqBadgeOverclaim, pqResistantIdentityOverclaim) it falls back to `.present`, which
 * those detectors document as the over-claim signal (and which their corpus asserts).
 */
export function detectorFlags(name: string, text: string): boolean {
  const fn = (detectors as Record<string, unknown>)[name];
  if (typeof fn !== 'function') throw new ConfigError(`unknown detector "${name}" — not exported by scripts/claim-detectors.ts`);
  const res = (fn as (t: string) => DetectorResult)(text);
  return res.overclaim !== undefined ? Boolean(res.overclaim) : Boolean(res.present);
}

/**
 * The registry's OWN hedge wording for a gated claim. The registry's `hedge` field is prose: when it
 * LEADS with quoted copy (G-2 `"signed with a post-quantum key" (…)`, G-5 `"blocked directly"`) the quoted
 * phrases are the hedge wording. When it leads with a parenthetical note (G-1 "(say nothing about PQ
 * messaging …)", G-4, G-6, G-7, G-8) it is guidance, not copy → NO hedge excuse exists for that claim
 * (fail-closed: G-1's note quotes "post-quantum-ready" as honest ONLY for identity key material, so it
 * must not excuse a PQ-messaging line).
 */
export function hedgePhrases(hedge: string | undefined): string[] {
  if (!hedge || !hedge.trim().startsWith('"')) return [];
  const out: string[] = [];
  for (const m of hedge.matchAll(/"([^"]+)"/g)) {
    const p = normalize(m[1]);
    if (p) out.push(p);
  }
  return out;
}

export interface CompiledClaim {
  claim: RegistryClaim;
  /** true when the registry gives this claim no patterns and no detector — the scanner cannot see it. */
  unenforceable: boolean;
  hedges: string[];
  /** Evidence strings for every pattern/detector hit on this line (empty = no match). */
  match(line: string): string[];
}

export function compileClaim(c: RegistryClaim): CompiledClaim {
  if (!c || typeof c.id !== 'string') throw new ConfigError(`registry claim without an id: ${JSON.stringify(c)}`);
  if (!KINDS.includes(c.kind)) throw new ConfigError(`${c.id}: unknown kind "${String(c.kind)}" (expected ${KINDS.join('/')})`);
  const regs: RegExp[] = [];
  for (const src of c.patterns ?? []) {
    try {
      regs.push(new RegExp(src, 'i'));
    } catch (e) {
      throw new ConfigError(`${c.id}: pattern does not compile: ${src} (${(e as Error).message})`);
    }
  }
  if (c.detector) detectorFlags(c.detector, ''); // existence check → ConfigError if unknown
  const detector = c.detector;
  return {
    claim: c,
    unenforceable: regs.length === 0 && !detector,
    hedges: c.kind === 'gated' ? hedgePhrases(c.hedge) : [],
    match(line: string): string[] {
      const t = normalize(line);
      const ev: string[] = [];
      for (const re of regs) {
        const m = re.exec(t);
        if (m) ev.push(m[0]);
      }
      if (detector && detectorFlags(detector, line)) ev.push(`detector:${detector}`);
      return ev;
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
    return cc;
  });
}

// ---- annotations ----------------------------------------------------------------------------------

const ANNOTATION_RE = /claim-sweep:ok\b(.*)$/;

/** null = no annotation on this line; {reason:null} = annotation present but REASONLESS (not honored). */
export function parseAnnotation(line: string): { reason: string | null } | null {
  const m = ANNOTATION_RE.exec(line);
  if (!m) return null;
  const rest = m[1];
  if (!rest.startsWith(':')) return { reason: null };
  const reason = rest.slice(1).replace(/\s*(?:\*\/\s*\}?|-->)\s*$/, '').trim();
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

const ANCHOR_RE = /^\s*(\S+\.(?:test|spec)\.[cm]?[jt]sx?)\s*::\s*"([^"]+)"/;

/**
 * A `requires` entry is satisfied iff it is a machine-checkable anchor `<file>.test.ts :: "<test name>"`,
 * a file with that path (or path suffix) exists, it contains the test name verbatim, and it is not in
 * qa/quarantine.json (the unified gate skips quarantined files, so their tests do not have to pass).
 * Anything else (prose like "Flint portal spec §6 tests (all)") cannot be verified → UNSATISFIED.
 * Running the anchors is NOT done here: src/**\/*.test.ts anchors are run by the unified gate step that
 * precedes this sweep in CI; e2e/*.spec.ts anchors are run only by ci.yml (not a required check).
 */
export function checkRequires(requires: string[] | undefined, idx: AnchorIndex): AnchorStatus[] {
  if (!requires || requires.length === 0) {
    return [{ requirement: '(none listed)', ok: false, why: 'test_gated claim lists no requires anchors' }];
  }
  return requires.map((req) => {
    const m = ANCHOR_RE.exec(req);
    if (!m) return { requirement: req, ok: false, why: 'not a machine-checkable anchor (expected `<file>.test.ts :: "<test name>"`)' };
    const [, file, name] = m;
    const cands = idx.files.filter((f) => f === file || f.endsWith('/' + file));
    if (cands.length === 0) return { requirement: req, ok: false, why: `anchor file ${file} not found` };
    const live = cands.filter((f) => !idx.quarantined.has(f) && idx.read(f).includes(name));
    if (live.length) return { requirement: req, ok: true, why: `found in ${live.join(', ')}` };
    const quarantinedHit = cands.filter((f) => idx.quarantined.has(f) && idx.read(f).includes(name));
    if (quarantinedHit.length) return { requirement: req, ok: false, why: `anchor only in quarantined ${quarantinedHit.join(', ')}` };
    return { requirement: req, ok: false, why: `test name not found in ${cands.join(', ')}` };
  });
}

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'test-results', 'playwright-report', 'coverage', 'out', 'build']);

export function buildAnchorIndex(root: string = REPO_ROOT): AnchorIndex {
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (SKIP_DIRS.has(name)) continue;
      const abs = join(dir, name);
      const st = statSync(abs);
      if (st.isDirectory()) walk(abs);
      else if (/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(name)) files.push(relative(root, abs).split(sep).join('/'));
    }
  };
  walk(root);
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
): { violations: Violation[]; honored: HonoredAnnotation[] } {
  const lines = content.split(/\r?\n/);
  const isComment = commentMask(lines);
  const violations: Violation[] = [];
  const honored: HonoredAnnotation[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (isComment[i]) continue;
    const line = lines[i];
    const here = parseAnnotation(line);
    const above = i > 0 ? parseAnnotation(lines[i - 1]) : null;
    const annotation = here?.reason ? { reason: here.reason, at: i + 1 } : above?.reason ? { reason: above.reason, at: i } : null;
    const reasonless = !annotation && (here !== null || above !== null);
    const normLine = normalize(line);
    for (const cc of claims) {
      const c = cc.claim;
      if (c.kind === 'allowed' || cc.unenforceable) continue;
      const evidence = cc.match(line);
      if (evidence.length === 0) continue;
      const push = (reason: string) => violations.push({ file, line: i + 1, claimId: c.id, kind: c.kind, evidence, reason });
      if (c.kind === 'never') {
        const extra = annotation || reasonless ? ' (a claim-sweep:ok annotation does NOT excuse kind=never)' : '';
        push(`kind=never: forbidden at any scope — no hedge or annotation excuses it${extra}`);
        continue;
      }
      let excused = false;
      let why = '';
      if (c.kind === 'gated') {
        const gate = c.gate as string;
        if (ctx.gateValue(gate)) excused = true;
        else if (cc.hedges.some((h) => normLine.includes(h))) excused = true;
        else why = `kind=gated: ${gate}()=false and no same-line hedge from this entry${cc.hedges.length ? ` (${cc.hedges.map((h) => `"${h}"`).join(' / ')})` : ' (entry has no hedge wording)'}`;
      } else if (c.kind === 'test_gated') {
        if (ctx.requiresOk(c.id)) excused = true;
        else why = 'kind=test_gated: requires anchors not satisfied';
      }
      if (excused) continue;
      if (annotation) {
        honored.push({ file, line: i + 1, annotationLine: annotation.at, claimId: c.id, reason: annotation.reason });
        continue;
      }
      push(`${why}${reasonless ? '; a REASONLESS claim-sweep:ok annotation is ignored (write `claim-sweep:ok: <reason>`)' : '; no claim-sweep:ok annotation'}`);
    }
  }
  return { violations, honored };
}
