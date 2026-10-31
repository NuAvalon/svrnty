// scripts/claim-sweep.map.ts
//
// SCAN-ROOT half of the launch-honesty copy-gate (#521 / Chaos #110 / S42). Schema = Athena (CI lane).
// Boundary ruling = Flint #157069 (containment/fail-closed/coverage).
//
// CLAIMS do not live here: scripts/claim-registry.json (Hypatia's svrnty claim registry v1.1) is the
// source of claims; each registry row names its `scan_root` (A/B). Gate values come from
// src/lib/claim-gates.ts (the scanner CALLS the gate; never a hardcoded guess).
//
// Roots follow the registry v1.1 `how_to_read.scan_root`:
//   A = svrnty src/ + app/ (svrnty CI)  ·  B = autobots infra/satellite/*.html (svrnty_deploy pre-deploy)
// Root A is the WHOLE source tree (not a hand-picked file list), so a renamed or new copy file can't
// silently leave the sweep. Test/spec files and type declarations are not shipped copy.

export interface ScanRoot {
  id: string;
  label: string;
  baseDir: string;            // relative to cwd (repo root); root B is cross-repo (autobots)
  dirs: string[];             // directories under baseDir
  recursive: boolean;         // walk subdirectories too
  include: (fileName: string) => boolean;
}

const isShippedSource = (n: string) =>
  /\.(?:ts|tsx)$/.test(n) && !/\.(?:test|spec)\.tsx?$/.test(n) && !n.endsWith('.d.ts');

// Two surface-roots in two repos (Archie #157051). Each run asserts its OWN root(s) via
// --assert-root; a required-but-unreachable (or empty) root = CONFIG-ERROR exit 2 (Flint: never silent-green).
export const SCAN_ROOTS: ScanRoot[] = [
  {
    id: 'A',
    label: 'svrnty source copy (src/ + app/, *.ts/*.tsx, tests excluded)',
    baseDir: '.',
    dirs: ['src', 'app'],
    recursive: true,
    include: isShippedSource,
  },
  {
    id: 'B',
    label: 'satellite static HTML (autobots infra/satellite/*.html)',
    baseDir: process.env.SATELLITE_HTML_DIR || '../autobots/infra/satellite',
    dirs: ['.'],
    recursive: false,           // registry: infra/satellite/*.html (top level)
    include: (n) => n.endsWith('.html'),
  },
];
