// scripts/claim-sweep.map.ts
//
// SCAN-ROOT half of the launch-honesty copy-gate (#521 / Chaos #110 / S42). Schema = Athena (CI lane).
// Boundary ruling = Flint #157069 (containment/fail-closed/coverage).
//
// CLAIMS no longer live here: the Oct-18 hand-written CLAIM_ROWS were REPLACED (S42, 2026-10-24) by
// scripts/claim-registry.json — Hypatia's svrnty claim registry v1 (content owner Hypatia; this repo reads
// it and never re-words it). Gate values still come from src/lib/claim-gates.ts (the scanner CALLS the
// gate; never a hardcoded guess).

export interface ScanRoot {
  id: string;
  label: string;
  baseDir: string;            // relative to cwd (repo root); root B is cross-repo (autobots)
  files: string[];
}

// Two surface-roots in two repos (Archie #157051). Each run asserts its OWN root(s) via
// --assert-root; a required-but-unreachable root = CONFIG-ERROR exit 2 (Flint: never silent-green).
export const SCAN_ROOTS: ScanRoot[] = [
  {
    id: 'A',
    label: 'svrnty frontend copy (Next.js) — the isXLive()-gated claims',
    baseDir: '.',
    files: ['app/page.tsx', 'src/components/Ceremony.tsx', 'src/components/JoinerCeremony.tsx', 'src/components/ContactShareDialog.tsx'],
  },
  {
    id: 'B',
    label: 'satellite static HTML (autobots infra/satellite) — the W-row/sovereignty caveats',
    baseDir: process.env.SATELLITE_HTML_DIR || '../autobots/infra/satellite',
    files: ['sovereignty.html', 'about.html'],
  },
];
