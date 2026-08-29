#!/usr/bin/env node
/**
 * Freeze Crystal / Growth / Organic seals into archive/ (SVG + JSON fixtures).
 * Run: node --import tsx src/components/identity/archive/freeze-seals.ts
 *
 * Do NOT overwrite existing frozen grammars — add a new variant + new archive
 * folder instead when experimenting.
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  composePhiSeal,
  composeGrowthSeal,
  composeOrganicSeal,
} from '../IdentitySeal';

const __dir = dirname(fileURLToPath(import.meta.url));
const ACCENT = '#f9a825';
const ACCENT2 = '#c9a227';
const BG = '#0c0805';

const SAMPLES = [
  { id: '5fold', fp: '5408785bfc9f6fa84bb8e44c90c0c03eaaaaaaaa' },
  { id: '7fold', fp: 'b87f9458752e861638a866c6a9953f912d9a3d7a' },
  { id: '10fold', fp: '871c3fa218f7e66d7567689d25558ca1b6f20fe2' },
] as const;

type Line = { x1: number; y1: number; x2: number; y2: number; op: number; w: number };

function lineEl(c: Line, stroke: string) {
  return `<line x1="${c.x1}" y1="${c.y1}" x2="${c.x2}" y2="${c.y2}" stroke="${stroke}" stroke-opacity="${c.op}" stroke-width="${c.w}" />`;
}

function svgCrystalLike(
  g: ReturnType<typeof composePhiSeal> | ReturnType<typeof composeOrganicSeal>,
  label: string,
  facets: boolean
) {
  const rings = g.rings
    .map(
      (r, i) =>
        `<circle cx="50" cy="50" r="${r}" fill="none" stroke="${i % 2 === 0 ? ACCENT : ACCENT2}" stroke-opacity="${0.18 - i * 0.025}" stroke-width="${0.8 - i * 0.08}" />`
    )
    .join('\n');
  const sacred = (g.sacredPaths ?? [])
    .map(
      (p) =>
        `<path d="${p.d}" fill="none" stroke="${ACCENT}" stroke-opacity="${p.op}" stroke-width="${p.w}" stroke-linejoin="miter" />`
    )
    .join('\n');
  const ticks = g.ticks
    .map(
      (t) =>
        `<line x1="${t.x1}" y1="${t.y1}" x2="${t.x2}" y2="${t.y2}" stroke="${ACCENT}" stroke-opacity="${t.major ? 0.4 : 0.22}" stroke-width="${t.major ? 1 : 0.5}" />`
    )
    .join('\n');
  const facetsEl = facets
    ? g.facets
        .map(
          (d) =>
            `<path d="${d}" fill="none" stroke="${ACCENT}" stroke-opacity="0.55" stroke-width="0.65" />`
        )
        .join('\n')
    : '';
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="400" height="400">
  <title>${label}</title>
  <rect width="100" height="100" fill="${BG}"/>
  ${rings}
  <polygon points="${g.hexOuter}" fill="none" stroke="${ACCENT}" stroke-opacity="0.45" stroke-width="1.05" />
  <polygon points="${g.hexMid}" fill="none" stroke="${ACCENT}" stroke-opacity="0.32" stroke-width="0.8" />
  <polygon points="${g.hexInner}" fill="none" stroke="${ACCENT2}" stroke-opacity="0.22" stroke-width="0.7" />
  ${sacred}
  ${ticks}
  ${g.spines.map((c) => lineEl(c, ACCENT)).join('\n')}
  ${g.branches.map((c) => lineEl(c, ACCENT)).join('\n')}
  ${g.notches.map((c) => lineEl(c, ACCENT2)).join('\n')}
  ${facetsEl}
  <polygon points="${g.hexCore}" fill="none" stroke="${ACCENT}" stroke-opacity="0.8" stroke-width="1.1" />
  <circle cx="50" cy="50" r="${g.rCore}" fill="none" stroke="${ACCENT}" stroke-width="1.05" />
  <circle cx="50" cy="50" r="1.8" fill="none" stroke="${ACCENT}" stroke-width="1" />
</svg>
`;
}

function svgGrowth(g: ReturnType<typeof composeGrowthSeal>, label: string) {
  const rings = g.rings
    .map(
      (r, i) =>
        `<circle cx="50" cy="50" r="${r}" fill="none" stroke="${ACCENT2}" stroke-opacity="${0.1 - i * 0.02}" stroke-width="0.55" />`
    )
    .join('\n');
  const sacred = g.sacredPaths
    .map(
      (p) =>
        `<path d="${p.d}" fill="none" stroke="${ACCENT}" stroke-opacity="${p.op}" stroke-width="${p.w}" stroke-linejoin="miter" />`
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="400" height="400">
  <title>${label}</title>
  <rect width="100" height="100" fill="${BG}"/>
  ${rings}
  <polygon points="${g.hexOuter}" fill="none" stroke="${ACCENT}" stroke-opacity="0.28" stroke-width="0.85" />
  <polygon points="${g.hexMid}" fill="none" stroke="${ACCENT}" stroke-opacity="0.18" stroke-width="0.65" />
  ${sacred}
  ${g.spines.map((c) => lineEl(c, ACCENT)).join('\n')}
  ${g.branches.map((c) => lineEl(c, ACCENT)).join('\n')}
  ${g.notches.map((c) => lineEl(c, ACCENT2)).join('\n')}
  <polygon points="${g.hexCore}" fill="none" stroke="${ACCENT}" stroke-opacity="0.75" stroke-width="1.05" />
  <circle cx="50" cy="50" r="${g.rCore}" fill="none" stroke="${ACCENT}" stroke-width="1" />
  <circle cx="50" cy="50" r="1.8" fill="none" stroke="${ACCENT}" stroke-width="1" />
</svg>
`;
}

function fixtureSummary(
  name: string,
  g: {
    fold: number;
    figure: string;
    figureId: string;
    spines: unknown[];
    branches: unknown[];
    notches?: unknown[];
    rings: readonly number[];
    R: number;
    r1: number;
    r2: number;
  }
) {
  return {
    variant: name,
    fold: g.fold,
    figure: g.figure,
    figureId: g.figureId,
    spineCount: g.spines.length,
    branchCount: g.branches.length,
    notchCount: g.notches?.length ?? 0,
    rings: [...g.rings],
    R: g.R,
    r1: g.r1,
    r2: g.r2,
  };
}

mkdirSync(join(__dir, 'svg'), { recursive: true });
mkdirSync(join(__dir, 'fixtures'), { recursive: true });

const manifest = {
  frozenAt: new Date().toISOString(),
  note:
    'Crystal / Growth / Organic freeze. Do not overwrite — add new variants instead. Source commits: Growth≈21d858c, Crystal+droplets+ogham≈300d9a5, Organic≈4103523.',
  samples: [] as unknown[],
};

for (const sample of SAMPLES) {
  const crystal = composePhiSeal(sample.fp);
  const growth = composeGrowthSeal(sample.fp);
  const organic = composeOrganicSeal(sample.fp);

  writeFileSync(
    join(__dir, 'svg', `${sample.id}-crystal.svg`),
    svgCrystalLike(crystal, `Crystal · ${sample.id}`, true)
  );
  writeFileSync(
    join(__dir, 'svg', `${sample.id}-growth.svg`),
    svgGrowth(growth, `Growth · ${sample.id}`)
  );
  writeFileSync(
    join(__dir, 'svg', `${sample.id}-organic.svg`),
    svgCrystalLike(organic, `Organic · ${sample.id}`, true)
  );

  const fixture = {
    id: sample.id,
    fingerprint: sample.fp,
    crystal: fixtureSummary('crystal', crystal),
    growth: fixtureSummary('growth', growth),
    organic: fixtureSummary('organic', organic),
  };
  writeFileSync(join(__dir, 'fixtures', `${sample.id}.json`), JSON.stringify(fixture, null, 2) + '\n');
  manifest.samples.push(fixture);
}

writeFileSync(join(__dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('Froze', SAMPLES.length, 'fingerprints × 3 variants → archive/svg + archive/fixtures');
