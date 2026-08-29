#!/usr/bin/env node
/** Snapshot compose formula source into archive/source/ */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dir = dirname(fileURLToPath(import.meta.url));
const root = join(__dir, '../..', '..', '..'); // unused; paths relative to cwd
void root;

const src = readFileSync(join(__dir, '../IdentitySeal.tsx'), 'utf8');
const lines = src.split('\n');

function extractFn(name) {
  const start = lines.findIndex((l) => l.includes(`export function ${name}(`));
  if (start < 0) throw new Error('missing ' + name);
  let docStart = start;
  while (docStart > 0 && lines[docStart - 1].trim().startsWith('*')) docStart--;
  if (docStart > 0 && lines[docStart - 1].trim().startsWith('/**')) docStart--;
  let depth = 0;
  let end = start;
  let seen = false;
  for (let i = start; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') {
        depth++;
        seen = true;
      }
      if (ch === '}') depth--;
    }
    if (seen && depth === 0) {
      end = i;
      break;
    }
  }
  return lines.slice(docStart, end + 1).join('\n') + '\n';
}

const commit = execSync('git rev-parse --short HEAD').toString().trim();
const header = `/**
 * FROZEN SNAPSHOT — do not edit to "improve" the live seal.
 * Live source while active: ../../IdentitySeal.tsx
 * Exists so Crystal / Growth / Organic formulas survive later experiments.
 * Frozen at: ${new Date().toISOString()}
 * Commit: ${commit}
 */

`;

const helpers = `// Shared helpers used by these composers live in IdentitySeal.tsx /
// sacred-geometry.ts at freeze time: PHI, PHI_INV, hexNibbles, fnv, pt, fmt,
// CRYSTAL_HABITS, HABIT_LABEL, sacredEntryFromFingerprint, composeSacredFigure,
// starPolygonPath.

`;

const outDir = join(__dir, 'source');
mkdirSync(outDir, { recursive: true });

const pieces = {
  'composePhiSeal.ts.txt': extractFn('composePhiSeal'),
  'composeOrganicSeal.ts.txt': extractFn('composeOrganicSeal'),
  'composeGrowthSeal.ts.txt': extractFn('composeGrowthSeal'),
};

for (const [file, body] of Object.entries(pieces)) {
  writeFileSync(join(outDir, file), header + helpers + body);
  console.log('wrote', file, `(${body.split('\n').length} lines)`);
}

writeFileSync(
  join(outDir, 'sacred-geometry.ts.txt'),
  header + readFileSync(join(__dir, '../sacred-geometry.ts'), 'utf8')
);
console.log('wrote sacred-geometry.ts.txt');

writeFileSync(
  join(outDir, 'README.md'),
  `# Frozen formula source

Plain-text snapshots of the compose grammars at freeze time (\`${commit}\`).

| File | Variant |
|------|---------|
| \`composePhiSeal.ts.txt\` | Crystal (\`phi\`) |
| \`composeGrowthSeal.ts.txt\` | Growth (post-Metatron) |
| \`composeOrganicSeal.ts.txt\` | Organic (Crystal clone + forks) |
| \`sacred-geometry.ts.txt\` | Catalog + figure path builders |

**Do not edit these to change live seals.** Edit \`IdentitySeal.tsx\` / \`sacred-geometry.ts\` instead. If you intentionally replace a frozen look, add \`archive/v2/\` rather than mutating these files.

Regenerate snapshots:
\`\`\`bash
node --import tsx src/components/identity/archive/freeze-source.ts
\`\`\`
`
);

console.log('done →', outDir);
