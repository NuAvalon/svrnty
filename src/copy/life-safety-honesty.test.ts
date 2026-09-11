// Life-safety honesty: Distress / panic-send / emergency-send must not appear in
// render-glass UI (app + components). No placeholder, no "coming soon" — the
// feature is unmounted, not implied as working or imminent.
// Queue #1 (distress-button removal). Does NOT touch src/lib/trust/ (fleet).
// Run: npx tsx --test src/copy/life-safety-honesty.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCAN = ['app', 'src/components'];
const FORBIDDEN = /\bdistress\b|panic[\s-]?send|emergency[\s-]?send/i;
const FILE_OK = /\.(ts|tsx|js|jsx|css|md)$/;
const SKIP = /\.(test|spec)\.(ts|tsx|js|jsx)$/;

function walk(dir: string, out: string[]) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.git') continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else if (FILE_OK.test(name) && !SKIP.test(name)) out.push(p);
  }
}

test('UI copy has zero distress / panic-send / emergency-send references', () => {
  const files: string[] = [];
  for (const rel of SCAN) walk(join(ROOT, rel), files);
  assert.ok(files.length > 20, `expected to scan UI sources, got ${files.length}`);

  const hits: string[] = [];
  for (const file of files) {
    const body = readFileSync(file, 'utf8');
    const lines = body.split(/\n/);
    lines.forEach((line, i) => {
      if (FORBIDDEN.test(line)) {
        hits.push(`${relative(ROOT, file)}:${i + 1}: ${line.trim()}`);
      }
    });
  }

  assert.deepEqual(
    hits,
    [],
    'Render-glass still mentions distress / panic-send / emergency-send. ' +
      'Life-safety honesty: remove the control and the copy — no Coming placeholder. ' +
      `hits=${JSON.stringify(hits, null, 2)}`,
  );
});
