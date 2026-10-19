#!/usr/bin/env node
/**
 * Regression harness for provenance-check.mjs (v0). Pins the path→tier classifier + the
 * field/authz well-formedness rules so a future edit to the gate can't silently weaken it.
 * Run: `node .github/scripts/provenance-check.test.mjs` (exits non-zero on any failure).
 * (Athena; schema per Archie #172575/#172693 + Flint #172583/#172676.)
 */
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HOOK = fileURLToPath(new URL('./provenance-check.mjs', import.meta.url));
const full = (auth) => `## Provenance
- **Change:** refine X
- **Impact:** subsystem Y
- **Origin:** Peter #172575
- **Authorized-by:** ${auth}
- **Blueprint:** n/a
`;
const run = (body, files) => {
  try {
    return execSync(`node ${HOOK}`, { env: { ...process.env, PR_BODY: body, CHANGED_FILES: files.join('\n') }, encoding: 'utf8' });
  } catch (e) { return 'NONZERO-EXIT:' + (e.stdout || '') + (e.stderr || ''); }
};
const tierOf = o => (o.match(/tier=(\w+)/) || [])[1];
const warns = o => (o.match(/::warning/g) || []).length;

let pass = 0, fail = 0;
function check(name, out, wantTier, wantWarns) {
  const t = tierOf(out), w = warns(out);
  const ok = t === wantTier && (wantWarns === 'any' ? true : w === wantWarns);
  console.log(`${ok ? '✅' : '❌'} ${name}: tier=${t} warns=${w} (want tier=${wantTier} warns=${wantWarns})`);
  if (!ok) { fail++; console.log('   OUT:', out.replace(/\n/g, ' ⏎ ').slice(0, 300)); } else pass++;
}

// --- field/authz rules ---
check('consequential + Peter #id complete', run(full('Peter #172501 (2026-10-17)'), ['src/lib/crypto/envelope.ts']), 'consequential', 0);
check('consequential + self → warn', run(full('self'), ['src/lib/crypto/envelope.ts']), 'consequential', 2);
check('consequential + bare-Peter → warn', run(full('Peter'), ['src/lib/trust/trust-graph.ts']), 'consequential', 2);
check('consequential + Peter + date → ok', run(full('Peter 2026-10-17'), ['src/lib/identity/keys.ts']), 'consequential', 0);
check('consequential missing fields → warns', run('## Provenance\n- **Change:** x\n- **Origin:** Peter #1\n', ['src/lib/crypto/x.ts']), 'consequential', 'any');

// --- tier classification (standard svrnty layout) ---
check('trivial (md + test)', run(full('self'), ['README.md', 'src/lib/foo.test.ts']), 'trivial', 0);
check('standard (UI component)', run(full('self'), ['src/components/Foo.tsx']), 'standard', 0);
check('author-notes.md NOT consequential (Flint FP fix)', run(full('self'), ['author-notes.md']), 'trivial', 0);
check('blueprint.md consequential (precedence)', run(full('Peter #1 2026-10-17'), ['blueprint_v2.8.7_canonical.md']), 'consequential', 0);
check('transport chokepoint: sync/consume-mailbox.ts', run(full('Peter #1 2026-10-17'), ['src/lib/sync/consume-mailbox.ts']), 'consequential', 0);
// A test file UNDER a consequential crypto-family dir stays consequential (dir-precedence over
// *.test trivial) — fail-safe over-classification, consistent with how src/lib/crypto/** already
// treats its own tests. A test OUTSIDE those dirs (e.g. src/lib/foo.test.ts) is still trivial.
check('sync/consume-mailbox.test.ts → consequential (dir precedence, fail-safe)', run(full('Peter #1 2026-10-17'), ['src/lib/sync/consume-mailbox.test.ts']), 'consequential', 0);
check('components/notes/notes-send.ts', run(full('Peter #1 2026-10-17'), ['src/components/notes/notes-send.ts']), 'consequential', 0);
check('.github/workflows', run(full('Peter #1 2026-10-17'), ['.github/workflows/ci.yml']), 'consequential', 0);
check('docker-compose.yml', run(full('Peter #1 2026-10-17'), ['docker-compose.yml']), 'consequential', 0);
check('mixed crypto+md → consequential', run(full('Peter #1 2026-10-17'), ['src/lib/crypto/x.ts', 'NOTES.md']), 'consequential', 0);

// --- promote-both (Archie #172693 / Flint #172676) ---
check('gate-script itself (.github/scripts/**) → consequential', run(full('Peter #172693 2026-10-17'), ['.github/scripts/provenance-check.mjs']), 'consequential', 0);
check('crypto-outside-crypto: messaging/seal.ts → consequential', run(full('Peter #1 2026-10-17'), ['src/lib/messaging/seal.ts']), 'consequential', 0);
check('crypto-outside-crypto: messaging/note-auth.ts → consequential', run(full('Peter #1 2026-10-17'), ['src/lib/messaging/note-auth.ts']), 'consequential', 0);
check('src/lib/sync/** dir → consequential', run(full('Peter #1 2026-10-17'), ['src/lib/sync/robust-db.ts']), 'consequential', 0);
check('plain messaging file (ring.ts) stays standard', run(full('self'), ['src/lib/messaging/ring.ts']), 'standard', 0);

console.log(`\n== ${pass} passed, ${fail} failed ==`);
process.exit(fail ? 1 : 0);
