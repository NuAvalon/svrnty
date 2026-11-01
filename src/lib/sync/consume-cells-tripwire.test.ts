// #720 T5 / contract v5 F5 (Flint #186298 T5, S62 C6/A7): uniform-frame cells (resync, consent-delta, distress, cover) NEVER produce a
// dead-letter row, a count or a receipt.
//
// WHY THIS IS A TRIPWIRE AND NOT A CLASSIFIER. Today F5 holds because cells never reach this path: uniform-frame.ts has no non-test importer,
// cells are built only in affirm-sync.ts and ride onion-transport to a satellite route, and nothing here opens one. A cell is built to be
// indistinguishable from any blob that cannot be opened, so the consume path CANNOT recognise one by shape: if one ever landed in this
// mailbox it would get an unknown-format verdict row. The rule therefore has to be enforced where a cell is OPENED, before it is wired
// in. This test goes RED the day the consume path starts to import the cell machinery, so that wiring cannot happen silently.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const CELL_MODULES = ['uniform-frame', 'onion-transport', 'onion-envelope', 'distress-cadence', 'distress-mark', 'consent-delta', 'route-ratchet'];
// The files that decide what happens to an envelope on the receive path, and the held/retry machinery they own.
const RECEIVE_PATH = ['consume-mailbox.ts', 'live-book-poll.ts', 'dead-letter.ts', 'hold-backoff.ts'];

const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const importsOf = (src: string) => [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);

test('F5 tripwire: the receive path imports none of the uniform-frame / onion / distress / consent-delta modules (so no cell can reach the held or dead-letter path unnoticed)', () => {
  for (const f of RECEIVE_PATH) {
    const src = stripComments(readFileSync(new URL(`./${f}`, import.meta.url), 'utf8'));
    const hits = importsOf(src).filter((spec) => CELL_MODULES.some((m) => spec.endsWith(`/${m}`) || spec.endsWith(`/${m}.js`) || spec === m));
    assert.deepEqual(hits, [], `${f} now imports cell machinery (${hits.join(', ')}). Contract v5 F5: a uniform-frame cell must never produce a dead-letter row, a count or a receipt. Implement that where the cell is OPENED, with a NEG per cell type, BEFORE wiring it into the receive path; then update this test.`);
  }
});

test('F5 tripwire control: the scan does find an import when there is one (the test is not passing on an empty match)', () => {
  const fake = stripComments(`import { frameUniform } from '@/lib/crypto/uniform-frame';\nimport { x } from "./onion-transport.js";\n// import { y } from './distress-mark';\n`);
  const hits = importsOf(fake).filter((spec) => CELL_MODULES.some((m) => spec.endsWith(`/${m}`) || spec.endsWith(`/${m}.js`) || spec === m));
  assert.deepEqual(hits, ['@/lib/crypto/uniform-frame', './onion-transport.js'], 'a commented-out import is ignored, real ones are caught');
});
