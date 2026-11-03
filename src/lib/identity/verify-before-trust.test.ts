// pt5 verify-before-trust SINK gate (survivor-safety — Peter #158030 "resistance between known and
// trusted" / Flint seal-criteria #158146 / Archie #92153). Trust promotion OR creation MUST require a
// REAL owner-verification. Gated BY CONSTRUCTION at the two write sinks (updateContact promotion +
// addContact creation) so no caller path (bulk-select Trust, TrustMap toggle, card dialog, import,
// future) can reach trusted-unverified. Static source guard (same style as blocker-c-failclosed.test.ts):
// the runtime enforces it via the throw; this test stops a future change from silently removing the gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');

function bodyOf(fn: string): string {
  const start = src.indexOf(`export async function ${fn}(`);
  assert.ok(start >= 0, `${fn} not found`);
  const body = src.slice(start, src.indexOf('\nexport ', start + 1));
  assert.ok(body.length > 0, `${fn} body empty`);
  return body;
}

// The promotion gate lives in finalizeContactUpdate, which the compare-and-swap runs on EVERY attempt before it encrypts and commits.
function gateBody(): string {
  const start = src.indexOf('async function finalizeContactUpdate(');
  assert.ok(start >= 0, 'finalizeContactUpdate not found');
  const body = src.slice(start, src.indexOf('\n}\n', start) + 3);
  assert.ok(body.length > 100, 'finalizeContactUpdate body empty');
  return body;
}
const casSrc = readFileSync(new URL('./contact-cas.ts', import.meta.url), 'utf8');

test('updateContact gates the unverified→trusted PROMOTION on a real owner-verify (fail-closed)', () => {
  const body = gateBody();
  assert.match(body, /verify-before-trust/, 'pt5 gate marker must be present');
  assert.match(body, /ownerHasVerified\(/, 'must check the real owner-verify');
  assert.match(body, /wasTrusted/, 'must gate the TRANSITION only (re-saving an already-trusted contact passes — non-regression)');
  assert.match(body, /throw new Error\(/, 'must throw (fail-closed) on an unverified promotion');
});

test('EVERY contact update path reaches that gate: updateContact and updateContactIf both run through the compare-and-swap, which finalizes each attempt before it encrypts', () => {
  assert.match(bodyOf('updateContact'), /casUpdateWith\(contactCasIO, /, 'updateContact goes through the compare-and-swap');
  assert.match(bodyOf('updateContactIf'), /casUpdateWith\(contactCasIO, /, 'updateContactIf (a new write path) goes through it too');
  assert.match(src, /finalize: finalizeContactUpdate,/, 'the store wires the gate in as the finalize step');
  const loop = casSrc.slice(casSrc.indexOf('export async function casUpdateWith'));
  const iFinalize = loop.indexOf('await io.finalize(existing, built)');
  const iEncrypt = loop.indexOf('await io.encrypt(next)');
  const iCommit = loop.indexOf('await io.commit(');
  assert.ok(iFinalize > 0 && iFinalize < iEncrypt && iEncrypt < iCommit, 'finalize runs before encrypt and commit, inside the attempt loop');
  assert.doesNotMatch(src.slice(src.indexOf('const contactCasIO'), src.indexOf('function assertUnlockedForContactWrite')), /finalize: \(\w+, \w+\) => \w+,/, 'the finalize step is not replaced by a pass-through');
});

test('addContact gates CREATING a trusted contact on a real owner-verify (fail-closed)', () => {
  const body = bodyOf('addContact');
  assert.match(body, /verify-before-trust/, 'pt5 gate marker must be present on the create path');
  assert.match(body, /ownerHasVerified\(/, 'must check the real owner-verify on create');
  assert.match(body, /throw new Error\(/, 'must throw (fail-closed) on an unverified trusted-create');
});

test('the gate reads the REAL owner-verify (ownerHasVerified), NOT the top-level trusted-since stamp', () => {
  // ownerHasVerified (trust-recipe) reads owner_verified_at / verification.verified_at(method in_person|
  // other_channel) — NEVER the top-level contact.verified_at a bare trust-toggle auto-stamps. The gate
  // must not be satisfiable by that stamp.
  assert.match(src, /import \{ ownerHasVerified \} from '\.\.\/trust\/trust-recipe'/, 'imports the real verify predicate');
  assert.doesNotMatch(gateBody(), /\.verified_at/, 'the promotion gate must not read a top-level verified_at stamp');
});
