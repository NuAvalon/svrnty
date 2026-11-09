// Run: npx tsx --test src/components/card-version-writers.guard.test.ts
// Pins the wiring unit tests can't reach: no owner-email save may rebuild the identity from a copy held in memory, or it erases
// card_version and the next contact update is dropped by every recipient. A real browser run proves the behaviour; this keeps it wired.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const frontend = readFileSync(join(__dirname, 'SoverentityFrontend.tsx'), 'utf8');
const page = readFileSync(join(__dirname, '..', '..', 'app', 'page.tsx'), 'utf8');
const STALE = /\.\.\.identity\.identity,\s*email: value/;

test('no email save rebuilds the identity from the copy in memory', () => {
  assert.doesNotMatch(frontend, STALE);
  assert.doesNotMatch(page, STALE);
});

test('all three email saves go through the helper', () => {
  assert.equal(frontend.match(/await saveOwnerEmail\(fp, value, identity, \{ load: loadIdentity, store: storeIdentity \}\)/g)?.length, 2);
  assert.equal(page.match(/await saveOwnerEmail\(fp, value, identity, \{ load: loadIdentity, store: storeIdentity \}\)/g)?.length, 1);
});

test('a send tells the parent about the new version, so a remount cannot bring back the old copy', () => {
  assert.match(frontend, /await storeIdentity\(fp, bumped\);[^\n]*\n\s*setIdentity\(bumped\);\s*\n\s*onIdentityUpdate\?\.\(bumped\);/);
});
