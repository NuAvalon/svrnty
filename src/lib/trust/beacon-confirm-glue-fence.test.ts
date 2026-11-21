// src/lib/trust/beacon-confirm-glue-fence.test.ts: SOURCE-SHAPE pins for the confirm glue and its wiring (the behaviour is in beacon-confirm-glue.test.ts).
// Run: npx tsx --test src/lib/trust/beacon-confirm-glue-fence.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
const GLUE = strip(readFileSync('src/lib/trust/beacon-confirm-glue.ts', 'utf8'));
const WIRING = strip(readFileSync('src/lib/trust/beacon-confirm-wiring.ts', 'utf8'));
const froms = (s: string): string[] => [...s.matchAll(/(?:from|import)\s*\(?\s*'([^']+)'/g)].map((m) => m[1]);
function walk(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (n === 'node_modules' || n === '.next' || n === '.git') continue;
    if (statSync(p).isDirectory()) walk(p, out); else if (/\.(ts|tsx)$/.test(n)) out.push(p);
  }
  return out;
}

test('CG1 the glue imports only the session and the code module, and touches no store, network, storage, clipboard or console', () => {
  assert.deepEqual(froms(GLUE).sort(), ['./beacon-confirm-code', './beacon-confirm-session']);
  assert.doesNotMatch(GLUE, /\bconsole\b|localStorage|sessionStorage|indexedDB|\bfetch\s*\(|XMLHttpRequest|\bnavigator\b|\bdocument\b|\bwindow\b|postMessage|BroadcastChannel|WebSocket|clipboard|Math\.random|\brequire\s*\(|\bimport\s*\(/);
});

test('CG2 the only write goes through the port and only inside the contact lock; the keys are read inside it at every entry', () => {
  assert.equal((GLUE.match(/writeConfirmed\(/g) ?? []).length, 2, 'the port declaration and the one call');
  const enter = GLUE.slice(GLUE.indexOf('async enter('), GLUE.indexOf('drop,\n'));
  const lockAt = enter.indexOf('withContactLock'), readAt = enter.indexOf('readKeys('), writeAt = enter.indexOf('writeConfirmed(');
  assert.ok(lockAt > 0 && readAt > lockAt && writeAt > readAt, 'lock, then the read of the keys, then the write');
  assert.equal((enter.match(/readKeys\(/g) ?? []).length, 1);
  assert.doesNotMatch(enter, /\bkeys\b[^;\n]*\bstart\b|startKeys/, 'no keys kept from the start are used at the entry');
});

test('CG3 the hook is registered once, at creation, and does nothing but end the session', () => {
  assert.equal((GLUE.match(/onLock\(/g) ?? []).length, 2, 'the port declaration and the one registration');
  const create = GLUE.slice(GLUE.indexOf('export function createConfirmGlue'));
  assert.ok(create.indexOf('ports.onLock(drop)') > 0 && create.indexOf('ports.onLock(drop)') < create.indexOf('async function readKeys'), 'registered once, before any session exists');
});

test('CG4 the wiring: strict own-key reader (never the creating one), the safety-write contact lock, the one writer, and the store hook; and nothing imports it yet', () => {
  assert.deepEqual(froms(WIRING).sort(), ['../contacts/safety-write', '../identity/beacon-key-record', '../identity/client-store', './beacon-confirm-glue']);
  assert.match(WIRING, /readBeaconKeyRecord\(ownerFingerprint\)/);
  assert.match(WIRING, /publicKey: await publicKeyOf\(r\.record\), generation: r\.record\.key_generation/, 'the own key and ITS generation');
  assert.match(WIRING, /publicKey: c\.beacon_public_key, generation: c\.beacon_key_generation/, 'the held key and ITS generation');
  assert.match(WIRING, /markBeaconPairConfirmed\(ownerFingerprint, c\.fingerprint, generation\)/, 'the pair of the contact\'s fingerprint at the compared generation');
  assert.match(WIRING, /getAllContacts\(ownerFingerprint\)\)\.find\(\(c\) => c\.id === contactId\)/, 'the contact is the owner\'s own, found by id');
  assert.doesNotMatch(WIRING, /ensureBeaconKeyRecord|importBeaconKeyRecord|newBeaconKeyRecord|getBeaconKeyRecord/, 'it never creates or replaces a key');
  assert.match(WIRING, /withSafetyWrite\(contactId, run\)/);
  assert.equal((WIRING.match(/markBeaconPairConfirmed\(/g) ?? []).length, 1);
  assert.match(WIRING, /onLock: onSessionLock/);
  assert.doesNotMatch(WIRING, /\bconsole\b/);
  const importers = walk('src').concat(walk('app')).filter((f) => !/\.test\.(ts|tsx)$/.test(f) && !/beacon-confirm-wiring\.ts$/.test(f) && /from\s*'[^']*beacon-confirm-wiring'/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importers, [], 'dark: no app file imports the wiring (the screen adds the one importer, behind the beacon switch, with its own review)');
});

test('CG5 the glue is imported by the wiring only, and the session module by the glue only', () => {
  const importing = (re: RegExp, self: RegExp): string[] => walk('src').concat(walk('app')).filter((f) => !/\.test\.(ts|tsx)$/.test(f) && !self.test(f) && re.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importing(/from\s*'[^']*beacon-confirm-glue'/, /beacon-confirm-glue\.ts$/), ['src/lib/trust/beacon-confirm-wiring.ts']);
  assert.deepEqual(importing(/from\s*'[^']*beacon-confirm-session'/, /beacon-confirm-session\.ts$/), ['src/lib/trust/beacon-confirm-glue.ts']);
});
