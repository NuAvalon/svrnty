// src/lib/identity/client-store-owner-key-guard.test.ts — the static RATCHET for the owner-side wiring (Flint #7356 (4), #7376).
// client-store.ts has no runtime IndexedDB test here, so this reads the SOURCE: every export that takes an owner fingerprint is either WIRED
// (it resolves the owner string through ownerKey / ownerKeyAsync and never uses the raw parameter) or listed as PENDING. The R5 (owner
// rotation) merge gate is: PENDING is empty, plus a real rotated-owner run in the Playwright e2e. A new export that takes an owner fingerprint
// fails here until it is classified.
// Run: npx tsx --test src/lib/identity/client-store-owner-key-guard.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'client-store.ts'), 'utf8');

/** G2: the reserved encrypted settings records (the owner string is in the row key AND the AAD). */
const WIRED = [
  'getSuppressionRecord', 'setSuppressionRecord', 'getHeldAffirmatives', 'setHeldAffirmatives',
  'readDeliveryDefault', 'writeDeliveryDefault', 'writeDeliveryDefaultIfAbsent', 'readDeliveryDefaultMigrating',
  'markDeliveryRestored', 'markDeliveryDefaultUnknown',
];
/** Still to wire (step B worklist, shared outbox step_b_client_store_worklist_v0.md): G1 stores, G3 contacts, G4 issued codes and gate arrivals, G5 the active pointer. */
const PENDING = [
  'storeIdentity', 'loadIdentity', 'storeKey', 'loadKey', 'verifyPassphrase', 'deviceHoldsOwner', 'sessionOpensOwner', 'assertRestoreKeepsOwnerDomain',
  'storePQKeys', 'loadPQKeys', 'storeVault', 'loadVault', 'loadDeviceMailbox', 'initDeviceMailboxAtGenesis', 'storeShards', 'loadShards',
  'hasEncryptedKeys', 'getKeyEnvelopeFingerprint', 'exportAll',
  'addContact', 'getContactByFingerprint', 'getAllContacts', 'getContactBookIntegrity', 'searchContacts',
  'isCodeOutstanding', 'codeUnderCap', 'alreadyAccepted', 'issuedCodeChannel', 'issuedCodeSpent', 'markAcceptedInMap', 'recordAcceptedJoiner',
  'isOutstandingIssuedCode', 'loadGateArrivals', 'getGateArrival', 'enqueueGateArrival', 'removeGateArrival',
  'setActiveFingerprint',
  // found by THIS guard after the worklist script missed them (multi-line signatures, or the owner parameter not first): step_b worklist v1
  'getMyDeviceMailbox', 'storeDeviceMailbox', 'markShardGiven', 'recordIssuedGrowCode', 'importPlaintextContacts', 'importVaultContents', 'importVaultContentsReport',
];

const stripComments = (t: string) => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
const OWNER_PARAM = /^(ownerFingerprint|ownerFp|owner_fingerprint|fingerprint|fp|activeFingerprint)\b/;

/** Every exported function with an owner-fingerprint parameter, found the way the worklist was found. */
function ownerExports(): Map<string, { param: string; body: string }> {
  const out = new Map<string, { param: string; body: string }>();
  const re = /^export (?:async )?function (\w+)\s*(?:<[^>]*>)?\(([^)]*)\)[^{]*\{/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(SRC))) {
    const param = m[2].split(',').map((p) => p.trim()).find((p) => OWNER_PARAM.test(p));
    if (!param) continue;
    const start = m.index;
    const end = SRC.indexOf('\n}\n', start); // a top-level function ends at a closing brace in column 0
    out.set(m[1], { param: param.split(':')[0].trim().replace(/\?$/, ''), body: stripComments(SRC.slice(start, end < 0 ? SRC.length : end + 2)) });
  }
  return out;
}

test('G0 the worklist is complete: the exports that take an owner fingerprint are exactly WIRED + PENDING (a new one must be classified here)', () => {
  const found = [...ownerExports().keys()].sort();
  assert.deepEqual(found, [...WIRED, ...PENDING].sort());
  assert.equal(new Set([...WIRED, ...PENDING]).size, WIRED.length + PENDING.length, 'no function is in both lists');
  assert.equal(WIRED.length + PENDING.length, 54, 'the 54 of the step B worklist v1 (the v0 figure of 47 missed seven)');
});

test('G1 a WIRED function resolves the owner string and never uses the raw parameter; a PENDING one does not resolve yet (so the lists stay honest)', () => {
  const ex = ownerExports();
  const wiredCalls = new RegExp('\\b(' + WIRED.join('|') + ')\\(');
  for (const name of WIRED) {
    const { param, body } = ex.get(name)!;
    assert.match(body, /ownerKey(?:Async)?\(/, name + ' must call ownerKey / ownerKeyAsync');
    // remove the resolver calls and the signature, and calls that pass the raw parameter to ANOTHER wired function (it resolves again, idempotently)
    const sig = body.slice(0, body.indexOf('{') + 1);
    let rest = body.slice(sig.length).replace(new RegExp('ownerKey(?:Async)?\\(\\s*' + param + '\\s*\\)', 'g'), '');
    rest = rest.replace(new RegExp('\\b(?:' + WIRED.join('|') + ')\\(\\s*' + param + '\\b', 'g'), '');
    assert.ok(!new RegExp('\\b' + param + '\\b').test(rest), name + ' uses the raw owner parameter "' + param + '" outside the resolver');
  }
  for (const name of PENDING) assert.doesNotMatch(ex.get(name)!.body, /ownerKey(?:Async)?\(/, name + ' is listed PENDING but already resolves: move it to WIRED');
  assert.ok(wiredCalls.test('getSuppressionRecord('));
});

test('G2 one database-open path loads the alias copy; nothing else calls the loader; no other direct indexedDB.open', () => {
  const code = stripComments(SRC);
  assert.equal((code.match(/\bloadOwnerAliases\(/g) ?? []).length, 1, 'loadOwnerAliases is called in exactly one place (the DB-open path)');
  assert.match(code, /async function openDB\(\): Promise<IDBDatabase> \{[\s\S]*?isOwnerKeyLoaded\(\)[\s\S]*?loadOwnerAliases\(/, 'the one call is inside openDB');
  assert.equal((code.match(/indexedDB\.open\(/g) ?? []).length, 1, 'one raw indexedDB.open (openDBRaw)');
  assert.match(code, /function openDBRaw\(\)[\s\S]*?indexedDB\.open\(/);
  assert.doesNotMatch(code, /\bclearOwnerAliases\b/, 'the copy is not cleared on lock (ruling A)');
});

test('G3 the alias row is one plaintext settings key, read in a readonly transaction before any owner-keyed read, and a malformed row is not repaired', () => {
  const code = stripComments(SRC);
  assert.match(code, /const OWNER_ALIASES_KEY = 'owner_aliases';/);
  assert.match(code, /readOwnerAliasRow\(db: IDBDatabase\)[\s\S]*?db\.transaction\('settings', 'readonly'\)/);
  const fn = code.slice(code.indexOf('async function readOwnerAliasRow'), code.indexOf('let _ownerAliasLoad'));
  assert.doesNotMatch(fn, /txPut|\.put\(|\.add\(/, 'reading the row never writes it (no repair)');
  assert.match(code, /catch \(e\) \{\s*db\.close\(\);\s*throw e;/, 'a failed load closes the connection and surfaces the error');
});
