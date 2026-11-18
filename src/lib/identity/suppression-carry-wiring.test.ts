// src/lib/identity/suppression-carry-wiring.test.ts
// STATIC guards for where the owner's suppression record and removed list travel. The identity store has no runtime IndexedDB test, so these read the SOURCE; they say what the code is,
// not what a browser ran. What they pin (each was a review ruling):
//   - the plaintext export can never carry the record: exportAll and the SovereignBackup type do not name it,
//   - the plaintext import and the password-sealed-file import never read it: only importVaultContentsReport (the passphrase-authenticated vault) applies it,
//   - the vault export is the ONE place it is attached, and the dialog packs it into the sealed vault,
//   - every change to the record goes through the atomic update (no read-then-replace in the restore block),
//   - a Remove must be recorded BEFORE its latch: recordRemovedContact has no caller yet, so this fails the day someone wires one without moving the pin,
//   - no screen imports the confirmation until the copy is cleared.
// Run: npx tsx --test src/lib/identity/suppression-carry-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../../', import.meta.url).pathname; // src/
const store = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
const dialog = readFileSync(new URL('../../components/export/VaultExportDialog.tsx', import.meta.url), 'utf8');
const codeOnly = (text: string): string => text.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

/** The text of one top-level function: from its head to the first line that is a lone closing brace. */
const fnBody = (head: string): string => {
  const a = store.indexOf(head);
  assert.ok(a >= 0, `${head} exists`);
  const b = store.indexOf('\n}\n', a);
  assert.ok(b > a, `${head} ends`);
  return codeOnly(store.slice(a, b));
};

const sources = (dir: string): string[] => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) return f === 'node_modules' ? [] : sources(p);
  return /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f) ? [p] : [];
});
const callersOf = (name: string): string[] =>
  sources(root).filter((f) => !f.endsWith('/identity/client-store.ts') && new RegExp(`\\b${name}\\b`).test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(f.indexOf('/src/') + 1));

test('W1 the plaintext export cannot carry the record: SovereignBackup and exportAll never name it', () => {
  const a = store.indexOf('export interface SovereignBackup');
  const iface = codeOnly(store.slice(a, store.indexOf('\n}\n', a)));
  const body = fnBody('export async function exportAll(');
  for (const text of [iface, body]) assert.doesNotMatch(text, /suppression|removed|exportSuppressionCarry/i);
});

test('W2 the plaintext import and the password-sealed-file import never read the record', () => {
  for (const head of ['export async function importAll(', 'export async function importAllWithPassword(']) {
    assert.doesNotMatch(fnBody(head), /suppression|restoreCarried|removed/i, head);
  }
});

test('W3 importVaultContentsReport is the ONE place that applies a carried record, from the vault only, after the identity is stored', () => {
  const body = fnBody('export async function importVaultContentsReport(');
  assert.equal([...body.matchAll(/restoreCarriedSuppression\(/g)].length, 1, 'called once');
  assert.match(body, /restoreCarriedSuppression\(fp, \(contents\.trustGraph as unknown as \{ suppression\?: unknown \} \| null\)\?\.suppression, contents\.sync\?\.lastModified\);/, 'from the vault body, with the vault\'s own timestamp');
  assert.ok(body.indexOf('await storeIdentity(fp, contents.identity);') < body.indexOf('restoreCarriedSuppression('), 'after the binding check and the identity write');
  assert.deepEqual(callersOf('restoreCarriedSuppression'), [], 'no other file calls it');
  const defs = [...store.matchAll(/restoreCarriedSuppression\(/g)].length;
  assert.equal(defs, 2, 'its definition and that one call, nothing else in the store');
});

test('W4 the vault export is the ONE place the record is attached, and it goes into the sealed vault body', () => {
  assert.deepEqual(callersOf('exportSuppressionCarry'), ['src/components/export/VaultExportDialog.tsx']);
  const code = codeOnly(dialog);
  assert.equal([...code.matchAll(/exportSuppressionCarry\(/g)].length, 1);
  assert.match(code, /\.\.\.\(suppression \? \{ suppression \} : \{\}\),/, 'inside the trust graph object, left out when it could not be read whole');
  assert.ok(code.indexOf('exportSuppressionCarry(') < code.indexOf('packVault('), 'before the vault is packed with the password');
  assert.equal([...store.matchAll(/exportSuppressionCarry\(/g)].length, 1, 'defined once in the store, called nowhere else in it');
});

test('W5 every change to the record or the removed list is the atomic update: the restore block has no read-then-replace and no raw put of those rows, and its storage is a thin layer over makeUpdate', () => {
  const a = store.indexOf("// ── Restoring the owner's suppression");
  const b = store.indexOf('// ── Piece-2 mutual-block: VIEWER-SIDE held-affirmatives store');
  assert.ok(a >= 0 && b > a, 'the block is found');
  const block = codeOnly(store.slice(a, b));
  assert.doesNotMatch(block, /setSuppressionRecord\(/, 'the unguarded setter is not used in the restore block');
  assert.doesNotMatch(block, /txPut\('settings', \{ key: (removedSettingKey|suppressionSettingKey)/, 'no raw put of the record or the list');
  assert.doesNotMatch(block, /txPutIfAbsent\(/, 'no separate put-if-absent: the CAS covers an absent row');
  assert.match(block, /return makeUpdate<T>\(\{/, 'the loop is the pure module\'s makeUpdate (tested there), not a copy of it');
  assert.match(block, /commitIfUnchanged\(await deps\.openDb\(\), \[\{ store: 'settings', key: deps\.settingKey, expected: token as StoredRow \}\]/, 'the commit compares the row that was read');
  assert.match(block, /const row = await deps\.readRow\(\);\s*return \{ token: row, held: await deps\.decode\(row\) \};/, 'the token IS the row the decision is made on');
  assert.match(block, /return sealedRowUpdate<T>\(\{\s*settingKey,\s*readRow: \(\) => txGet<SealedRow>\('settings', settingKey\),\s*openDb: openDB,\s*decode: \(row\) => decodeSealed\(row, ownerFingerprint, recordId, parse\),\s*seal,\s*\}\);/, 'the real store supplies the real read, open and decode');
  assert.doesNotMatch(block, /isPiece2MutualBlockLive/, 'the mutual-block live gate is not touched');
});

test('W6 each of the two new records is sealed in ONE place with its own reserved id, and read as ok / absent / unreadable', () => {
  for (const id of ['REMOVED_RECORD_ID', 'SUPPRESSION_PENDING_RECORD_ID']) {
    assert.equal([...codeOnly(store).matchAll(new RegExp(`encryptContactRecord\\(_sessionKey, ${id},`, 'g'))].length, 1, `${id} is sealed in exactly one place`);
  }
  assert.match(store, /const REMOVED_RECORD_ID = 'piece2:removed';/);
  assert.match(store, /const SUPPRESSION_PENDING_RECORD_ID = 'piece2:suppression-pending';/);
  assert.match(store, /\{ name: 'removed-contacts', recordId: REMOVED_RECORD_ID, settingKey: removedSettingKey \},/);
  assert.match(store, /\{ name: 'suppression-pending', recordId: SUPPRESSION_PENDING_RECORD_ID, settingKey: suppressionPendingSettingKey \},/);
});

test('W7 TRIPWIRE (rewritten now that a Remove caller exists, as it instructed): the ONE caller of recordRemovedContact records BEFORE the latch write and before the delete, and no file calls removeAtTap yet', () => {
  assert.deepEqual(callersOf('recordRemovedContact'), ['src/lib/trust/block-latch-wiring.ts'], 'the single caller is the shared Remove helper, never a screen');
  assert.equal([...store.matchAll(/recordRemovedContact\(/g)].length, 1, 'only its definition in the store');
  const wiring = codeOnly(readFileSync(new URL('../trust/block-latch-wiring.ts', import.meta.url), 'utf8'));
  assert.match(wiring, /recordRemoved: \(id\) => recordRemovedContact\(ownerFingerprint, id\),/, 'the helper hands the record step to removeWithLatch');
  const latchFile = codeOnly(readFileSync(new URL('../trust/block-latch.ts', import.meta.url), 'utf8'));
  const head = latchFile.indexOf('export async function removeWithLatch(');
  assert.ok(head >= 0);
  const body = latchFile.slice(head, latchFile.indexOf('\n}\n', head));
  const [rec, latch, del] = [body.indexOf('await a.recordRemoved(id)'), body.indexOf('await a.latch.setLatched('), body.lastIndexOf('await a.removeContactRecord()')];
  assert.ok(rec > 0 && rec < latch && latch < del, 'record, THEN latch, THEN delete');
  // beacon-wire.ts and beacon-client.ts DEFINE and wrap removeAtTap; any other file naming it is a caller. Block and Remove write the SAME local latch the wire writes while it is OFF, through
  // blockLatchPortsFor; moving that call to removeAtTap is a go-live gate (the first importer of the beacon client), and whoever makes it must rewrite this line.
  const reachingTheLatch = callersOf('removeAtTap').filter((f) => !/\/lib\/(trust\/beacon-wire|crypto\/beacon-client)\.ts$/.test(f));
  assert.deepEqual(reachingTheLatch, [], 'no file calls removeAtTap yet (the local latch is written through blockLatchPortsFor)');
});

test('W8 no screen imports the confirmation or the readers yet (the copy is not cleared for screens until the build is green)', () => {
  for (const name of ['confirmGlobalOffAfterRestore', 'readPendingGlobalOff', 'readRemovedList']) {
    assert.deepEqual(callersOf(name), [], `${name} has no caller outside the store`);
  }
});

test('W9 the lines that only the store can hold: the best-effort wrapper, the throw on a refused Remove, the ports\' owner and keys, the all-or-nothing export', () => {
  assert.match(fnBody('export async function restoreCarriedSuppression('), /try \{\s*return await restoreSuppression\(carried, \{ backupAt, restoredAt: new Date\(\)\.toISOString\(\) \}, createRestorePorts\(ownerFingerprint\)\);\s*\} catch \(e\) \{[\s\S]*return null;\s*\}/, 'a failure leaves the device private and does not fail the restore');
  assert.match(fnBody('export async function recordRemovedContact('), /const refusal = removalRefusal\(await recordRemoval\(createRestorePorts\(ownerFingerprint\)\.updateRemoved, durableId\)\);\s*if \(refusal !== null\) throw new Error\(refusal\);/, 'a refused Remove throws, so the caller\'s Remove fails');
  assert.match(fnBody('export async function exportSuppressionCarry('), /return suppressionToCarry\(await getSuppressionRecord\(ownerFingerprint\), await readRemovedList\(ownerFingerprint\)\);/, 'the export decision is the pure all-or-nothing one, over the two real reads');
  const ports = fnBody('function createRestorePorts(');
  assert.match(ports, /updateSuppression: updateSuppressionRecord\(ownerFingerprint\),/, 'the restore changes the record through the one shared atomic update');
  assert.match(store, /export const updateSuppressionRecord = \(ownerFingerprint: string\): Update<SuppressionRecord> =>\s*updateSealed<SuppressionRecord>\(ownerFingerprint, suppressionSettingKey\(ownerFingerprint\), SUPPRESSION_RECORD_ID, \(x\) => \(isSuppressionRecord\(x\) \? x : null\), \(v\) => sealSuppression\(ownerFingerprint, v\)\);/);
  assert.match(ports, /updateRemoved: updateSealed<string\[\]>\(ownerFingerprint, removedSettingKey\(ownerFingerprint\), REMOVED_RECORD_ID, parseRemovedList, \(v\) => sealRemoved\(ownerFingerprint, v\)\),/);
  assert.match(ports, /readPending: \(\) => readPendingGlobalOff\(ownerFingerprint\),\s*writePending: \(marker\) => writePendingGlobalOff\(ownerFingerprint, marker\),\s*clearPending: \(\) => clearPendingGlobalOff\(ownerFingerprint\),/);
  assert.match(store, /export const confirmGlobalOffAfterRestore = \(ownerFingerprint: string\): Promise<ConfirmOutcome> => confirmPendingGlobalOff\(createRestorePorts\(ownerFingerprint\)\);/);
});

test('W11 the Block / Unblock write is the atomic update too: block-suppression never reads then replaces, and the plain setter has no production caller left', () => {
  const block = codeOnly(readFileSync(new URL('../trust/block-suppression.ts', import.meta.url), 'utf8'));
  assert.doesNotMatch(block, /setSuppressionRecord|getSuppressionRecord/, 'no read-then-replace in the block path');
  assert.match(block, /import \{ updateSuppressionRecord \} from '@\/lib\/identity\/client-store';/);
  assert.match(block, /const defaultStore: SuppressionStoreSeam = \{ updateSuppression: updateSuppressionRecord \};/, 'the default store is the shared atomic update');
  assert.match(block, /store\.updateSuppression\(ownerFingerprint\)<BlockSuppressionOutcome>\(\(held\) => decideBlock\(held, id, blocked\)\)/, 'the decision runs inside the update');
  // CHANGED ON PURPOSE: genesis was the last caller of the unguarded setter. It now writes the empty record ABSENT-ONLY through the same atomic update, so no production code replaces a record blindly.
  assert.deepEqual(callersOf('setSuppressionRecord'), [], 'the unguarded setter has no production caller: genesis writes absent-only through the atomic update');
});

test('W15 the genesis hook is absent-only through the atomic update: it names the shared update, never the plain setter, and takes only TYPES from the restore module', () => {
  const genesis = codeOnly(readFileSync(new URL('../trust/piece2-genesis.ts', import.meta.url), 'utf8'));
  assert.doesNotMatch(genesis, /setSuppressionRecord|getSuppressionRecord/, 'no blind write and no read-then-replace');
  assert.match(genesis, /import \{ updateSuppressionRecord as realUpdateSuppressionRecord \} from '@\/lib\/identity\/client-store';/);
  assert.match(genesis, /export const piece2GenesisInit: GenesisHook = makePiece2GenesisInit\(realUpdateSuppressionRecord\);/, 'the default hook is wired to the shared atomic update');
  assert.match(genesis, /await updateSuppression\(fp\)<GenesisInitOutcome>\(decideGenesisInit\);/, 'the decision runs inside the update');
  assert.match(genesis, /^import type \{ Decision, SealedRead, Update \} from '@\/lib\/trust\/suppression-restore';$/m, 'types only from the restore module: no runtime dependency');
  assert.match(genesis, /if \(held\.state === 'absent'\) return \{ write: emptySuppression\(\), result: 'written' \};/, 'the empty record is written only for an ABSENT record');
});

test('W12 the export screen\'s look is the sealed read: it tells absent from unreadable, and only a LEFT-OUT result shows the notice', () => {
  const body = fnBody('export async function readSuppressionCarryStatus(');
  assert.match(body, /readSealed<SuppressionRecord>\(ownerFingerprint, suppressionSettingKey\(ownerFingerprint\), SUPPRESSION_RECORD_ID, \(x\) => \(isSuppressionRecord\(x\) \? x : null\)\);/, 'the record is read as ok / absent / unreadable, not through the null-for-everything getter');
  assert.match(body, /return suppressionCarryStatus\(record, await readRemovedList\(ownerFingerprint\)\);/);
  const d = codeOnly(dialog);
  assert.match(d, /\.then\(async \(m\) => \{ await m\.repairSuppressionRecord\(fingerprint\)\.catch\(\(\) => undefined\); return m\.readSuppressionCarryStatus\(fingerprint\); \}\)\s*\.then\(\(r\) => \{ if \(!cancelled\) setSuppressionLeftOut\(r === 'left-out'\); \}\)\s*\.catch\(\(\) => \{ if \(!cancelled\) setSuppressionLeftOut\(true\); \}\);/, 'the same repair the export runs, THEN the sealed look; only left-out shows the notice; a failed look is doubt and shows it');
  assert.match(d, /\{suppressionLeftOut && \(\s*<Alert data-testid="suppression-left-out-notice"/);
  assert.match(d, /setSuppressionLeftOut\(false\);\s*\};/, 'closing the dialog resets it');
});

test('W13 the notice does not block the export: handleExport never reads the flag', () => {
  const a = dialog.indexOf('const handleExport = async');
  const b = dialog.indexOf('\n  };\n', a);
  assert.ok(a > 0 && b > a);
  assert.doesNotMatch(dialog.slice(a, b), /suppressionLeftOut/);
});

test('W14 the left-out notice is the reviewed sentence, byte for byte: ASCII, 269 characters, pinned by hash', () => {
  const m = /export const SUPPRESSION_LEFT_OUT_NOTICE =\s*"((?:[^"\\]|\\.)*)"\s*\+\s*"((?:[^"\\]|\\.)*)";/.exec(dialog);
  assert.ok(m, 'the constant is two string literals joined');
  const text = m![1] + m![2];
  assert.equal(text.length, 269);
  assert.ok(/^[\x20-\x7e]+$/.test(text), 'plain ASCII');
  assert.equal(createHash('sha256').update(text).digest('hex').slice(0, 16), '4d7af208e52252c7');
  assert.doesNotMatch(dialog, /PROVISIONAL/, 'no provisional marker is left');
});

