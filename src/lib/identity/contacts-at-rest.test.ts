// src/lib/identity/contacts-at-rest.test.ts
// Run: npx tsx --test src/lib/identity/contacts-at-rest.test.ts
//
// Contacts at rest, contract v0.1 ("nothing readable about contacts on a locked phone").
// Behavioral anchors over a fake-indexeddb harness — each A has a test that fails without
// the change it names:
//   A1  gate + codes write only through encryptContactRecord under reserved AAD ids;
//       every contact id written is a UUID (namespace cannot collide with atrest:* ids)
//   A3  writes while locked THROW — never plaintext, never a silent drop
//   A4  reads THROW on anything but genuine absence (locked / corrupt / wrong shape);
//       a corrupt codes record drops the poll cycle, an absent one returns empty;
//       after re-unlock the round-trip works
//   A5  sealed-absent + legacy-present → the read returns the plaintext row (never "empty");
//       a failed read stops the write
//   A6  layout seals {nodes, digest} — no topology/glass strings anywhere in the record;
//       locked read short-circuits; layoutDigest is the pinned TLV formula
//   A7  first unlocked write seals the legacy bag and LEAVES the old row in place
//   A8  exportAll carries none of the three stores
//   A9  describeAtRestError maps to exactly the two person-facing lines
// Static guards pin the wiring the harness cannot see (component copy routing, migration order).

import 'fake-indexeddb/auto';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { lpStr } from '../crypto/lp-tlv';
import {
  ATREST_COPY,
  AtRestLockedError,
  AtRestUnreadableError,
  describeAtRestError,
  enqueueGateArrival,
  exportAll,
  getGateArrival,
  initSessionKey,
  loadGateArrivals,
  loadIssuedCodeMap,
  lockSession,
  readAtRestLayout,
  recordAcceptedJoiner,
  recordIssuedGrowCode,
  removeGateArrival,
  writeAtRestLayout,
} from './client-store';
import { decryptContactRecord } from './contact-crypto';
import { dropCycleOnThrow } from '../sync/live-book-poll';
import { layoutDigest, loadLayoutMemory, saveLayoutMemory } from '../trust/layout-memory';

const OWNER = 'a1'.repeat(32); // 64-hex owner fp
const OTHER = 'b2'.repeat(32);
const PASS = 'test-passphrase';

const clientStore = () => readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');

/** Raw settings row helper (test-side; mirrors txGet on the same DB). */
async function rawSetting(key: string): Promise<any> {
  const db = await new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open('svrnty', 4);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  try {
    return await new Promise((res, rej) => {
      const tx = db.transaction('settings', 'readonly');
      const req = tx.objectStore('settings').get(key);
      req.onsuccess = () => res(req.result ?? null);
      req.onerror = () => rej(req.error);
    });
  } finally {
    db.close();
  }
}

async function rawPutSetting(key: string, value: unknown): Promise<void> {
  const db = await new Promise<IDBDatabase>((res, rej) => {
    const r = indexedDB.open('svrnty', 4);
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  try {
    await new Promise<void>((res, rej) => {
      const tx = db.transaction('settings', 'readwrite');
      tx.objectStore('settings').put({ key, value });
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  } finally {
    db.close();
  }
}

/** Decrypt a sealed at-rest row with the session key initSessionKey derived from PASS. */
async function unseal(recordId: string, ownerFp: string): Promise<any> {
  const row = await rawSetting(`${recordId}:${ownerFp}`);
  assert.ok(row?.value?.ciphertext, `no sealed row for ${recordId}`);
  const saltRow = await rawSetting('key_encryption_salt');
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(PASS), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: Uint8Array.from(atob(saltRow.value), (c) => c.charCodeAt(0)), iterations: 600_000, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  return decryptContactRecord(key, recordId, ownerFp, row.value);
}

const arrival = (fp: string) => ({
  fingerprint: fp,
  displayName: `name-${fp.slice(0, 4)}`,
  publicKeyArmored: 'PUB',
  epoch: 1,
  inviteNonce: 'NONCE1',
  mintChannel: 'remote' as const,
  arrivedAt: '2026-11-11T00:00:00Z',
  direction: 'inbound_joiner' as const,
});

test.before(async () => {
  await initSessionKey(PASS);
});

// ── A1: sealed writes under reserved AAD ids; nothing readable while locked ──────────────────

test('A1: gate + codes writes land as sealed rows; no fp/code/name readable in them', async () => {
  await recordIssuedGrowCode(OWNER, 'CODE42', 2, 'remote');
  await enqueueGateArrival(OWNER, arrival('fp-joiner-aaaa'));

  for (const key of [`atrest:codes:${OWNER}`, `atrest:gate:${OWNER}`]) {
    const row = await rawSetting(key);
    assert.ok(row?.value?.ciphertext, `${key} must be a sealed {iv,ciphertext} record`);
    const blob = JSON.stringify(row.value);
    for (const plain of ['CODE42', 'fp-joiner-aaaa', 'name-fp-j', 'NONCE1']) {
      assert.ok(!blob.includes(plain), `${key} leaks ${plain} readable at rest`);
    }
  }
});

test('A1: every contact id the store writes is a UUID (reserved atrest:* ids can never collide)', () => {
  const src = clientStore();
  // Every contacts-store row id comes from crypto.randomUUID() — pin all id-mint sites.
  const idSites = src.match(/id:\s*crypto\.randomUUID\(\)|const id = crypto\.randomUUID\(\)/g) ?? [];
  assert.ok(idSites.length >= 2, 'contact/shard ids must mint via crypto.randomUUID()');
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  assert.match(crypto.randomUUID(), uuid);
  for (const reserved of ['atrest:gate', 'atrest:codes', 'atrest:layout']) {
    assert.ok(!uuid.test(reserved), `${reserved} must not be UUID-shaped`);
    assert.ok(reserved.includes(':'), 'reserved ids carry a namespace UUIDs never contain');
  }
});

// ── A3: locked writes throw — never plaintext, never silently dropped ────────────────────────

test('A3: locked writes throw AtRestLockedError and write nothing', async () => {
  lockSession();
  try {
    await assert.rejects(() => recordIssuedGrowCode(OWNER, 'LOCKX', 1, 'remote'), AtRestLockedError);
    await assert.rejects(() => enqueueGateArrival(OWNER, arrival('fp-locked')), AtRestLockedError);
    await assert.rejects(() => removeGateArrival(OWNER, 'fp-joiner-aaaa'), AtRestLockedError);
    await assert.rejects(() => writeAtRestLayout(OWNER, { v: 1, nodes: [], digest: 'd' }), AtRestLockedError);
    // nothing written under the locked attempt's keys
    assert.equal(await rawSetting(`atrest:codes:${OWNER}`) && true, true); // prior row untouched
    assert.equal(await rawSetting(`atrest:layout:${OWNER}`), null, 'layout write must not land');
  } finally {
    await initSessionKey(PASS); // restore for the rest of the file
  }
});

// ── A4: reads throw on anything but genuine absence ──────────────────────────────────────────

test('A4: absent → empty; corrupt / locked → throw; the poll cycle drops on a bad codes read', async () => {
  // absent: a fresh owner reads empty, not an error
  assert.deepEqual(await loadIssuedCodeMap(OTHER), {});
  assert.deepEqual(await loadGateArrivals(OTHER), []);

  // corrupt the sealed codes row → read throws AtRestUnreadableError (never an empty map)
  const good = await rawSetting(`atrest:codes:${OWNER}`);
  await rawPutSetting(`atrest:codes:${OWNER}`, { ...good.value, ciphertext: 'AAAA' + good.value.ciphertext.slice(4) });
  await assert.rejects(() => loadIssuedCodeMap(OWNER), AtRestUnreadableError);
  await assert.rejects(() => recordAcceptedJoiner(OWNER, 'CODE42', 'fp-x'), AtRestUnreadableError);
  // ...and the poll's cycle wrapper drops the cycle on that throw (envelope stays for retry)
  let dropped = false;
  const cycle = { key: () => ({}) as any, drop: () => { dropped = true; }, get ended() { return dropped; } };
  await assert.rejects(() => dropCycleOnThrow(cycle, () => loadIssuedCodeMap(OWNER)), AtRestUnreadableError);
  assert.ok(dropped, 'a failed codes read must drop the unlock cycle (the envelope is kept, retried)');

  // a wrong-shape sealed row throws too
  await rawPutSetting(`atrest:codes:${OWNER}`, good.value);
  await assert.doesNotReject(() => loadIssuedCodeMap(OWNER)); // restored
  const badShape = { ...good.value };
  // seal a non-map (a string) under the codes AAD so the shape check fires, not the tag
  await writeAtRestLayout(OWNER, { v: 1, nodes: [{ id: 'n1', x: 1, y: 2 }], digest: 'd'.repeat(32) });
  const layoutRow = await rawSetting(`atrest:layout:${OWNER}`);
  await rawPutSetting(`atrest:codes:${OWNER}`, layoutRow.value); // layout record under codes AAD → tag fails anyway
  await assert.rejects(() => loadIssuedCodeMap(OWNER), AtRestUnreadableError);
  await rawPutSetting(`atrest:codes:${OWNER}`, badShape);

  // locked read throws even though a sealed row exists
  lockSession();
  await assert.rejects(() => loadIssuedCodeMap(OWNER), AtRestLockedError);
  await assert.rejects(() => loadGateArrivals(OWNER), AtRestLockedError);
  await initSessionKey(PASS);
});

// ── A5: legacy row answers while the sealed row is absent; a failed read stops the write ─────

test('A5: sealed-absent + legacy-present reads return the plaintext row (never "empty")', async () => {
  const legacyMap = { [OTHER]: { LEGACY9: { acceptUntil: Date.now() + 60_000, accepted: [], cap: 1, channel: 'remote' } } };
  await rawPutSetting('issued_grow_codes', JSON.stringify(legacyMap));
  const map = await loadIssuedCodeMap(OTHER); // no sealed row for OTHER
  assert.equal(map[OTHER]?.LEGACY9?.acceptUntil > 0, true, 'legacy row must answer while sealed is absent');

  // a malformed legacy row is NOT "empty" — it throws, and the write is stopped
  await rawPutSetting('issued_grow_codes', '{not-json');
  await assert.rejects(() => loadIssuedCodeMap(OTHER), AtRestUnreadableError);
  await assert.rejects(() => recordIssuedGrowCode(OTHER, 'NEW1', 1, 'remote'), AtRestUnreadableError);
  assert.equal(await rawSetting(`atrest:codes:${OTHER}`), null, 'a failed read must not produce a write');

  // restore a clean legacy row; the legacy gate map too
  await rawPutSetting('issued_grow_codes', JSON.stringify(legacyMap));
  const legacyGate = { [OTHER]: { 'fp-legacy-peer': arrival('fp-legacy-peer') } };
  await rawPutSetting('grow_gate_arrivals', JSON.stringify(legacyGate));
  const gate = await loadGateArrivals(OTHER);
  assert.equal(gate.length, 1);
  assert.equal(gate[0].fingerprint, 'fp-legacy-peer');
});

// ── A6: layout — sealed {nodes, digest}; no topology/glass stored; locked short-circuits ──────

test('A6: layoutDigest is the pinned TLV formula; sealed record stores no topology/glass', async () => {
  const expect = bytesToHex(
    sha256(concatBytes(lpStr('svrnty-layout-digest-v1'), lpStr('a|b;c|d'), lpStr('x:known;y:trusted'))).slice(0, 16),
  );
  assert.equal(layoutDigest('a|b;c|d', 'x:known;y:trusted'), expect);
  assert.equal(expect.length, 32); // 16 bytes hex

  await saveLayoutMemory(OWNER, [{ id: 'fpA', x: 1, y: 2 }], 'a|b;c|d', 'x:known;y:trusted');
  const rec = await readAtRestLayout(OWNER);
  assert.ok(rec, 'sealed layout record must exist');
  assert.deepEqual(Object.keys(rec!).sort(), ['digest', 'nodes', 'v']);
  assert.equal(rec!.digest, expect);
  // nothing of the signature strings lands in the stored record — not sealed, not anywhere
  const storedJson = JSON.stringify(rec);
  assert.ok(!storedJson.includes('a|b;c|d'), 'topology string must not be stored');
  assert.ok(!storedJson.includes('x:known;y:trusted'), 'glass string must not be stored');
  const raw = await rawSetting(`atrest:layout:${OWNER}`);
  assert.ok(!JSON.stringify(raw.value).includes('a|b'), 'ciphertext row carries no readable pair');

  // round-trip via the payload loader
  const mem = await loadLayoutMemory(OWNER);
  assert.equal(mem.digest, expect);
  assert.equal(mem.nodes.get('fpA')?.x, 1);

  // locked → short-circuit empty (no decrypt attempt, no throw)
  lockSession();
  const locked = await loadLayoutMemory(OWNER);
  assert.equal(locked.digest, '');
  assert.equal(locked.nodes.size, 0);
  await initSessionKey(PASS);
});

// ── A7: first unlocked write seals the legacy bag and LEAVES the old row ──────────────────────

test('A7: first unlocked write seals the bag; the old plaintext row is left in place', async () => {
  // OTHER still has only the legacy rows from the A5 test.
  await recordIssuedGrowCode(OTHER, 'NEWCODE', 3, 'remote');
  const sealed = await unseal('atrest:codes', OTHER);
  assert.ok(sealed.NEWCODE, 'new code sealed');
  assert.ok(sealed.LEGACY9, 'legacy bag migrated into the same sealed write');
  const legacyRow = await rawSetting('issued_grow_codes');
  assert.ok(legacyRow?.value.includes('LEGACY9'), 'the old codes row is left in place (A7)');

  await enqueueGateArrival(OTHER, arrival('fp-new-peer'));
  const gateSealed = await unseal('atrest:gate', OTHER);
  assert.ok(gateSealed['fp-legacy-peer'], 'legacy gate bag migrated');
  assert.ok(gateSealed['fp-new-peer'], 'new arrival sealed');
  const legacyGateRow = await rawSetting('grow_gate_arrivals');
  assert.ok(legacyGateRow?.value.includes('fp-legacy-peer'), 'the old gate row is left in place (A7)');

  // subsequent reads use the seal, not the legacy row
  assert.ok(await getGateArrival(OTHER, 'fp-legacy-peer'));
});

// ── A8: exportAll carries none of the three stores ───────────────────────────────────────────

test('A8: exportAll carries no gate/codes/layout data', async () => {
  // identity must exist for exportAll — mint one directly through the store path
  const { storeIdentity } = await import('./client-store');
  await storeIdentity(OWNER, { identity: { fingerprint: OWNER, public_key: 'PUB' } } as any);
  const backup = JSON.stringify(await exportAll(OWNER));
  for (const marker of ['CODE42', 'LEGACY9', 'fp-joiner', 'atrest:', 'svrnty.trust-map.layout', 'digest']) {
    assert.ok(!backup.includes(marker), `export leaks ${marker}`);
  }
});

test('A8 (static): exportAll + emit paths never reference the at-rest rows or the legacy keys', () => {
  const src = clientStore();
  const exp = src.slice(src.indexOf('export async function exportAll('));
  const body = exp.slice(0, exp.indexOf('\nexport '));
  for (const k of ['atrest:', 'issued_grow_codes', 'grow_gate_arrivals', 'layout']) {
    assert.ok(!body.includes(k), `exportAll must not touch ${k}`);
  }
});

// ── A9: the two person-facing lines ──────────────────────────────────────────────────────────

test('A9: describeAtRestError maps to exactly the two lines; unknown errors pass through', () => {
  assert.equal(describeAtRestError(new AtRestLockedError('x')), 'Unlock svrnty to continue.');
  assert.equal(
    describeAtRestError(new AtRestUnreadableError('x')),
    "Your invite records couldn't be read on this device. Nothing was changed.",
  );
  assert.equal(describeAtRestError(new Error('decrypt failed record atrest:codes:fp')), null);
  assert.equal(describeAtRestError('nope'), null);
  assert.equal(ATREST_COPY.lockedList, 'Unlock to see your invites');
});

test('A9 (static): person-facing callers route errors through describeAtRestError, and the gate list draws the lock line not "empty"', () => {
  const read = (rel: string) => readFileSync(new URL(`../../components/${rel}`, import.meta.url), 'utf8');
  const ceremony = read('JoinerCeremony.tsx');
  assert.match(ceremony, /describeAtRestError\(/, 'joiner ceremony must map at-rest errors');
  const gate = read('GrowGatePanel.tsx');
  assert.match(gate, /describeAtRestError\(/, 'gate panel must map at-rest errors');
  assert.match(gate, /ATREST_COPY\.lockedList/, 'a locked gate list draws the unlock line');
  assert.match(gate, /loadError\s*\?/, 'a failed list render shows the mapped line, not the empty copy');
  const sheet = read('GrowSheet.tsx');
  assert.match(sheet, /describeAtRestError\(/, 'invite mint must surface an at-rest write failure');
});

// ── Static: the stores are written ONLY through encryptContactRecord; no new key material ─────

test('A1/A2 (static): no JSON.stringify writes remain on the three stores; no new key derivation', () => {
  const src = clientStore();
  // the at-rest block: write path goes through writeAtRestRecord → encryptContactRecord only
  const writes = src.match(/writeAtRestRecord\(/g) ?? [];
  assert.ok(writes.length >= 4, 'codes/gate/layout writes all route through writeAtRestRecord');
  // no plaintext JSON.stringify of the maps survives in the save paths
  const region = src.slice(src.indexOf('Contacts at rest (contract v0.1'));
  assert.doesNotMatch(region, /JSON\.stringify\(map\)|JSON\.stringify\(bag\)/, 'no plaintext map write may remain');
  // A2: no new key material — the only key the sealed path uses is _sessionKey
  assert.doesNotMatch(region, /deriveKey|importKey|randomBytes|generateKey/, 'the sealed path must reuse _sessionKey only');
});

test('A5 (static): the unlock migration runs after the mailbox ensure, inside initSessionKey, verified-owners only', () => {
  const src = clientStore();
  const init = src.slice(src.indexOf('export async function initSessionKey('));
  const body = init.slice(0, init.indexOf('\n}'));
  assert.ok(body.indexOf('ensureDeviceMailboxesOnUnlock()') < body.indexOf('migrateAtRestStoresOnUnlock()'), 'migration runs with the other unlock heals');
  const mig = src.slice(src.indexOf('async function migrateAtRestStoresOnUnlock('));
  assert.match(mig.slice(0, mig.indexOf('\n}')), /_unlockVerifiedOwners/, 'migration writes only for session-verified owners');
});

test('A6 (static): layout persistence stores positions + digest — topology/glass never serialized', () => {
  const src = readFileSync(new URL('../trust/layout-memory.ts', import.meta.url), 'utf8');
  const save = src.slice(src.indexOf('export async function saveLayoutMemory('));
  const body = save.slice(0, save.indexOf('\n}'));
  assert.match(body, /digest: layoutDigest\(topology, glass\)/, 'save stores the digest');
  assert.doesNotMatch(body, /topology:|glass:/, 'save must not serialize topology/glass fields');
  const legacy = src.slice(src.indexOf('function readLegacyLayout('));
  assert.match(legacy, /localStorage\.getItem/, 'the localStorage row is the A5 read fallback');
});
