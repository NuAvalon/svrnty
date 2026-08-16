// src/lib/sync/vault.selftest.ts
//
// Standalone, framework-free proof of the .svrnty v3 vault format (lane 0.10).
// Run:  npx tsx src/lib/sync/vault.selftest.ts
// Exits non-zero on the first failed assertion. Pure logic — no browser, no DOM
// (WebCrypto + Argon2id run fine under Node 22).
//
// Covers, per Athena's G3 harness spec + Flint's co-review crux:
//   1. pack → unpack roundtrip (contents incl. safe word survive)
//   2. cleartext header is crypto-params ONLY (no name / fingerprint / safe word)
//   3. tamper-evidence: a flipped header byte AND a flipped body byte both fail
//   4. F1: a param-bomb (oversized memory_cost) is REJECTED before deriveKey
//   5. F3: a too-short passphrase is rejected on write
//   6. wrong passphrase fails with a generic error (no safe word leaked)
//   7. v2 legacy file is refused with an actionable message (clean-break)
//   8. identity-backup (encrypted-backup.ts) still roundtrips + clamps params

import {
  packVault,
  unpackVault,
  readVaultHeader,
  createVaultContents,
  type VaultContents,
  type VaultIdentity,
  type VaultKeys,
} from './vault';
import { encryptBackup, decryptBackup } from '../crypto/encrypted-backup';
import { MIN_PASSPHRASE_LENGTH } from '../crypto/kdf';
import type { TrustGraph } from '../trust/types';

let passed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  ✗ FAIL: ${msg}`);
    process.exit(1);
  }
  passed++;
}
async function assertThrows(fn: () => Promise<unknown> | unknown, msg: string): Promise<void> {
  try {
    await fn();
  } catch {
    passed++;
    return;
  }
  console.error(`  ✗ FAIL (expected throw): ${msg}`);
  process.exit(1);
}

const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;
const GOOD_PASS = 'correct horse battery staple';
const SAFE_WORD = 'lighthouse-42';

function makeContents(): VaultContents {
  const identity: VaultIdentity = {
    version: '1.0',
    created_at: '2026-08-16T00:00:00.000Z',
    identity: {
      name: 'Ada Lovelace',
      email: 'ada@example.com',
      fingerprint: 'ABCD1234ABCD1234ABCD1234ABCD1234DEADBEEF',
      public_key: '-----BEGIN PGP PUBLIC KEY-----\nfake\n-----END-----',
    },
    verification: { status: 'unverified', method: null, verified_at: null },
    metadata: { client_version: 'test', key_type: 'ecc', key_usage: ['sign'] },
  };
  const keys: VaultKeys = {
    classical: { privateKey: 'SECRET-PRIVATE-KEY', passphrase: 'pgp-pass' },
    pq: null,
  };
  const trustGraph: TrustGraph = { edges: [] } as unknown as TrustGraph;
  return createVaultContents(identity, keys, trustGraph, { safeWord: SAFE_WORD });
}

/** Split a packed v3 file into (magic+headerLen prefix, header bytes, body bytes). */
function splitFile(buf: ArrayBuffer): { prefix: Uint8Array; header: Uint8Array; body: Uint8Array } {
  const bytes = new Uint8Array(buf);
  const headerLen =
    ((bytes[MAGIC_LEN] << 24) |
      (bytes[MAGIC_LEN + 1] << 16) |
      (bytes[MAGIC_LEN + 2] << 8) |
      bytes[MAGIC_LEN + 3]) >>>
    0;
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  return {
    prefix: bytes.slice(0, headerStart),
    header: bytes.slice(headerStart, headerStart + headerLen),
    body: bytes.slice(headerStart + headerLen),
  };
}

/** Reassemble a file from a (possibly mutated) header object + body, fixing the length. */
function assemble(prefixMagic: Uint8Array, headerObj: object, body: Uint8Array): ArrayBuffer {
  const headerBytes = new TextEncoder().encode(JSON.stringify(headerObj));
  const out = new Uint8Array(MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length + body.length);
  out.set(prefixMagic.slice(0, MAGIC_LEN), 0);
  const hl = headerBytes.length;
  out[MAGIC_LEN] = (hl >>> 24) & 0xff;
  out[MAGIC_LEN + 1] = (hl >>> 16) & 0xff;
  out[MAGIC_LEN + 2] = (hl >>> 8) & 0xff;
  out[MAGIC_LEN + 3] = hl & 0xff;
  out.set(headerBytes, MAGIC_LEN + HEADER_LEN_SIZE);
  out.set(body, MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length);
  return out.buffer;
}

async function main(): Promise<void> {
  console.log('vault.selftest — .svrnty v3');

  // 1. Roundtrip.
  const contents = makeContents();
  const packed = await packVault(contents, GOOD_PASS);
  const { header, contents: out } = await unpackVault(packed, GOOD_PASS);
  assert(header.version === 3, 'header.version === 3');
  assert(header.kdf.algorithm === 'argon2id', 'kdf is argon2id');
  assert(out.identity.identity.name === 'Ada Lovelace', 'identity roundtrips');
  assert(out.keys.classical.privateKey === 'SECRET-PRIVATE-KEY', 'private key roundtrips');
  assert(out.settings.safeWord === SAFE_WORD, 'safe word roundtrips (in encrypted body)');

  // 2. Cleartext header is crypto-params only — no identity, no safe word.
  const { header: hdrBytes } = splitFile(packed);
  const headerText = new TextDecoder().decode(hdrBytes);
  assert(!headerText.includes('Ada Lovelace'), 'header does NOT leak display name');
  assert(!headerText.includes(SAFE_WORD), 'header does NOT leak safe word');
  assert(!headerText.includes('DEADBEEF'), 'header does NOT leak fingerprint');
  const previewHeader = readVaultHeader(packed);
  assert(
    // @ts-expect-error — proving these fields are gone from the v3 header type/data
    previewHeader.displayName === undefined && previewHeader.safeWord === undefined,
    'pre-passphrase preview exposes no identity fields',
  );

  // 3. Tamper-evidence.
  const parts = splitFile(packed);
  // (a) flip a body byte → GCM tag fails
  const bodyTamper = new Uint8Array(new Uint8Array(packed)); // copy
  const bodyOffset = MAGIC_LEN + HEADER_LEN_SIZE + parts.header.length;
  bodyTamper[bodyOffset] ^= 0x01;
  await assertThrows(() => unpackVault(bodyTamper.buffer, GOOD_PASS), 'flipped body byte rejected');
  // (b) mutate the header (salt) → AAD mismatch + wrong key → fails
  const hdrObj = JSON.parse(new TextDecoder().decode(parts.header));
  const saltChars = hdrObj.kdf.salt.split('');
  saltChars[0] = saltChars[0] === 'A' ? 'B' : 'A';
  hdrObj.kdf.salt = saltChars.join('');
  const headerTampered = assemble(parts.prefix, hdrObj, parts.body);
  await assertThrows(() => unpackVault(headerTampered, GOOD_PASS), 'mutated header salt rejected');

  // 4. F1 — param-bomb rejected before deriveKey (returns fast, no OOM).
  const bombObj = JSON.parse(new TextDecoder().decode(parts.header));
  bombObj.kdf.memory_cost = 10_000_000; // ~10 GB — hostile
  const bombFile = assemble(parts.prefix, bombObj, parts.body);
  const t0 = process.hrtime.bigint();
  await assertThrows(() => unpackVault(bombFile, GOOD_PASS), 'param-bomb rejected');
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert(elapsedMs < 500, `param-bomb rejected FAST (was ${elapsedMs.toFixed(1)}ms, no allocation)`);

  // 5. F3 — weak passphrase rejected on write.
  await assertThrows(() => packVault(makeContents(), 'short'), 'weak passphrase rejected on write');
  await assertThrows(() => packVault(makeContents(), 'elevenchars'), '11-char passphrase rejected (floor is 12)');
  assert(MIN_PASSPHRASE_LENGTH >= 12, 'passphrase floor is at least 12');

  // 6. Wrong passphrase → generic failure, no safe word in the error.
  try {
    await unpackVault(packed, 'wrong passphrase entirely');
    console.error('  ✗ FAIL: wrong passphrase should throw');
    process.exit(1);
  } catch (e) {
    const m = String((e as Error).message);
    assert(!m.includes(SAFE_WORD), 'wrong-passphrase error does not leak safe word');
    passed++;
  }

  // 7. v2 legacy file refused with actionable message.
  const v2 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x02, 0, 0, 0, 2, 123, 125]);
  try {
    readVaultHeader(v2.buffer);
    console.error('  ✗ FAIL: v2 file should be refused');
    process.exit(1);
  } catch (e) {
    assert(/legacy v2/i.test(String((e as Error).message)), 'v2 refusal is actionable');
    passed++;
  }

  // 8. Identity-backup path still roundtrips through the shared KDF.
  const idBackup = { identity: { name: 'x' }, keys: {}, contacts: [] } as unknown as Parameters<
    typeof encryptBackup
  >[0];
  const enc = await encryptBackup(idBackup, GOOD_PASS);
  assert(enc.kdf.algorithm === 'argon2id', 'identity backup uses argon2id');
  const dec = (await decryptBackup(enc, GOOD_PASS)) as { identity: { name: string } };
  assert(dec.identity.name === 'x', 'identity backup roundtrips');
  const idBomb = { ...enc, kdf: { ...enc.kdf, memory_cost: 10_000_000 } };
  await assertThrows(() => decryptBackup(idBomb, GOOD_PASS), 'identity backup clamps param-bomb');

  console.log(`\n✓ all ${passed} assertions passed`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
