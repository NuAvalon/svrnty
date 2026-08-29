// src/lib/sync/vault.selftest.ts
//
// Standalone, framework-free proof of the .svrnty vault format.
// Run:  npx tsx src/lib/sync/vault.selftest.ts
// Exits non-zero on the first failed assertion. Pure logic — no browser, no DOM
// (WebCrypto + Argon2id + Shamir run fine under Node 22).
//
// Covers, per Athena's G3 harness spec + Flint's co-review crux:
//   1. pack → unpack roundtrip (contents incl. safe word survive); export is v4
//   2. cleartext header is crypto-params ONLY (no name / fingerprint / safe word)
//   3. tamper-evidence: a flipped header byte AND a flipped body byte both fail
//   4. F1: a param-bomb (oversized memory_cost) is REJECTED before deriveKey
//   5. F3: a too-short passphrase is rejected on write
//   6. wrong passphrase fails with a generic error (no safe word leaked)
//   7. v2 legacy file is refused with an actionable message (clean-break)
//   8. identity-backup (encrypted-backup.ts) still roundtrips + clamps params
//   ★ 9. RECOVERY DUAL-ENVELOPE (the v4 fix, Do-No-Harm):
//        export → LOSE the passphrase → extractRecoveryVault (NO passphrase) →
//        recoverFromSeedPhrase AND recoverFromShards → private keys come back
//        byte-for-byte. Envelope reveals TYPE not IDENTITY. Daily unlock intact.
//  10. MIGRATION: an existing v3 file still opens by passphrase (not bricked);
//        extractRecoveryVault refuses it with a re-export message.
//  11. a v4 file with NO recovery configured fails extraction honestly.

import {
  packVault,
  unpackVault,
  readVaultHeader,
  extractRecoveryVault,
  createVaultContents,
  type VaultContents,
  type VaultIdentity,
  type VaultKeys,
} from './vault';
import {
  createKeyVault,
  recoverFromSeedPhrase,
  recoverFromShards,
  type PrivateKeyBundle,
} from '../crypto/recovery';
import {
  deriveKeyArgon2id,
  defaultArgon2Params,
  aesGcmEncrypt,
  toBase64,
  randomBytes,
  SALT_LENGTH,
  IV_LENGTH,
  MIN_PASSPHRASE_LENGTH,
} from '../crypto/kdf';
import { encryptBackup, decryptBackup } from '../crypto/encrypted-backup';
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
/** assertThrows + check the message matches (honest, actionable errors). */
async function assertThrowsMatch(
  fn: () => Promise<unknown> | unknown,
  re: RegExp,
  msg: string,
): Promise<void> {
  try {
    await fn();
  } catch (e) {
    assert(re.test(String((e as Error).message)), `${msg} (message: "${(e as Error).message}")`);
    return;
  }
  console.error(`  ✗ FAIL (expected throw): ${msg}`);
  process.exit(1);
}

const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;
const BODY_LEN_SIZE = 4;
const MAGIC_V3 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x03]);
const GOOD_PASS = 'correct horse battery staple';
const SAFE_WORD = 'lighthouse-42';

function readU32(b: Uint8Array, o: number): number {
  return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
}
function writeU32(b: Uint8Array, o: number, v: number): void {
  b[o] = (v >>> 24) & 0xff;
  b[o + 1] = (v >>> 16) & 0xff;
  b[o + 2] = (v >>> 8) & 0xff;
  b[o + 3] = v & 0xff;
}

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

/** v4 split: (prefix = magic+headerLen, header, body, recovery). */
function splitFile(buf: ArrayBuffer): {
  prefix: Uint8Array;
  magic: Uint8Array;
  header: Uint8Array;
  body: Uint8Array;
  recovery: Uint8Array;
} {
  const bytes = new Uint8Array(buf);
  const headerLen = readU32(bytes, MAGIC_LEN);
  const headerStart = MAGIC_LEN + HEADER_LEN_SIZE;
  const bodyLenOffset = headerStart + headerLen;
  const bodyLen = readU32(bytes, bodyLenOffset);
  const bodyStart = bodyLenOffset + BODY_LEN_SIZE;
  return {
    prefix: bytes.slice(0, headerStart),
    magic: bytes.slice(0, MAGIC_LEN),
    header: bytes.slice(headerStart, headerStart + headerLen),
    body: bytes.slice(bodyStart, bodyStart + bodyLen),
    recovery: bytes.slice(bodyStart + bodyLen),
  };
}

/** Reassemble a v4 file from a (possibly mutated) header object + body + recovery. */
function assemble(magic: Uint8Array, headerObj: object, body: Uint8Array, recovery: Uint8Array): ArrayBuffer {
  const headerBytes = new TextEncoder().encode(JSON.stringify(headerObj));
  const out = new Uint8Array(
    MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length + BODY_LEN_SIZE + body.length + recovery.length,
  );
  let o = 0;
  out.set(magic.slice(0, MAGIC_LEN), o);
  o += MAGIC_LEN;
  writeU32(out, o, headerBytes.length);
  o += HEADER_LEN_SIZE;
  out.set(headerBytes, o);
  o += headerBytes.length;
  writeU32(out, o, body.length);
  o += BODY_LEN_SIZE;
  out.set(body, o);
  o += body.length;
  out.set(recovery, o);
  return out.buffer;
}

/**
 * Craft a LEGACY v3 file (old format: no BODY_LEN, no recovery envelope, AAD =
 * MAGIC_V3 ‖ header). Proves unpackVault still opens pre-v4 backups (migration).
 */
async function packV3(contents: VaultContents, passphrase: string): Promise<ArrayBuffer> {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);
  const kdf = defaultArgon2Params(salt);
  const header = { format: 'svrnty-vault', version: 3, kdf, iv: toBase64(iv) };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const aad = new Uint8Array(MAGIC_LEN + headerBytes.length);
  aad.set(MAGIC_V3, 0);
  aad.set(headerBytes, MAGIC_LEN);
  const key = deriveKeyArgon2id(passphrase, salt, kdf);
  const body = await aesGcmEncrypt(key, iv, new TextEncoder().encode(JSON.stringify(contents)), aad);
  key.fill(0);
  const out = new Uint8Array(MAGIC_LEN + HEADER_LEN_SIZE + headerBytes.length + body.length);
  let o = 0;
  out.set(MAGIC_V3, o);
  o += MAGIC_LEN;
  writeU32(out, o, headerBytes.length);
  o += HEADER_LEN_SIZE;
  out.set(headerBytes, o);
  o += headerBytes.length;
  out.set(body, o);
  return out.buffer;
}

async function main(): Promise<void> {
  console.log('vault.selftest — .svrnty v4 (recovery dual-envelope)');

  // 1. Roundtrip. Export writes v4.
  const contents = makeContents();
  const packed = await packVault(contents, GOOD_PASS);
  const { header, contents: out } = await unpackVault(packed, GOOD_PASS);
  assert(header.version === 4, 'header.version === 4 (export writes v4)');
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
    // @ts-expect-error — proving these fields are gone from the header type/data
    previewHeader.displayName === undefined && previewHeader.safeWord === undefined,
    'pre-passphrase preview exposes no identity fields',
  );

  // 3. Tamper-evidence.
  const parts = splitFile(packed);
  // (a) flip a body byte → GCM tag fails
  const bodyTamper = new Uint8Array(new Uint8Array(packed)); // copy
  const bodyOffset = MAGIC_LEN + HEADER_LEN_SIZE + parts.header.length + BODY_LEN_SIZE;
  bodyTamper[bodyOffset] ^= 0x01;
  await assertThrows(() => unpackVault(bodyTamper.buffer, GOOD_PASS), 'flipped body byte rejected');
  // (b) mutate the header (salt) → AAD mismatch + wrong key → fails
  const hdrObj = JSON.parse(new TextDecoder().decode(parts.header));
  const saltChars = hdrObj.kdf.salt.split('');
  saltChars[0] = saltChars[0] === 'A' ? 'B' : 'A';
  hdrObj.kdf.salt = saltChars.join('');
  const headerTampered = assemble(parts.magic, hdrObj, parts.body, parts.recovery);
  await assertThrows(() => unpackVault(headerTampered, GOOD_PASS), 'mutated header salt rejected');

  // 4. F1 — param-bomb rejected before deriveKey (returns fast, no OOM).
  const bombObj = JSON.parse(new TextDecoder().decode(parts.header));
  bombObj.kdf.memory_cost = 10_000_000; // ~10 GB — hostile
  const bombFile = assemble(parts.magic, bombObj, parts.body, parts.recovery);
  const t0 = process.hrtime.bigint();
  await assertThrows(() => unpackVault(bombFile, GOOD_PASS), 'param-bomb rejected');
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert(elapsedMs < 500, `param-bomb rejected FAST (was ${elapsedMs.toFixed(1)}ms, no allocation)`);

  // 5. F3 — weak passphrase rejected on write.
  await assertThrows(() => packVault(makeContents(), 'short'), 'weak passphrase rejected on write');
  await assertThrows(() => packVault(makeContents(), 'elevenchars'), '11-char passphrase rejected (floor is 12)');
  assert(MIN_PASSPHRASE_LENGTH >= 12, 'passphrase floor is at least 12');

  // 6. Wrong passphrase → generic failure, no safe word in the error.
  await assertThrowsMatch(
    () => unpackVault(packed, 'wrong passphrase entirely'),
    /wrong passphrase|could not open/i,
    'wrong passphrase → generic failure',
  );
  try {
    await unpackVault(packed, 'wrong passphrase entirely');
  } catch (e) {
    assert(!String((e as Error).message).includes(SAFE_WORD), 'wrong-passphrase error does not leak safe word');
  }

  // 7. v2 legacy file refused with actionable message.
  const v2 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x02, 0, 0, 0, 2, 123, 125]);
  await assertThrowsMatch(() => readVaultHeader(v2.buffer), /legacy v2/i, 'v2 refusal is actionable');

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

  // ★ 9. RECOVERY DUAL-ENVELOPE — the v4 fix. Do-No-Harm round-trip.
  const bundle: PrivateKeyBundle = {
    classical_private_key: 'CLASSICAL-ED25519-PRIV-KEY-ABCDEF',
    classical_passphrase: 'pgp-key-passphrase-xyz',
    pq_signing_secret_key: 'ML-DSA-87-SECRET-KEY-BASE64',
    pq_kem_secret_key: 'ML-KEM-1024-SECRET-KEY-BASE64',
  };
  const { vault: keyVault, shards, seedPhrase } = await createKeyVault(bundle, 3, 5, 'FEEDFACEFEEDFACE');

  const withRecovery = makeContents();
  withRecovery.recovery = keyVault; // exactly what ContactManagement.tsx passes at export
  const packed4 = await packVault(withRecovery, GOOD_PASS);
  assert(readVaultHeader(packed4).version === 4, 'recovery export is v4');

  // The whole point: extract the recovery vault with NO passphrase.
  const kv = extractRecoveryVault(packed4);
  assert(kv.master_secret_hash === keyVault.master_secret_hash, 'recovery envelope survives passphrase-free extraction');

  // Path 1: lost passphrase, recover via SEED PHRASE → identity byte-for-byte.
  const viaSeed = await recoverFromSeedPhrase(kv, seedPhrase);
  assert(viaSeed.classical_private_key === bundle.classical_private_key, 'seed recovery rebuilds classical private key');
  assert(viaSeed.classical_passphrase === bundle.classical_passphrase, 'seed recovery rebuilds pgp passphrase');
  assert(viaSeed.pq_kem_secret_key === bundle.pq_kem_secret_key, 'seed recovery rebuilds PQ KEM secret');

  // Path 2: lost passphrase AND seed, recover via GUARDIAN SHARDS (3-of-5).
  const viaShards = await recoverFromShards(kv, shards.slice(0, 3));
  assert(viaShards.classical_private_key === bundle.classical_private_key, 'guardian (3-of-5) rebuilds identity');
  assert(viaShards.pq_signing_secret_key === bundle.pq_signing_secret_key, 'guardian recovery rebuilds PQ signing secret');

  // Daily unlock is UNCHANGED — passphrase still opens it, recovery vault still in the body.
  const { contents: dailyOut } = await unpackVault(packed4, GOOD_PASS);
  assert(dailyOut.identity.identity.name === 'Ada Lovelace', 'v4 daily passphrase unlock still works');
  assert(!!dailyOut.recovery, 'recovery KeyVault still present in the encrypted body (daily path intact)');

  // The recovery envelope reveals TYPE not IDENTITY — opaque ciphertext + params.
  const recText = new TextDecoder().decode(splitFile(packed4).recovery);
  assert(!recText.includes('Ada Lovelace'), 'recovery envelope does NOT leak name');
  assert(!recText.includes(SAFE_WORD), 'recovery envelope does NOT leak safe word');
  assert(!recText.includes(bundle.classical_private_key), 'recovery envelope does NOT leak plaintext private key');
  assert(!recText.includes('FEEDFACE'), 'recovery envelope does NOT leak fingerprint');

  // 10. MIGRATION — an existing v3 file still opens by passphrase; extract refuses it.
  const v3file = await packV3(makeContents(), GOOD_PASS);
  const { header: v3h, contents: v3c } = await unpackVault(v3file, GOOD_PASS);
  assert(v3h.version === 3, 'legacy v3 file reads as version 3');
  assert(v3c.identity.identity.name === 'Ada Lovelace', 'v3 daily unlock still works (existing backups not bricked)');
  await assertThrowsMatch(
    () => extractRecoveryVault(v3file),
    /re-export/i,
    'v3 extract refused with actionable re-export guidance',
  );

  // 11. A v4 file with NO recovery configured → honest "no recovery vault" error.
  const packedNoRec = await packVault(makeContents(), GOOD_PASS); // recovery === null
  await assertThrowsMatch(
    () => extractRecoveryVault(packedNoRec),
    /no recovery vault/i,
    'no-recovery extract fails honestly (no false promise)',
  );

  console.log(`\n✓ all ${passed} assertions passed`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
