// Test helper: turn a REAL current-format export into an older-format backup file (no BODY_LEN, no recovery envelope outside the body, AAD = MAGIC_V3 || header),
// the same layout vault.selftest.ts packV3 crafts. The body keeps the owner's recovery vault, as the older exporter packed it, unless dropRecovery says the exporting device had none.
import { unpackVault } from '../src/lib/sync/vault';
import { deriveKeyArgon2id, defaultArgon2Params, aesGcmEncrypt, toBase64, randomBytes, SALT_LENGTH, IV_LENGTH } from '../src/lib/crypto/kdf';

const MAGIC_V3 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x03]);
const MAGIC_LEN = 8;
const HEADER_LEN_SIZE = 4;

export async function downgradeToOldFormat(v4: ArrayBuffer, passphrase: string, opts?: { dropRecovery?: boolean }): Promise<ArrayBuffer> {
  const unpacked = await unpackVault(v4, passphrase);
  // dropRecovery models an exporting device that had NO recovery KeyVault stored: the body's `recovery` is null.
  const contents = opts?.dropRecovery ? { ...unpacked.contents, recovery: null } : unpacked.contents;
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
  out.set(MAGIC_V3, o); o += MAGIC_LEN;
  new DataView(out.buffer).setUint32(o, headerBytes.length, false); o += HEADER_LEN_SIZE;
  out.set(headerBytes, o); o += headerBytes.length;
  out.set(body, o);
  return out.buffer;
}
