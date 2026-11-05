// src/lib/crypto/argon2-core.ts
// The pure passphrase-BYTES → key derivation shared by the Argon2 worker (argon2-worker.ts) and its
// node/SSR fallback (argon2-async.ts). Kept in its own module so both paths run IDENTICAL derivation
// logic and it is unit-testable in node without a Worker global (task #542).
//
// It decodes the transferred passphrase bytes to the string deriveKeyArgon2id expects, derives (F1
// param-guard + argon2id come along verbatim → byte-identical to the sync path), copies the key into
// its own exact-size buffer (transferable), and zeros both the derivation key and the passphrase bytes.
import { deriveKeyArgon2id, type Argon2Params } from './kdf';

export function deriveKeyFromPassphraseBytes(
  passphraseBytes: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
): Uint8Array {
  const passphrase = new TextDecoder().decode(passphraseBytes);
  // F1 (assertParamsWithinLimits) fires INSIDE deriveKeyArgon2id, before the 64 MiB allocation.
  const key = deriveKeyArgon2id(passphrase, salt, params);
  const out = new Uint8Array(key); // exact-size copy in its own buffer → transferable out of the worker
  key.fill(0);
  passphraseBytes.fill(0); // zero the (transferred) passphrase bytes
  return out;
}
