// src/lib/identity/recovery-canonical.selftest.ts
//
// Standalone, framework-free proof of the RESTORE-path canonical-fp reconstruction.
// Run:  npx tsx src/lib/identity/recovery-canonical.selftest.ts
// Exits non-zero on the first failed assertion. Pure crypto round-trip — no browser,
// no Playwright (OpenPGP ed25519 + ML-KEM-1024 + ML-DSA-87 run fine under Node 22).
//
// The bug this guards (same CLASS as beat-3, but in RESTORE): under canonical-only
// (Res#1) a restored identity MUST come back as the SAME canonical 64-hex fp with its
// post_quantum legs repopulated — never silently downgraded to a classical id.
// reconstructCanonicalIdentityForRestore rebuilds the canonical fp from RECOVERED key
// material WITHOUT trusting any carried public key (anti-poison), then refuses unless
// the recomputed fp equals the backup's claimed fp. Both restore adapters
// (seedVaultRestore + vaultPassphraseRestore) call it.
//
// Covers:
//   1. HAPPY ROUND-TRIP: mint canonical (genesis) → reconstruct (restore) → the SAME
//      64-hex fp + post_quantum {ML-DSA-87, ML-KEM-1024} repopulated with the orig pubs.
//   2. LEGACY (pre-PQ-pub backup): PQ pubs absent → graceful, actionable re-export
//      guidance (NEVER a silent classical downgrade).
//   3. ANTI-POISON (PQ KEM): a foreign-but-valid KEM pub → integrity refusal.
//   4. ANTI-POISON (PQ SIG): a foreign-but-valid SIG pub → integrity refusal.
//   5. ANTI-POISON (classical): a foreign unlocked private key → fp-mismatch refusal
//      (a crafted vault cannot substitute a foreign classical key: private-key↔fp bind).
//   6. fp MISMATCH: a tampered claimed fingerprint → integrity refusal.
//   7. MALFORMED PQ: a truncated KEM pub (wrong FIPS length) → refusal.

import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import {
  mintCanonicalFingerprint,
  reconstructCanonicalIdentityForRestore,
  KEM_PUB_LEN,
} from './fingerprint';
import { generatePQKeypairBundle, uint8ToBase64, type PQKeypairBundle } from '../crypto/pq';

let passed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  ✗ FAIL: ${msg}`);
    process.exit(1);
  }
  passed++;
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

/**
 * Mint a full identity EXACTLY as genesis does (browser-identity.ts): an ed25519 PGP
 * key + an ML-KEM-1024 / ML-DSA-87 bundle, with a canonical fp committing all four
 * public keys (sign ‖ enc ‖ kem ‖ sig).
 */
async function mintIdentity(name: string, email: string): Promise<{
  unlocked: any;
  pq: PQKeypairBundle;
  fingerprint: string;
}> {
  const passphraseBytes = new Uint8Array(32);
  crypto.getRandomValues(passphraseBytes);
  const passphrase = btoa(String.fromCharCode(...passphraseBytes));
  const { privateKey } = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name, email }],
    passphrase,
    format: 'armored',
  });
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const pq = generatePQKeypairBundle();
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  return { unlocked, pq, fingerprint };
}

async function main(): Promise<void> {
  console.log('recovery-canonical.selftest — RESTORE-path canonical-fp reconstruction (§5)');

  // Genesis: mint identity A (backed up + restored) and a FOREIGN identity B (source of
  // valid-but-non-matching key material for the anti-poison cases).
  const A = await mintIdentity('Ada Lovelace', 'ada@example.com');
  const B = await mintIdentity('Blaise Pascal', 'blaise@example.com');

  const kemPubB64 = uint8ToBase64(A.pq.kem.publicKey);
  const sigPubB64 = uint8ToBase64(A.pq.signing.publicKey);
  const kemSecB64 = uint8ToBase64(A.pq.kem.secretKey);
  const sigSecB64 = uint8ToBase64(A.pq.signing.secretKey);

  assert(/^[0-9a-f]{64}$/.test(A.fingerprint), 'genesis mints a canonical 64-hex fp');
  assert(A.fingerprint !== B.fingerprint, 'two identities → distinct canonical fps (fp commits the keys)');

  // 1. HAPPY ROUND-TRIP — restore reconstructs the SAME canonical id + repopulates PQ.
  const out = await reconstructCanonicalIdentityForRestore({
    decryptedIdentityKey: A.unlocked,
    pqKemPublicKeyB64: kemPubB64,
    pqSigPublicKeyB64: sigPubB64,
    pqKemSecretKeyB64: kemSecB64,
    pqSigSecretKeyB64: sigSecB64,
    claimedFingerprint: A.fingerprint,
  });
  assert(out.fingerprint === A.fingerprint, 'restore reconstructs the SAME canonical fp (round-trip)');
  assert(/^[0-9a-f]{64}$/.test(out.fingerprint), 'reconstructed fp is canonical 64-hex');
  assert(out.post_quantum.sig_algorithm === 'ML-DSA-87', 'post_quantum.sig_algorithm repopulated');
  assert(out.post_quantum.kem_algorithm === 'ML-KEM-1024', 'post_quantum.kem_algorithm repopulated');
  assert(out.post_quantum.sig_public_key === sigPubB64, 'post_quantum sig pub repopulated (matches genesis)');
  assert(out.post_quantum.kem_public_key === kemPubB64, 'post_quantum kem pub repopulated (matches genesis)');

  // 2. LEGACY — a pre-format-bump backup carries PQ secrets but NO PQ pubs. ML-DSA's
  //    public key is not derivable from its secret via @noble, so the canonical fp
  //    cannot be reconstructed → graceful, actionable re-export (no silent downgrade).
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: A.unlocked,
        pqKemPublicKeyB64: undefined,
        pqSigPublicKeyB64: undefined,
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: A.fingerprint,
      }),
    /re-export/i,
    'legacy (no PQ pubs) → actionable re-export guidance (no silent classical downgrade)',
  );

  // 3. ANTI-POISON (PQ KEM) — a foreign-but-valid KEM pub with A's KEM secret fails the
  //    ML-KEM encap→decap correspondence round-trip.
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: A.unlocked,
        pqKemPublicKeyB64: uint8ToBase64(B.pq.kem.publicKey), // foreign
        pqSigPublicKeyB64: sigPubB64,
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: A.fingerprint,
      }),
    /integrity/i,
    'poisoned KEM pub (foreign) → integrity refusal',
  );

  // 4. ANTI-POISON (PQ SIG) — a foreign-but-valid SIG pub with A's SIG secret fails the
  //    ML-DSA sign→verify correspondence round-trip.
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: A.unlocked,
        pqKemPublicKeyB64: kemPubB64,
        pqSigPublicKeyB64: uint8ToBase64(B.pq.signing.publicKey), // foreign
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: A.fingerprint,
      }),
    /integrity/i,
    'poisoned SIG pub (foreign) → integrity refusal',
  );

  // 5. ANTI-POISON (classical) — a crafted vault substitutes a FOREIGN unlocked private
  //    key. A's PQ round-trips pass (self-consistent), but sign+enc derived from B →
  //    a different canonical fp → refusal. This is the private-key↔fp bind: the fn never
  //    trusts a carried public key.
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: B.unlocked, // FOREIGN classical key
        pqKemPublicKeyB64: kemPubB64,
        pqSigPublicKeyB64: sigPubB64,
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: A.fingerprint,
      }),
    /does not match/i,
    'foreign classical key → fp-mismatch refusal (private-key↔fp bind)',
  );

  // 6. fp MISMATCH — a tampered claimed fingerprint (flip the first nibble).
  const tampered = (A.fingerprint[0] === 'a' ? 'b' : 'a') + A.fingerprint.slice(1);
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: A.unlocked,
        pqKemPublicKeyB64: kemPubB64,
        pqSigPublicKeyB64: sigPubB64,
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: tampered,
      }),
    /does not match/i,
    'tampered claimed fp → integrity refusal',
  );

  // 7. MALFORMED PQ — a truncated KEM pub (wrong FIPS length) is rejected up front.
  await assertThrowsMatch(
    () =>
      reconstructCanonicalIdentityForRestore({
        decryptedIdentityKey: A.unlocked,
        pqKemPublicKeyB64: uint8ToBase64(A.pq.kem.publicKey.slice(0, KEM_PUB_LEN - 1)), // truncated
        pqSigPublicKeyB64: sigPubB64,
        pqKemSecretKeyB64: kemSecB64,
        pqSigSecretKeyB64: sigSecB64,
        claimedFingerprint: A.fingerprint,
      }),
    /integrity|length/i,
    'truncated KEM pub → integrity/length refusal',
  );

  console.log(`\n✓ all ${passed} assertions passed`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
