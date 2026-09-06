// src/lib/identity/recovery-canonical.selftest.ts
//
// Framework-free proof that RESTORE reconstructs the CANONICAL identity (Res#1)
// instead of silently downgrading it to classical. Sibling of vault.selftest.ts ★9.
// Run:  npx tsx src/lib/identity/recovery-canonical.selftest.ts
//
// The bug (pre-fix): restore derived a 40-hex OpenPGP fp and dropped post_quantum, so
// a canonical identity came back CLASSICAL → canonical-only verify fails everywhere
// (seedVaultRestore.ts:78 getFingerprint / vaultPassphraseRestore.ts:55 ===40 reject).
//
// The fix (Flint part 2): reconstructCanonicalIdentityForRestore rebuilds the 64-hex
// canonical fp from the four pubkeys — sign+enc derived from the UNLOCKED private key
// (classical anti-poison, never the carried public), kem+sig from the carried/stored
// pubs VERIFIED against the vault SECRETS via ML-DSA sign/verify + ML-KEM encap/decap
// round-trip (PQ anti-poison) — and repopulates post_quantum.
//
// This selftest is the BUILD-TO-THE-TEST spec for that fn: it runs the harness green
// now (mint -> export -> recover -> part-1 pub carry) and PENDs (exit 2) until part 2
// lands, then asserts the reconstruction + anti-poison + graceful legacy-fail.

import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle } from '../crypto/pq';
import { createKeyVault, recoverFromSeedPhrase, type PrivateKeyBundle } from '../crypto/recovery';
import * as fpmod from './fingerprint';
import { mintCanonicalFingerprint, fingerprintMatchesKey } from './fingerprint';

const PASS = 'recovery-canonical-selftest-passphrase';
let passed = 0;

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`  ✗ FAIL: ${msg}`);
    process.exit(1);
  }
  passed++;
  console.log(`  ✓ ${msg}`);
}

async function assertThrowsMatch(fn: () => Promise<unknown>, re: RegExp, msg: string): Promise<void> {
  try {
    await fn();
  } catch (e) {
    const m = String((e as Error).message);
    if (re.test(m)) {
      passed++;
      console.log(`  ✓ ${msg} (threw: "${m}")`);
      return;
    }
    console.error(`  ✗ FAIL: ${msg} — threw, but message did not match ${re}: "${m}"`);
    process.exit(1);
  }
  console.error(`  ✗ FAIL (expected throw): ${msg}`);
  process.exit(1);
}

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');
const unlock = async (armored: string, pp: string) => {
  const k = await readPrivateKey({ armoredKey: armored });
  return k.isDecrypted() ? k : decryptKey({ privateKey: k, passphrase: pp });
};

async function main(): Promise<void> {
  console.log('recovery-canonical.selftest — restore reconstructs the canonical identity (Res#1)\n');

  // ── Mint a REAL canonical identity (genesis-equivalent: 4 keys → SHA256(sign‖enc‖kem‖sig)). ──
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Recover Test', email: 'rt@example.test' }],
    passphrase: PASS,
    format: 'armored',
  });
  const unlocked = await unlock(privateKey, PASS);
  const pq = generatePQKeypairBundle();
  const minted = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  const CANON = minted.fingerprint;
  assert(/^[0-9a-f]{64}$/.test(CANON), 'minted canonical fp is 64-hex');
  assert(
    (await fingerprintMatchesKey(CANON, publicKey, {
      kem_public_key: b64(pq.kem.publicKey),
      sig_public_key: b64(pq.signing.publicKey),
    })) === true,
    'minted identity passes canonical-only verify (fingerprintMatchesKey)',
  );

  // ── Build the PrivateKeyBundle WITH pq pubs (part 1), export, recover via seed. ──
  const bundle: PrivateKeyBundle = {
    classical_private_key: privateKey,
    classical_passphrase: PASS,
    pq_signing_secret_key: b64(pq.signing.secretKey),
    pq_kem_secret_key: b64(pq.kem.secretKey),
    pq_signing_public_key: b64(pq.signing.publicKey), // part 1: carried at genesis
    pq_kem_public_key: b64(pq.kem.publicKey), // part 1: carried at genesis
  };
  const { vault, seedPhrase } = await createKeyVault(bundle, 3, 5, CANON);
  const recovered = await recoverFromSeedPhrase(vault, seedPhrase);
  assert(recovered.classical_private_key === privateKey, 'seed recovery round-trips the classical private key');
  assert(
    recovered.pq_signing_public_key === bundle.pq_signing_public_key,
    'seed recovery round-trips the ML-DSA-87 public key (part 1 carry survives vault round-trip)',
  );
  assert(
    recovered.pq_kem_public_key === bundle.pq_kem_public_key,
    'seed recovery round-trips the ML-KEM-1024 public key (part 1 carry survives vault round-trip)',
  );

  // ── BUILD-TO-THE-TEST gate: reconstruct fn is Flint's part 2. ──
  const reconstruct = (fpmod as Record<string, unknown>).reconstructCanonicalIdentityForRestore as
    | undefined
    | ((a: {
        decryptedIdentityKey: unknown;
        pqKemPublicKeyB64?: string;
        pqSigPublicKeyB64?: string;
        pqKemSecretKeyB64: string;
        pqSigSecretKeyB64: string;
        claimedFingerprint: string;
      }) => Promise<{
        fingerprint: string;
        post_quantum: { sig_algorithm: string; sig_public_key: string; kem_algorithm: string; kem_public_key: string };
      }>);

  if (typeof reconstruct !== 'function') {
    console.log('\n  ⏳ PENDING: reconstructCanonicalIdentityForRestore not yet exported from ./fingerprint (Flint part 2).');
    console.log(
      `  ✓ harness GREEN (${passed} assertions): mint → export → recover + part-1 pub-carry verified.\n` +
        '    Reconstruct + anti-poison + graceful-fail assertions activate when part 2 lands.',
    );
    process.exit(2); // non-zero = not-yet-complete (honest); flips to 0 when part 2 lands
  }

  const recoveredUnlocked = await unlock(recovered.classical_private_key, recovered.classical_passphrase);

  // ── SEED path: reconstruct from the recovered bundle's stored pubs (part 1). ──
  const seedOut = await reconstruct({
    decryptedIdentityKey: recoveredUnlocked,
    pqKemPublicKeyB64: recovered.pq_kem_public_key,
    pqSigPublicKeyB64: recovered.pq_signing_public_key,
    pqKemSecretKeyB64: recovered.pq_kem_secret_key,
    pqSigSecretKeyB64: recovered.pq_signing_secret_key,
    claimedFingerprint: CANON,
  });
  assert(seedOut.fingerprint === CANON, 'SEED path: reconstructed fp === original canonical 64-hex (no downgrade)');
  assert(
    seedOut.post_quantum?.kem_algorithm === 'ML-KEM-1024' && seedOut.post_quantum?.sig_algorithm === 'ML-DSA-87',
    'SEED path: post_quantum repopulated (ML-KEM-1024 + ML-DSA-87)',
  );
  assert(
    (await fingerprintMatchesKey(seedOut.fingerprint, publicKey, {
      kem_public_key: seedOut.post_quantum.kem_public_key,
      sig_public_key: seedOut.post_quantum.sig_public_key,
    })) === true,
    'SEED path: reconstructed identity passes canonical-only verify',
  );

  // ── VAULT path: same fn, pubs sourced as-if carried in VaultContents.identity.post_quantum. ──
  const vaultOut = await reconstruct({
    decryptedIdentityKey: recoveredUnlocked,
    pqKemPublicKeyB64: b64(pq.kem.publicKey),
    pqSigPublicKeyB64: b64(pq.signing.publicKey),
    pqKemSecretKeyB64: recovered.pq_kem_secret_key,
    pqSigSecretKeyB64: recovered.pq_signing_secret_key,
    claimedFingerprint: CANON,
  });
  assert(vaultOut.fingerprint === CANON, 'VAULT path: reconstructed fp === original canonical 64-hex');

  // ── LEGACY graceful-fail: pre-format-bump bundle (no pq pubs) → /re-export/i, NOT silent downgrade. ──
  await assertThrowsMatch(
    () =>
      reconstruct({
        decryptedIdentityKey: recoveredUnlocked,
        pqKemPublicKeyB64: undefined,
        pqSigPublicKeyB64: undefined,
        pqKemSecretKeyB64: recovered.pq_kem_secret_key,
        pqSigSecretKeyB64: recovered.pq_signing_secret_key,
        claimedFingerprint: CANON,
      }),
    /re-export/i,
    'LEGACY (no pq pubs): fails with actionable /re-export/i (no silent classical downgrade)',
  );

  // ── POISONED: pq pub does not match its secret → anti-poison round-trip fails → /integrity/i. ──
  const otherPq = generatePQKeypairBundle();
  await assertThrowsMatch(
    () =>
      reconstruct({
        decryptedIdentityKey: recoveredUnlocked,
        pqKemPublicKeyB64: b64(otherPq.kem.publicKey),
        pqSigPublicKeyB64: b64(otherPq.signing.publicKey),
        pqKemSecretKeyB64: recovered.pq_kem_secret_key,
        pqSigSecretKeyB64: recovered.pq_signing_secret_key,
        claimedFingerprint: CANON,
      }),
    /integrity/i,
    'POISONED (pub↔secret mismatch): anti-poison round-trip fails with /integrity/i',
  );

  // ── FP-MISMATCH: right keys, wrong claimed fingerprint → /does not match/i. ──
  await assertThrowsMatch(
    () =>
      reconstruct({
        decryptedIdentityKey: recoveredUnlocked,
        pqKemPublicKeyB64: recovered.pq_kem_public_key,
        pqSigPublicKeyB64: recovered.pq_signing_public_key,
        pqKemSecretKeyB64: recovered.pq_kem_secret_key,
        pqSigSecretKeyB64: recovered.pq_signing_secret_key,
        claimedFingerprint: 'f'.repeat(64),
      }),
    /does not match/i,
    'FP-MISMATCH (wrong claimedFingerprint): fails with /does not match/i',
  );

  console.log(
    `\n✓ all ${passed} assertions passed — restore reconstructs canonical (no downgrade), anti-poison holds, legacy fails gracefully`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
