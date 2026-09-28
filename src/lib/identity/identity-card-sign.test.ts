// src/lib/identity/identity-card-sign.test.ts
// (A) signed identity card — sign/verify round-trip + the pq_kem-swap tamper detection (spec §8).
// Real keys, generated once in before(). Run: npx tsx --test src/lib/identity/identity-card-sign.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import {
  signIdentityCard, verifySignedIdentityCard, type SignedIdentityCard,
  suiteFromKemLength, classifyImportedCard, buildSignedIdentityCard,
} from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';

// A §5 CANONICAL identity + card: openpgp (sign+enc) + REAL ML-KEM-1024 (1568B) / ML-DSA-87 (2592B)
// pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig) fp (NOT the 40-hex OpenPGP fp). Post-res1 the card-verify
// Invariant-1 (fingerprintMatchesKey) is canonical-only, so a card must carry its real FIPS-length pq
// that hashes to the claimed fp. Mirrors genesis + relay/mailbox-auth.test.ts makeCanonicalIdentity.
interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string; }
async function makeCanonicalId(name: string): Promise<CanonId> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
function canonCard(id: CanonId, over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.0', type: 'identity-exchange', created_at: '2026-08-17T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: '', ...over,
    },
  };
}

const passphrase = 'test-passphrase-0';
const otherPass = 'test-passphrase-1';

let privateKey: string, publicKey: string, fingerprint: string;
let malloryPriv: string, malloryPub: string, malloryFp: string;

before(async () => {
  ({ privateKey, publicKey } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.test' }], passphrase, format: 'armored',
  }));
  fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  ({ privateKey: malloryPriv, publicKey: malloryPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Mallory', email: 'm@example.test' }], passphrase: otherPass, format: 'armored',
  }));
  malloryFp = (await readKey({ armoredKey: malloryPub })).getFingerprint();
});

const b64 = (s: string) => Buffer.from(s).toString('base64');

/** Alice's identity card with a real fp↔key binding + placeholder pq keys (the signature covers them). */
function aliceCard(over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.0',
    type: 'identity-exchange',
    created_at: '2026-08-17T00:00:00.000Z',
    identity: {
      fingerprint,
      display_name: 'Alice',
      public_key: publicKey,
      email: 'alice@example.test',
      pq_sig_public_key: b64('alice-ml-dsa-pubkey'),
      pq_kem_public_key: b64('alice-ml-kem-pubkey'),
      next_authority_commitment: '',
      ...over,
    },
  };
}

test('round-trip (CANONICAL): a card signed by its own key verifies', async () => {
  const id = await makeCanonicalId('rt');
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
  assert.equal(await verifySignedIdentityCard(signed), true);
});

test('§8.1 THE threat — swapping pq_kem_public_key breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  const tampered: SignedIdentityCard = {
    ...signed,
    identity: { ...signed.identity, pq_kem_public_key: b64('attacker-ml-kem-pubkey') },
  };
  assert.equal(await verifySignedIdentityCard(tampered), false);
});

test('swapping pq_sig_public_key breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  const tampered: SignedIdentityCard = {
    ...signed,
    identity: { ...signed.identity, pq_sig_public_key: b64('attacker-ml-dsa-pubkey') },
  };
  assert.equal(await verifySignedIdentityCard(tampered), false);
});

test('tampering a scalar (display_name) breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  assert.equal(
    await verifySignedIdentityCard({ ...signed, identity: { ...signed.identity, display_name: 'Eve' } }),
    false,
  );
});

test('no signature field → false (branch-2 guard; the caller drops pq quietly)', async () => {
  const unsigned = aliceCard() as SignedIdentityCard; // no signature attached
  assert.equal(await verifySignedIdentityCard(unsigned), false);
});

test('fingerprint↔key mismatch → false (Invariant-1) even with a valid signature', async () => {
  const signed = await signIdentityCard(aliceCard({ fingerprint: malloryFp }), privateKey, passphrase);
  assert.equal(await verifySignedIdentityCard(signed), false);
});

test('attacker re-signs a swapped card with THEIR key but keeps the victim fingerprint → false', async () => {
  // Mallory swaps pq_kem, keeps Alice's fingerprint + public_key, signs with her OWN key.
  // fp↔key passes (Alice's pair), but the signature is against Alice's public_key while Mallory
  // signed → verifyWithEnvelope fails. The attacker cannot forge Alice's signature.
  const forged = await signIdentityCard(
    aliceCard({ pq_kem_public_key: b64('mallory-kem') }),
    malloryPriv, otherPass,
  );
  assert.equal(await verifySignedIdentityCard(forged), false);
});

test('structural: signature attaches TOP-LEVEL, not nested inside identity (§8.5)', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  assert.equal(typeof signed.signature, 'string');
  assert.equal((signed.identity as Record<string, unknown>).signature, undefined);
});

// ── §6 suite-length derivation (the ek length IS the suite discriminant) ─────────────
/** A base64 ML-KEM public key of exactly `n` decoded bytes (real length, placeholder bytes). */
const kemOfBytes = (n: number) => Buffer.from('k'.repeat(n)).toString('base64');

test('§6 suiteFromKemLength: 1568B → ML-KEM-1024 (Cat-5)', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(1568)), 'ML-KEM-1024');
});
test('§6 suiteFromKemLength: 1184B → ML-KEM-768 (Cat-3)', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(1184)), 'ML-KEM-768');
});
test('§6 downgrade-floor: 800B (ML-KEM-512) → undefined — below the svrnty floor, not accepted', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(800)), undefined);
});
test('§6 suiteFromKemLength: empty / non-base64 → undefined (never a false accept)', () => {
  assert.equal(suiteFromKemLength(''), undefined);
  assert.equal(suiteFromKemLength('not valid base64 !!'), undefined);
});

// ── §4 classifyImportedCard — the fail-closed 4-branch import table ──────────────────
test('classify branch 1: fp↔key mismatch → reject, no classical import, no pq', async () => {
  const signed = await signIdentityCard(aliceCard({ fingerprint: malloryFp }), privateKey, passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});
test('classify branch 1: malformed card (no identity) → reject', async () => {
  const d = await classifyImportedCard({ version: '1.0', type: 'identity-exchange' });
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
});
test('classify branch 2 (CANONICAL): fp OK, no signature → classical-only, quiet, pq dropped', async () => {
  const id = await makeCanonicalId('br2');
  const d = await classifyImportedCard(canonCard(id)); // canonCard carries no `signature`
  assert.equal(d.branch, 2);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'quiet');
});
test('classify branch 3 (CANONICAL): signature present but INVALID (tampered) → classical-only, LOUD, pq dropped', async () => {
  const id = await makeCanonicalId('br3');
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
  // fp↔key still passes (canonical fp intact); tampering display_name breaks only the signature → branch 3.
  const tampered = { ...signed, identity: { ...signed.identity, display_name: 'Eve' } };
  const d = await classifyImportedCard(tampered);
  assert.equal(d.branch, 3);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'loud');
});
test('CANONICAL-ONLY GATE (res1): a card with EMPTY pq → branch 1 (reject) — no v1/no-PQ signers in greenfield (was branch 4a pre-res1)', async () => {
  // Pre-res1, an empty-pq card from a "legit v1/no-PQ signer" imported classical-quiet (branch 4a) via the
  // 40-hex OpenPGP path. Post-res1 classifyImportedCard's fp-gate (fingerprintMatchesKey) is canonical-only:
  // empty pq → the canonical fp cannot be recomputed → fp↔key FALSE → branch 1 (reject). Greenfield has no
  // v1/no-PQ signers (Archie #130477 canonical-only), so 4a collapses to branch 1. [Flint: the 4a source
  // branch is now dead code — prune at your gate-semantics discretion.]
  const id = await makeCanonicalId('br4a');
  const signed = await signIdentityCard(canonCard(id, { pq_kem_public_key: '', pq_sig_public_key: '' }), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});
test('classify branch 4b (CANONICAL): valid sig, supported suite → STORE authenticated pq (both keys)', async () => {
  const id = await makeCanonicalId('br4b'); // real ML-KEM-1024 (1568B) + ML-DSA-87 (2592B) pq
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4b');
  assert.equal(d.suite, 'ML-KEM-1024');
  assert.equal(d.importClassical, true);
  assert.equal(d.alarm, 'quiet');
  assert.deepEqual(d.pq, { pq_kem_public_key: id.kemB64, pq_sig_public_key: id.sigB64 });
});
test('CANONICAL-ONLY GATE (res1): a card with a WRONG-LENGTH suite → branch 1 (reject) — the fp-gate needs FIPS-length canonical pq (was branch 4c pre-res1)', async () => {
  // Pre-res1, an unsupported-suite (wrong-length kem) card imported classical soft-info (branch 4c) via the
  // 40-hex path. Post-res1 the fp-gate is canonical-only: a non-FIPS-length kem → the canonical fp cannot be
  // recomputed → fp↔key FALSE → branch 1 (reject). Greenfield canonical-only (Archie #130477); 4c collapses
  // to branch 1. [Flint: the 4c source branch is now dead code — prune at your gate-semantics discretion.]
  const id = await makeCanonicalId('br4c');
  const signed = await signIdentityCard(canonCard(id, { pq_kem_public_key: kemOfBytes(999) }), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});

// ── SEND-side buildSignedIdentityCard — the REAL Grow/QR/copy path. The tests above build cards via
// signIdentityCard(canonCard(...)) DIRECTLY, bypassing buildSignedIdentityCard — which is exactly HOW the
// empty-pq-legs beat-3 bug shipped untested. These lock the wrapper-shape fix + the build-time guard.
test('buildSignedIdentityCard (WRAPPER shape, genesis): carries REAL pq legs — post_quantum at the wrapper top-level is read (beat-3 regression lock)', async () => {
  const id = await makeCanonicalId('grow-wrap');
  // Genesis identity WRAPPER: post_quantum is a SIBLING of nested `.identity` (browser-identity.ts:163),
  // NOT inside `.identity`. Pre-fix, buildSignedIdentityCard read idData.post_quantum (the unwrapped nested
  // identity) → undefined → empty legs → the grown card was rejected by every peer (beat-3).
  const pin = 'a'.repeat(64);
  const wrapper = {
    identity: { fingerprint: id.fingerprint, public_key: id.publicKey, display_name: 'Alice' },
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
    next_authority_commitment: pin,
  };
  const signed = await buildSignedIdentityCard(wrapper, id.privateKey, id.passphrase);
  assert.equal(signed.version, '1.1');
  assert.equal(signed.identity.next_authority_commitment, pin);
  assert.equal(signed.identity.pq_kem_public_key, id.kemB64);
  assert.equal(signed.identity.pq_sig_public_key, id.sigB64);
  assert.ok(signed.identity.pq_kem_public_key.length > 0 && signed.identity.pq_sig_public_key.length > 0);
  // …and the card self-binds: a peer's classify does NOT reject it.
  const d = await classifyImportedCard(signed);
  assert.notEqual(d.branch, 1);
});
test('buildSignedIdentityCard (FLAT shape): reads post_quantum beside fingerprint (both identity shapes supported)', async () => {
  const id = await makeCanonicalId('grow-flat');
  const flat = {
    fingerprint: id.fingerprint, public_key: id.publicKey, display_name: 'Alice',
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
  };
  const signed = await buildSignedIdentityCard(flat, id.privateKey, id.passphrase);
  assert.equal(signed.identity.pq_kem_public_key, id.kemB64);
  assert.equal(signed.identity.pq_sig_public_key, id.sigB64);
});
test('buildSignedIdentityCard GUARD (N2 class-killer): a canonical fp with ABSENT pq legs is UNINSTANTIABLE — throws at build, not caught downstream at a peer', async () => {
  const id = await makeCanonicalId('grow-nopq');
  // Canonical fp (claims 4 keys) but the wrapper carries NO post_quantum → empty legs. This is exactly the
  // beat-3 shape; the guard MUST refuse to construct it at the send-side.
  const wrapperNoPq = { identity: { fingerprint: id.fingerprint, public_key: id.publicKey } };
  await assert.rejects(
    () => buildSignedIdentityCard(wrapperNoPq, id.privateKey, id.passphrase),
    /self-inconsistent|does not bind/,
  );
});

// ── PQ-HYBRID card signing (§7): threading the ML-DSA-87 signing secret dual-signs the card; it
// re-verifies via the card's OWN carried pq_sig pubkey (self-supply — sound because the classical
// half signs OVER that field AND the canonical fp binds it), while classical cards still verify.
// Locks: send-thread + receive self-supply + backward-compat + anti-strip.
async function makeHybridId(name: string): Promise<{ identity: any; priv: string; pass: string; sigSecret: Uint8Array }> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint: fp } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  const identity = {
    identity: { fingerprint: fp, public_key: pub, display_name: name },
    post_quantum: { sig_public_key: uint8ToBase64(pq.signing.publicKey), kem_public_key: uint8ToBase64(pq.kem.publicKey) },
  };
  return { identity, priv, pass, sigSecret: pq.signing.secretKey };
}

test('PQ-HYBRID: threading the PQ secret yields a dual-signed card that self-verifies (4b); classical still verifies; strip fails closed', async () => {
  const { identity, priv, pass, sigSecret } = await makeHybridId('hybrid-alice');

  // HYBRID: pass the ML-DSA signing secret → the card carries a pq_signature.
  const hybrid = await buildSignedIdentityCard(identity, priv, pass, sigSecret);
  assert.ok(typeof hybrid.pq_signature === 'string' && hybrid.pq_signature.length > 0, 'card must carry an ML-DSA pq_signature');

  // Verifies with NO explicit pq pubkey — self-supplied from the card's carried, sig-bound pq_sig_public_key.
  assert.equal(await verifySignedIdentityCard(hybrid), true, 'hybrid card self-verifies');
  const dispHybrid = await classifyImportedCard(hybrid);
  assert.equal(dispHybrid.branch, '4b');
  assert.equal(dispHybrid.alarm, 'quiet');

  // BACKWARD-COMPAT: the SAME identity signed classically (omit the secret) still verifies + imports 4b.
  const classical = await buildSignedIdentityCard(identity, priv, pass);
  assert.equal(classical.pq_signature, undefined, 'classical card carries no pq_signature');
  assert.equal(await verifySignedIdentityCard(classical), true, 'classical card still verifies (backward compat)');

  // ANTI-STRIP: deleting the carried pq_sig pubkey to dodge the ML-DSA check breaks the canonical
  // fingerprint binding (fp = H(sign‖enc‖kem‖sig)) → rejected at Invariant-1 (branch 1), never a
  // silent downgrade. (The classical half also signs over the field, so tampering is caught twice.)
  const stripped = { ...hybrid, identity: { ...hybrid.identity, pq_sig_public_key: '' } } as SignedIdentityCard;
  assert.equal(await verifySignedIdentityCard(stripped), false, 'stripping the carried pq_sig pubkey fails closed');
  assert.equal((await classifyImportedCard(stripped)).branch, 1);
});

// Flint PR#146 required-fix guard: self-supply newly makes the pq_signature base64-decode reachable,
// so a malformed pq_signature must FAIL CLOSED (branch 3, loud), never throw out of verify.
test('PQ-HYBRID guard: a malformed-base64 pq_signature returns false → branch 3 (never throws)', async () => {
  const { identity, priv, pass, sigSecret } = await makeHybridId('hybrid-garbage');
  const hybrid = await buildSignedIdentityCard(identity, priv, pass, sigSecret);
  // Valid classical sig + valid carried pq_sig pubkey, but a GARBAGE (non-base64) pq_signature.
  // Pre-guard, self-supply → base64ToUint8(atob) → THROW; post-guard → false.
  const garbage = { ...hybrid, pq_signature: '!!! not base64 !!!' } as SignedIdentityCard;
  assert.equal(await verifySignedIdentityCard(garbage), false); // returns (does not throw)
  const disp = await classifyImportedCard(garbage);
  assert.equal(disp.branch, 3);
  assert.equal(disp.alarm, 'loud');
});

// Anti-downgrade lock: stripping the pq_signature but KEEPING the pq_sig pubkey (attempt to force the
// card back to classical-only) flips the derived suite HYBRID→CLASSICAL → the signed bytes change →
// the classical sig no longer verifies → branch 3 (loud), never a silent classical accept.
test('PQ-HYBRID guard: stripping pq_signature (keeping pubkey) → branch 3, not a silent downgrade', async () => {
  const { identity, priv, pass, sigSecret } = await makeHybridId('hybrid-stripsig');
  const hybrid = await buildSignedIdentityCard(identity, priv, pass, sigSecret);
  const { pq_signature, ...noSig } = hybrid;
  void pq_signature;
  const stripped = noSig as SignedIdentityCard;
  assert.equal(await verifySignedIdentityCard(stripped), false);
  assert.equal((await classifyImportedCard(stripped)).branch, 3);
});
