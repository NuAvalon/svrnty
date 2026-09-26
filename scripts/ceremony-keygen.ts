// scripts/ceremony-keygen.ts — REAL Node Zero ceremony keygen (b-MINIMAL pure release-signing root).
//
// Replaces the THROWAWAY scripts/gen-test-genesis.ts for the real G0 mint. gen-test-genesis fakes
// enc/kem as random pubkeys with NO held secret (→ undecryptable identity + permanent lineage-lock)
// and emits no rotation-authority/nac. This tool generates REAL, HELD, seed-based keys and the
// rotation-authority commitment, all reproducible from a SINGLE cold-seed backup.
//
// ── MODEL (Apollo A2 / Flint gate #142625 A2, Peter b-MINIMAL #142663 · 2FA: Peter #143240, Archie BUILD-GO #143272, Flint reqs #143258) ──
//   masterSecret (32B) is the ONE root. Every identity key AND the rotation authority derive from it
//   via domain-separated HKDF-SHA256 — the SAME construction the rotation authority already uses
//   (fingerprint.ts rotationAuthorityLeg). "No new crypto for a forever-key": HKDF-SHA256, ed25519,
//   x25519, ML-DSA-87, ML-KEM-1024 — all already in-tree and FIPS-standard.
//
//   ── 2FA FRONT-DOOR (b) ── masterSecret is NO LONGER a raw CSPRNG value that gets backed up directly.
//   It is DERIVED from TWO required factors: masterSecret = scrypt(seed, password)  (node-zero-2fa.ts).
//     • seed     = 32B CSPRNG → backed up as the SEED PHRASE (factor 1)
//     • password = operator "spell" → sealed independently (factor 2)
//   BOTH are required to re-materialize; a found seed phrase ALONE is insufficient (Peter's ask). scrypt
//   is memory-hard (~256MB, N=2^18) so a seed-thief pays a full evaluation per password guess. The ONLY new
//   crypto vs the prior model is this one scrypt front-door — deriveNodeZero(masterSecret) below is
//   BYTE-IDENTICAL, so `--selftest` on a fixed masterSecret reproduces the prior vectors exactly (the
//   lower layer is provably unperturbed). Cold backup = seed phrase + sealed password (two independent
//   sealed backups, Flint req 5). The masterSecret itself is ephemeral — derived, used, wiped.
//
//   b-MINIMAL: Node Zero is a PURE release-signing root — no card / no satellite / no openpgp / no
//   app-load. enc/kem are generated REAL+HELD anyway because the canonical fingerprint COMMITS them
//   (fp = SHA256(sign‖enc‖kem‖sig)); random enc/kem would permanently commit an undecryptable identity
//   and forfeit the ability to add capability later without re-minting.
//
// ── FROZEN forever ── the four HKDF labels below AND the 2FA scheme (node-zero-2fa.ts: scrypt params,
//   salt-domain, input encoding, NFKD normalization) are part of key derivation for all time: recovering
//   Node Zero REQUIRES these exact bytes. GATED on Flint's independent byte-confirm before the real mint.
//   Do not edit without re-minting the identity.
//
// Runners:
//   Self-test — lower layer (deterministic, co-witnessable — NO artifacts; reproduces prior vectors):
//     npx tsx scripts/ceremony-keygen.ts --selftest [--master-hex <64hex>]
//   Self-test — 2FA front-door (deterministic, co-witnessable — NO artifacts):
//     npx tsx scripts/ceremony-keygen.ts --selftest-2fa [--seed-hex <64hex>] [--password <spell>] [--salt-hex <32hex>]
//   REAL mint (air-gap, ceremony only — CSPRNG seed+salt, writes artifacts, refuses on any KAT fail):
//     npx tsx scripts/ceremony-keygen.ts --out <dir> (--password <spell> | --password-file <f>) [--seedphrase-out <file>]
//   DR re-materialize (reconstruct an EXISTING genesis from BOTH factors; fp-asserted):
//     npx tsx scripts/ceremony-keygen.ts --out <dir> --seedphrase "<phrase>" (--password <spell> | --password-file <f>) \
//        --attestation <genesis-attestation.json>   (pulls salt+params+fp)   [or --salt-hex <32hex> --expect-fp <fp>]

import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
// @noble-only leaves (NO openpgp): canonical fp from fingerprint-canonical.ts, rotation-authority nac
// from rotation-authority.ts. Importing from fingerprint.ts here would drag openpgp (readKey) into the
// air-gap keygen bundle for zero function — the (A) RIDE ruling (Flint) severs it.
import {
  deriveCanonicalFingerprintHex,
  SIGN_PUB_LEN, ENC_PUB_LEN, KEM_PUB_LEN, SIG_PUB_LEN,
} from '../src/lib/identity/fingerprint-canonical';
import {
  deriveNextAuthorityCommitment,
  deriveNextAuthorityKeypair,
} from '../src/lib/identity/rotation-authority';
// recovery.js helpers are 32B↔hex-phrase generic. Under 2FA they carry the SEED (factor 1), not the
// masterSecret (which is now scrypt-derived, never backed up directly). Aliased at use-site for clarity.
import { generateMasterSecret, masterSecretToSeedPhrase, seedPhraseToMasterSecret } from '../src/lib/crypto/recovery.js';
// 2FA front-door (b): masterSecret = scrypt(seed, password). deriveNodeZero() below stays UNCHANGED.
import {
  deriveMasterSecret2FA, generate2FASalt, NODE_ZERO_2FA, FROZEN_SCRYPT_PARAMS, type ScryptParams,
} from '../src/lib/crypto/node-zero-2fa';

// ── FROZEN domain-separation labels (v1). Changing ANY label re-derives that key forever. GATED on Flint. ──
export const NODE_ZERO_HKDF_LABEL = {
  sign: 'svrnty:node-zero-identity:v1:sign', // ed25519 signing seed (32B)
  enc:  'svrnty:node-zero-identity:v1:enc',  // x25519 enc secret (32B — the secret scalar itself)
  dsa:  'svrnty:node-zero-identity:v1:dsa',  // ML-DSA-87 signing seed (32B)
  kem:  'svrnty:node-zero-identity:v1:kem',  // ML-KEM-1024 seed (64B = d‖z)
} as const;

// Genesis constants (epoch 0; nac commits the epoch-1 rotation authority).
export const GENESIS_EPOCH = 0;
export const NEXT_AUTHORITY_EPOCH = 1;
export const GENESIS_VERSION_COUNTER = 1;
export const GENESIS_GRAMMAR_VERSION = 1;

const b64 = (u8: Uint8Array): string => Buffer.from(u8).toString('base64');
const leg = (ms: Uint8Array, label: string, len: number): Uint8Array =>
  hkdf(sha256, ms, undefined, utf8ToBytes(label), len); // @noble v2: info MUST be bytes (string throws)

export interface NodeZeroSecrets {
  masterSecret: Uint8Array; // 32 — the SINGLE cold-seed root (backed up as seedPhrase)
  edSeed: Uint8Array;       // 32 — ed25519 signing seed (airgap-sign consumes via secret-seeds.json)
  dsaSeed: Uint8Array;      // 32 — ML-DSA-87 signing seed (airgap-sign consumes)
  encSeed: Uint8Array;      // 32 — x25519 enc secret (held; recoverable from masterSecret)
  kemSeed: Uint8Array;      // 64 — ML-KEM-1024 seed (held; recoverable from masterSecret)
  dsaSecret: Uint8Array;    // 4896 — ML-DSA-87 secret key
  kemSecret: Uint8Array;    // 3168 — ML-KEM-1024 secret key
}
export interface NodeZeroPubs {
  signPub: Uint8Array; encPub: Uint8Array; kemPub: Uint8Array; sigPub: Uint8Array;
}
export interface NodeZero {
  secrets: NodeZeroSecrets;
  pubs: NodeZeroPubs;
  fingerprint: string; // 64-hex SHA256(sign‖enc‖kem‖sig)
  nac: string;         // 64-hex SHA256(authEd‖authDsa) for epoch 1
}

/** PURE, deterministic derivation of the whole Node Zero identity from a 32B masterSecret. */
export function deriveNodeZero(masterSecret: Uint8Array): NodeZero {
  if (masterSecret.length !== 32) throw new Error(`masterSecret must be 32B, got ${masterSecret.length}`);
  const edSeed = leg(masterSecret, NODE_ZERO_HKDF_LABEL.sign, 32);
  const encSeed = leg(masterSecret, NODE_ZERO_HKDF_LABEL.enc, 32);
  const dsaSeed = leg(masterSecret, NODE_ZERO_HKDF_LABEL.dsa, 32);
  const kemSeed = leg(masterSecret, NODE_ZERO_HKDF_LABEL.kem, 64);

  const signPub = ed25519.getPublicKey(edSeed);
  const encPub = x25519.getPublicKey(encSeed);
  const dsa = ml_dsa87.keygen(dsaSeed);     // 32B seed → { publicKey 2592, secretKey 4896 }
  const kem = ml_kem1024.keygen(kemSeed);   // 64B seed → { publicKey 1568, secretKey 3168 }

  const pubs: NodeZeroPubs = { signPub, encPub, kemPub: kem.publicKey, sigPub: dsa.publicKey };
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, kem.publicKey, dsa.publicKey);
  const nac = deriveNextAuthorityCommitment(masterSecret, NEXT_AUTHORITY_EPOCH); // REUSED verbatim
  return {
    secrets: { masterSecret, edSeed, dsaSeed, encSeed, kemSeed, dsaSecret: dsa.secretKey, kemSecret: kem.secretKey },
    pubs, fingerprint, nac,
  };
}

export interface Kat { name: string; pass: boolean; detail: string }

/** Flint gate #142625 B1–B6 + FIPS lengths + domain-separation independence. All must pass to mint. */
export function runKats(masterSecret: Uint8Array): { nz: NodeZero; kats: Kat[]; allPass: boolean } {
  const nz = deriveNodeZero(masterSecret);
  const { secrets: s, pubs: p } = nz;
  const kats: Kat[] = [];
  const hx = bytesToHex;

  // B1 — SIGNER-FEED: the two signing seeds derive the attested signing pubs (airgap-sign step-3 passes).
  const b1a = hx(ed25519.getPublicKey(s.edSeed)) === hx(p.signPub);
  const b1b = hx(ml_dsa87.keygen(s.dsaSeed).publicKey) === hx(p.sigPub);
  kats.push({ name: 'B1 signer-feed: ed_seed→signPub & dsa_seed→sigPub', pass: b1a && b1b, detail: `ed=${b1a} dsa=${b1b}` });

  // B1+ — SIGN/VERIFY round-trip over a real preimage-shaped message (proves the held signing secrets work).
  const msg = utf8ToBytes('svrnty:ceremony-keygen:kat-signing-probe');
  const edOk = ed25519.verify(ed25519.sign(msg, s.edSeed), msg, p.signPub);
  const dsaOk = ml_dsa87.verify(ml_dsa87.sign(msg, s.dsaSecret), msg, p.sigPub);
  kats.push({ name: 'B1+ ed25519 & ML-DSA-87 sign/verify round-trip', pass: edOk && dsaOk, detail: `ed=${edOk} dsa=${dsaOk}` });

  // B2 — ENC round-trip: x25519 ECDH agrees both directions ⇒ enc private is REAL+HELD (not random-pub).
  const eph = x25519.utils.randomSecretKey();
  const ss1 = x25519.getSharedSecret(s.encSeed, x25519.getPublicKey(eph));
  const ss2 = x25519.getSharedSecret(eph, p.encPub);
  const b2 = hx(ss1) === hx(ss2);
  kats.push({ name: 'B2 enc x25519 ECDH round-trip (real+held)', pass: b2, detail: `ss-agree=${b2}` });

  // B3 — KEM round-trip: encapsulate(kemPub)→decapsulate(kemSecret) same ss ⇒ kem private REAL+HELD.
  const enc = ml_kem1024.encapsulate(p.kemPub);
  const b3 = hx(enc.sharedSecret) === hx(ml_kem1024.decapsulate(enc.cipherText, s.kemSecret));
  kats.push({ name: 'B3 kem ML-KEM-1024 encap/decap round-trip (real+held)', pass: b3, detail: `ss-agree=${b3}` });

  // B4 — NAC: attestation nac == deriveNextAuthorityCommitment(ms,1) AND restore→re-derive byte-identical.
  const restoredMs = seedPhraseToMasterSecret(masterSecretToSeedPhrase(masterSecret));
  const b4a = nz.nac === deriveNextAuthorityCommitment(masterSecret, NEXT_AUTHORITY_EPOCH);
  const b4b = deriveNextAuthorityCommitment(restoredMs, NEXT_AUTHORITY_EPOCH) === nz.nac;
  kats.push({ name: 'B4 nac derive + seedPhrase-restore consistency', pass: b4a && b4b, detail: `derive=${b4a} restore=${b4b}` });

  // B5 — FP consistency.
  const b5 = deriveCanonicalFingerprintHex(p.signPub, p.encPub, p.kemPub, p.sigPub) === nz.fingerprint;
  kats.push({ name: 'B5 fp consistency SHA256(sign‖enc‖kem‖sig)', pass: b5, detail: `fp=${nz.fingerprint.slice(0, 16)}…` });

  // B6 — RECOVERABILITY: restore masterSecret from the single seedPhrase → re-derive ALL keys → identical.
  const nz2 = deriveNodeZero(restoredMs);
  const b6 =
    hx(nz2.pubs.signPub) === hx(p.signPub) && hx(nz2.pubs.encPub) === hx(p.encPub) &&
    hx(nz2.pubs.kemPub) === hx(p.kemPub) && hx(nz2.pubs.sigPub) === hx(p.sigPub) &&
    hx(nz2.secrets.dsaSecret) === hx(s.dsaSecret) && hx(nz2.secrets.kemSecret) === hx(s.kemSecret) &&
    nz2.fingerprint === nz.fingerprint && nz2.nac === nz.nac;
  kats.push({ name: 'B6 full recoverability from single seedPhrase', pass: b6, detail: `all-secrets+pubs+fp+nac=${b6}` });

  // FIPS lengths — never mint a truncated bundle.
  const lenOk = p.signPub.length === SIGN_PUB_LEN && p.encPub.length === ENC_PUB_LEN &&
    p.kemPub.length === KEM_PUB_LEN && p.sigPub.length === SIG_PUB_LEN;
  kats.push({ name: 'FIPS pubkey lengths 32/32/1568/2592', pass: lenOk, detail: `${p.signPub.length}/${p.encPub.length}/${p.kemPub.length}/${p.sigPub.length}` });

  // DSEP — domain-separation independence: identity keys MUST NOT collide with the rotation authority
  //        (both derive from masterSecret). A label collision would be catastrophic; prove distinctness.
  const auth = deriveNextAuthorityKeypair(masterSecret, NEXT_AUTHORITY_EPOCH);
  const dsep = hx(s.edSeed) !== hx(auth.edSecret) && hx(p.signPub) !== hx(auth.edPublic) && hx(p.sigPub) !== hx(auth.dsaPublic);
  kats.push({ name: 'DSEP identity ⟂ rotation-authority (no label collision)', pass: dsep, detail: `distinct=${dsep}` });

  return { nz, kats, allPass: kats.every(k => k.pass) };
}

export interface TwoFactorKatResult { nz: NodeZero; masterSecret: Uint8Array; kats: Kat[]; allPass: boolean }

/**
 * 2FA front-door KATs (Flint reqs #143258, Peter's "needs both" ask #143240). Proves:
 *   T1 determinism — same (seed,password,salt) ⇒ same masterSecret (DR re-materializes exactly).
 *   T2 recover     — (seed,password,salt) ⇒ masterSecret ⇒ deriveNodeZero reproduces fp/nac/pubs.
 *   T3 wrong-pw    — a wrong password ⇒ different masterSecret ⇒ different fp (mint fp-assert REFUSES).
 *   T4 seed-alone  — the seed used directly as a masterSecret ⇒ different fp: a found seed phrase ALONE
 *                    cannot re-materialize the identity (the entire point of 2FA — Peter's ask).
 *   T5 salt-bind   — a different salt ⇒ different masterSecret (the recorded salt is bound in).
 * Runs scrypt 4× (~seconds each at N=2^17) — acceptable for a once-run ceremony/witness step.
 */
export function run2FAKats(seed: Uint8Array, password: string, salt: Uint8Array,
                           params: ScryptParams = FROZEN_SCRYPT_PARAMS): TwoFactorKatResult {
  const hx = bytesToHex;
  const kats: Kat[] = [];

  const masterSecret = deriveMasterSecret2FA(seed, password, salt, params); // scrypt #1
  const nz = deriveNodeZero(masterSecret);

  // T1 — determinism.
  const ms2 = deriveMasterSecret2FA(seed, password, salt, params);          // scrypt #2
  const t1 = hx(ms2) === hx(masterSecret);
  kats.push({ name: 'T1 2FA determinism: same (seed,password,salt) ⇒ same masterSecret', pass: t1, detail: `match=${t1}` });

  // T2 — recover: re-derive the whole identity from the two factors, byte-compare (reuses ms2, no scrypt).
  const nz2 = deriveNodeZero(ms2);
  const t2 = nz2.fingerprint === nz.fingerprint && nz2.nac === nz.nac &&
    hx(nz2.pubs.signPub) === hx(nz.pubs.signPub) && hx(nz2.pubs.encPub) === hx(nz.pubs.encPub) &&
    hx(nz2.pubs.kemPub) === hx(nz.pubs.kemPub) && hx(nz2.pubs.sigPub) === hx(nz.pubs.sigPub);
  kats.push({ name: 'T2 2FA recover: (seed,password,salt) ⇒ identical fp/nac/pubs', pass: t2, detail: `fp=${nz.fingerprint.slice(0, 16)}…` });

  // T3 — wrong password ⇒ different masterSecret ⇒ different fp (the fp-assert refuse property, req 4).
  const nzWrong = deriveNodeZero(deriveMasterSecret2FA(seed, password + ' wrong', salt, params)); // scrypt #3
  const t3 = nzWrong.fingerprint !== nz.fingerprint;
  kats.push({ name: 'T3 wrong-password ⇒ different fp (mint fp-assert refuses)', pass: t3, detail: `differs=${t3}` });

  // T4 — found seed phrase ALONE (seed used directly as masterSecret) ⇒ different fp. No scrypt.
  const nzSeedAlone = deriveNodeZero(seed);
  const t4 = nzSeedAlone.fingerprint !== nz.fingerprint;
  kats.push({ name: 'T4 seed-phrase-alone insufficient (seed ≠ masterSecret ⇒ different fp)', pass: t4, detail: `differs=${t4}` });

  // T5 — salt binding: flip one salt byte ⇒ different masterSecret.
  const otherSalt = salt.slice(); otherSalt[0] ^= 0xff;
  const t5 = hx(deriveMasterSecret2FA(seed, password, otherSalt, params)) !== hx(masterSecret); // scrypt #4
  kats.push({ name: 'T5 salt binding: different salt ⇒ different masterSecret', pass: t5, detail: `differs=${t5}` });

  return { nz, masterSecret, kats, allPass: kats.every(k => k.pass) };
}

/** The genesis attestation — the nac's card-less home (Flint C4). Matches DurableIdentity durable shape.
 *  v2 adds the (non-secret) two_factor block: salt + scrypt params so DR is deterministic and the
 *  frozen construction is self-documenting (Flint reqs 2,3). fp/nac do NOT depend on this JSON. */
export function buildGenesisAttestation(nz: NodeZero, twoFactor: { salt: Uint8Array; params: ScryptParams }) {
  return {
    schema: 'svrnty:node-zero-genesis-attestation:v2',
    fingerprint: nz.fingerprint,
    epoch: GENESIS_EPOCH,
    version_counter: GENESIS_VERSION_COUNTER,
    grammar_version: GENESIS_GRAMMAR_VERSION,
    next_authority_commitment: nz.nac,
    durable: { fingerprint: nz.fingerprint, epoch: GENESIS_EPOCH, next_authority_commitment: nz.nac },
    pubkeys: {
      sign_pub: b64(nz.pubs.signPub), enc_pub: b64(nz.pubs.encPub),
      kem_pub: b64(nz.pubs.kemPub), sig_pub: b64(nz.pubs.sigPub),
    },
    hkdf_labels: NODE_ZERO_HKDF_LABEL, // recorded so the derivation is self-documenting (frozen)
    // 2FA (b): the (non-secret) inputs needed to re-derive masterSecret = scrypt(seed, password).
    // salt + params are recorded here; the seed phrase + sealed password are the two secret factors.
    two_factor: {
      scheme: NODE_ZERO_2FA.scheme,
      kdf: NODE_ZERO_2FA.kdf,
      params: { N: twoFactor.params.N, r: twoFactor.params.r, p: twoFactor.params.p, dkLen: twoFactor.params.dkLen },
      salt: b64(twoFactor.salt),
      salt_domain: NODE_ZERO_2FA.saltDomain,
      input_encoding: NODE_ZERO_2FA.inputEncoding,
      normalization: NODE_ZERO_2FA.normalization,
    },
  };
}

// ───────────────────────────────── CLI ─────────────────────────────────
const fromB64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));

/** Read the password (factor 2) from --password-file (preferred; one trailing newline stripped) or
 *  --password (convenience — visible in the process list, so warn). Returns null if neither given. */
function readPassword(argFile: string | null, argInline: string | null): string | null {
  if (argFile) return readFileSync(argFile, 'utf8').replace(/\r?\n$/, ''); // strip ONE trailing newline
  if (argInline !== null) {
    console.error('  ⚠ --password is visible in the process list / shell history. Prefer --password-file for the real mint.');
    return argInline;
  }
  return null;
}

function main() {
  const argv = process.argv.slice(2);
  const arg = (f: string): string | null => { const i = argv.indexOf(f); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
  const has = (f: string): boolean => argv.includes(f);

  const printKats = (masterSecret: Uint8Array) => {
    const { nz, kats, allPass } = runKats(masterSecret);
    console.log('\n=== NODE ZERO CEREMONY KEYGEN — KAT VECTOR (lower layer) ===');
    console.log(`  fingerprint      = ${nz.fingerprint}`);
    console.log(`  nac (epoch 1)    = ${nz.nac}`);
    console.log(`  sign_pub  sha256 = ${bytesToHex(sha256(nz.pubs.signPub))}  (${nz.pubs.signPub.length}B)`);
    console.log(`  enc_pub   sha256 = ${bytesToHex(sha256(nz.pubs.encPub))}  (${nz.pubs.encPub.length}B)`);
    console.log(`  kem_pub   sha256 = ${bytesToHex(sha256(nz.pubs.kemPub))}  (${nz.pubs.kemPub.length}B)`);
    console.log(`  sig_pub   sha256 = ${bytesToHex(sha256(nz.pubs.sigPub))}  (${nz.pubs.sigPub.length}B)`);
    console.log(`  ed_seed   sha256 = ${bytesToHex(sha256(nz.secrets.edSeed))}`);
    console.log(`  dsa_seed  sha256 = ${bytesToHex(sha256(nz.secrets.dsaSeed))}`);
    console.log(`  labels           = ${JSON.stringify(NODE_ZERO_HKDF_LABEL)}`);
    console.log('  --- KATs (lower layer) ---');
    for (const k of kats) console.log(`  [${k.pass ? 'PASS' : 'FAIL'}] ${k.name}  (${k.detail})`);
    console.log(`  => ${allPass ? 'ALL PASS' : 'FAILURES PRESENT'}`);
    return { nz, allPass };
  };

  const print2FAKats = (r: TwoFactorKatResult) => {
    console.log('  --- KATs (2FA front-door) ---');
    for (const k of r.kats) console.log(`  [${k.pass ? 'PASS' : 'FAIL'}] ${k.name}  (${k.detail})`);
    console.log(`  => 2FA ${r.allPass ? 'ALL PASS' : 'FAILURES PRESENT'}`);
  };

  // ── SELF-TEST (lower layer) — unchanged; on a fixed masterSecret it reproduces the prior vectors,
  //    proving deriveNodeZero() is byte-identical under the 2FA change. NO artifacts. ──
  if (has('--selftest')) {
    const mhex = arg('--master-hex');
    const ms = mhex ? hexToBytes(mhex) : new Uint8Array(32); // default: all-zero fixed vector (co-witnessable)
    if (ms.length !== 32) { console.error(`✗ --master-hex must be 64 hex chars (32B), got ${ms.length}B`); process.exit(1); }
    const { allPass } = printKats(ms);
    console.log(mhex ? '\n(self-test on provided masterSecret — NO artifacts written)' : '\n(self-test on all-ZERO fixed masterSecret — deterministic lower-layer co-witness; NO artifacts)');
    process.exit(allPass ? 0 : 1);
  }

  // ── SELF-TEST (2FA front-door) — deterministic co-witness of masterSecret = scrypt(seed, password).
  //    Fixed default vectors (all-zero seed, fixed spell, all-zero salt). NO artifacts. ──
  if (has('--selftest-2fa')) {
    const seedHex = arg('--seed-hex');
    const saltHex = arg('--salt-hex');
    const seed = seedHex ? hexToBytes(seedHex) : new Uint8Array(32);                        // default all-zero seed
    const salt = saltHex ? hexToBytes(saltHex) : new Uint8Array(NODE_ZERO_2FA.saltBytes);  // default all-zero salt
    const password = arg('--password') ?? 'svrnty:node-zero-2fa:selftest';                  // fixed default spell
    if (seed.length !== 32) { console.error(`✗ --seed-hex must be 64 hex chars (32B), got ${seed.length}B`); process.exit(1); }
    if (salt.length !== NODE_ZERO_2FA.saltBytes) { console.error(`✗ --salt-hex must be ${NODE_ZERO_2FA.saltBytes * 2} hex chars (${NODE_ZERO_2FA.saltBytes}B), got ${salt.length}B`); process.exit(1); }
    console.log('\n=== NODE ZERO CEREMONY KEYGEN — 2FA SELF-TEST ===');
    console.log(`  scheme   = ${NODE_ZERO_2FA.scheme}`);
    console.log(`  scrypt   = N=${NODE_ZERO_2FA.N} r=${NODE_ZERO_2FA.r} p=${NODE_ZERO_2FA.p} dkLen=${NODE_ZERO_2FA.dkLen}`);
    console.log(`  input    = ${NODE_ZERO_2FA.inputEncoding};  salt = utf8("${NODE_ZERO_2FA.saltDomain}") ‖ salt${NODE_ZERO_2FA.saltBytes}B;  norm = ${NODE_ZERO_2FA.normalization}`);
    console.log(`  seed     = ${bytesToHex(seed)}`);
    console.log(`  salt     = ${bytesToHex(salt)}`);
    console.log(`  password = ${JSON.stringify(password)}  (NFKD-normalized before hashing)`);
    console.log('  (running scrypt ×4 — ~16s each at N=2^18…)');
    const r = run2FAKats(seed, password, salt);
    console.log(`  masterSecret sha256 = ${bytesToHex(sha256(r.masterSecret))}`);
    console.log(`  → fingerprint       = ${r.nz.fingerprint}`);
    console.log(`  → nac (epoch 1)     = ${r.nz.nac}`);
    print2FAKats(r);
    const { allPass: lowerPass } = printKats(r.masterSecret); // full-stack co-witness on the derived masterSecret
    console.log('\n(2FA self-test — deterministic; NO artifacts written)');
    process.exit(r.allPass && lowerPass ? 0 : 1);
  }

  const outDir = arg('--out');
  if (!outDir) {
    console.error('usage: ceremony-keygen.ts --selftest [--master-hex <64hex>]                                  (lower-layer co-witness)');
    console.error('       ceremony-keygen.ts --selftest-2fa [--seed-hex <64hex>] [--password <s>] [--salt-hex <32hex>]  (2FA co-witness)');
    console.error('       ceremony-keygen.ts --out <dir> (--password <s> | --password-file <f>) [--seedphrase-out <file>]         (fresh mint)');
    console.error('       ceremony-keygen.ts --out <dir> --seedphrase "<phrase>" (--password <s>|--password-file <f>) \\');
    console.error('                          --attestation <genesis.json>  [or --salt-hex <32hex> --expect-fp <fp>]              (DR re-materialize)');
    process.exit(1);
  }

  // ── Factor 2 (password) — required for BOTH fresh mint and DR (this is the 2FA forever-key). ──
  const password = readPassword(arg('--password-file'), arg('--password'));
  if (password === null) {
    console.error('\n✗ 2FA requires a password (factor 2). Pass --password-file <f> (preferred) or --password <spell>.');
    console.error('  This forever-key needs BOTH a seed phrase AND a password to mint or recover.');
    process.exit(1);
  }

  // ── Mode: DR re-materialize (--seedphrase present) vs fresh mint. ──
  const seedphraseArg = arg('--seedphrase');
  const isRestore = seedphraseArg !== null;

  let seed: Uint8Array;
  let salt: Uint8Array;
  let params: ScryptParams = FROZEN_SCRYPT_PARAMS;
  let expectFp: string | null = null;

  if (isRestore) {
    // DR RE-MATERIALIZE — reconstruct an EXISTING genesis from BOTH factors (Flint cond.3: loud). ──
    seed = seedPhraseToMasterSecret(seedphraseArg!); // recovery.js: 64-hex phrase → 32B seed (factor 1)
    // salt + params + expected-fp come from the published genesis attestation (turnkey) or explicit flags.
    const attPath = arg('--attestation');
    if (attPath) {
      const att = JSON.parse(readFileSync(attPath, 'utf8'));
      if (!att.two_factor || !att.two_factor.salt || !att.two_factor.params) {
        console.error('\n✗ --attestation lacks a two_factor{salt,params} block — not a 2FA genesis (v2). Use --salt-hex + --expect-fp.');
        seed.fill(0); process.exit(1);
      }
      salt = fromB64(att.two_factor.salt);
      const p = att.two_factor.params;
      params = { N: p.N, r: p.r, p: p.p, dkLen: p.dkLen };
      expectFp = arg('--expect-fp') ?? att.fingerprint ?? null;
    } else {
      const saltHex = arg('--salt-hex');
      if (!saltHex) {
        console.error('\n✗ DR re-materialize needs the salt: pass --attestation <genesis.json> (turnkey) or --salt-hex <32hex>.');
        seed.fill(0); process.exit(1);
      }
      salt = hexToBytes(saltHex);
      expectFp = arg('--expect-fp');
    }
    if (salt.length !== NODE_ZERO_2FA.saltBytes) { console.error(`✗ salt must be ${NODE_ZERO_2FA.saltBytes}B, got ${salt.length}B`); seed.fill(0); process.exit(1); }
    // ⛔ fp-ASSERT is MANDATORY on DR (Flint cond.2): a wrong seed phrase OR password silently
    //    re-materializes a DIFFERENT genesis. Without --expect-fp (or an attestation carrying it) we refuse.
    if (!expectFp) {
      console.error('\n✗ DR re-materialize REQUIRES --expect-fp <published-genesis-fp> (or an --attestation carrying it).');
      console.error('  Without it a wrong seed phrase OR password would silently write a DIFFERENT forever-key. Do-no-harm: refusing.');
      seed.fill(0); salt.fill(0); process.exit(1);
    }
    console.log('\n⚠⚠⚠  DR RE-MATERIALIZE MODE — NOT a fresh mint  ⚠⚠⚠');
    console.log('  Reconstructing an EXISTING Node Zero genesis from the seed phrase + password (disaster recovery).');
    console.log('  Output MUST byte-match the genesis you already published; fp is asserted against --expect-fp below.');
  } else {
    // FRESH MINT — CSPRNG seed (factor 1) + CSPRNG salt; password is the operator's spell (factor 2). ──
    seed = generateMasterSecret(); // 32B crypto.getRandomValues — the SEED
    salt = generate2FASalt();      // 16B non-secret salt (recorded in genesis-attestation.json)
  }

  // Derive masterSecret from BOTH factors (scrypt — ~16s at N=2^18), then the whole identity below it.
  console.log(`\n  deriving masterSecret = scrypt(seed, password)  [N=${params.N} r=${params.r} p=${params.p}] — ~16s…`);
  const masterSecret = deriveMasterSecret2FA(seed, password, salt, params);

  // Refuse to write anything unless EVERY KAT passes — lower layer AND 2FA front-door (Flint cond.1). ──
  const { nz, allPass: lowerPass } = printKats(masterSecret);
  const twoFa = run2FAKats(seed, password, salt, params);
  print2FAKats(twoFa);
  const allPass = lowerPass && twoFa.allPass;

  const wipe = () => {
    seed.fill(0); salt.fill(0); masterSecret.fill(0);
    nz.secrets.masterSecret.fill(0); nz.secrets.edSeed.fill(0); nz.secrets.dsaSeed.fill(0);
    nz.secrets.encSeed.fill(0); nz.secrets.kemSeed.fill(0); nz.secrets.dsaSecret.fill(0); nz.secrets.kemSecret.fill(0);
    twoFa.masterSecret.fill(0);
    twoFa.nz.secrets.masterSecret.fill(0); twoFa.nz.secrets.edSeed.fill(0); twoFa.nz.secrets.dsaSeed.fill(0);
    twoFa.nz.secrets.encSeed.fill(0); twoFa.nz.secrets.kemSeed.fill(0); twoFa.nz.secrets.dsaSecret.fill(0); twoFa.nz.secrets.kemSecret.fill(0);
  };
  if (!allPass) { console.error('\n✗ KAT FAILURE — refusing to write a Node Zero genesis. Nothing minted.'); wipe(); process.exit(1); }

  // ⛔ fp-ASSERT GUARD (Flint cond.2) — DR only. The re-materialized fp MUST equal the published genesis
  //    fp, else the provided seed phrase/password recover the WRONG identity. Refuse to write on mismatch.
  if (isRestore) {
    const norm = (s: string) => s.toLowerCase().replace(/[^0-9a-f]/g, '');
    if (norm(nz.fingerprint) !== norm(expectFp!)) {
      console.error('\n⛔ fp-ASSERT FAILED — re-materialized genesis does NOT match --expect-fp. NOTHING WRITTEN.');
      console.error(`     re-materialized fp     = ${nz.fingerprint}`);
      console.error(`     expected (--expect-fp) = ${norm(expectFp!)}`);
      console.error('  The provided seed phrase AND/OR password recover a DIFFERENT identity than you published.');
      console.error('  Check BOTH factors — the seed phrase and the password must each be exactly right.');
      wipe(); process.exit(1);
    }
    console.log(`\n  ✓ fp-ASSERT PASSED — re-materialized fp == published genesis: ${nz.fingerprint}`);
  }

  mkdirSync(outDir, { recursive: true });
  const pubkeys = {
    sign_pub: b64(nz.pubs.signPub), enc_pub: b64(nz.pubs.encPub), kem_pub: b64(nz.pubs.kemPub), sig_pub: b64(nz.pubs.sigPub),
  };
  writeFileSync(join(outDir, 'pubkeys.json'), JSON.stringify(pubkeys, null, 2));
  writeFileSync(join(outDir, 'secret-seeds.json'), JSON.stringify({ ed_seed: b64(nz.secrets.edSeed), dsa_seed: b64(nz.secrets.dsaSeed) }, null, 2));
  writeFileSync(join(outDir, 'genesis-attestation.json'), JSON.stringify(buildGenesisAttestation(nz, { salt, params }), null, 2));

  const seedPhrase = masterSecretToSeedPhrase(seed); // the phrase now backs up the SEED (factor 1)
  const spOut = arg('--seedphrase-out');
  if (spOut) writeFileSync(spOut, seedPhrase + '\n');

  if (isRestore) {
    console.log('\n=== ✓ NODE ZERO RE-MATERIALIZED (disaster recovery) ===');
    console.log(`  → ${outDir}/pubkeys.json + secret-seeds.json + genesis-attestation.json  (regenerated, byte-identical to the original genesis)`);
    console.log(`  fingerprint = ${nz.fingerprint}  (asserted == published)`);
    console.log('  secret-seeds.json is ready for airgap-sign. Your seed phrase + password are UNCHANGED — you recovered from them.');
    if (spOut) console.log(`  (seed phrase also re-written to ${spOut} at operator request — same value; treat as TOP SECRET.)`);
  } else {
    console.log('\n=== ✓ REAL NODE ZERO GENESIS MINTED (2FA) ===');
    console.log(`  → ${outDir}/pubkeys.json  (travels to build machine)`);
    console.log(`  → ${outDir}/secret-seeds.json  (SECRET — ed_seed+dsa_seed for airgap-sign; never leaves the air-gap)`);
    console.log(`  → ${outDir}/genesis-attestation.json  (fp + nac + epoch-0 + two_factor{salt,params} — the nac's home)`);
    console.log('\n  ⛔ TWO INDEPENDENT SEALED BACKUPS — BOTH are required to ever recover this forever-key:');
    console.log(`\n     FACTOR 1 — SEED PHRASE (write on paper, seal):   ${seedPhrase}`);
    console.log('     FACTOR 2 — PASSWORD ("your spell"): seal SEPARATELY — do NOT store it with the seed phrase.');
    console.log('\n  Neither factor alone can recover the key: a found seed phrase without the password is inert, and');
    console.log('  vice-versa. The salt + scrypt params live in genesis-attestation.json (non-secret) — DR needs them too.');
    console.log('\n  ⚠ MENTAL MODEL: a MEMORIZED spell is low-entropy — its real protection is the memory-hard scrypt cost,');
    console.log('     and the SEALED password backup is the true second factor. For maximum strength use a high-entropy');
    console.log('     passphrase (treated AS the protection), not a short memorable word. scrypt slows a seed-thief; it');
    console.log('     does not make a weak password strong — the residual is YOUR password entropy.');
    if (spOut) console.log(`\n  (seed phrase also written to ${spOut} at operator request — treat as TOP SECRET; destroy after cold transcription.)`);
  }

  // Flint D2 — zero secret material after backup + nac derivation.
  wipe();
  process.exit(0);
}

main();
