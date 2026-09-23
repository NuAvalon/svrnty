// scripts/ceremony-keygen.ts — REAL Node Zero ceremony keygen (b-MINIMAL pure release-signing root).
//
// Replaces the THROWAWAY scripts/gen-test-genesis.ts for the real G0 mint. gen-test-genesis fakes
// enc/kem as random pubkeys with NO held secret (→ undecryptable identity + permanent lineage-lock)
// and emits no rotation-authority/nac. This tool generates REAL, HELD, seed-based keys and the
// rotation-authority commitment, all reproducible from a SINGLE cold-seed backup.
//
// ── MODEL (Apollo A2 decision / Flint gate #142625 A2, reached 3-seats-apart, Peter b-MINIMAL #142663) ──
//   masterSecret (32B platform CSPRNG) is the ONE root. Every identity key AND the rotation authority
//   derive from it via domain-separated HKDF-SHA256 — the SAME construction the rotation authority
//   already uses (fingerprint.ts rotationAuthorityLeg). ⇒ ONE backup (masterSecret → seedPhrase)
//   recovers EVERYTHING; Flint re-derives the whole identity from masterSecret and byte-compares.
//   "No new crypto for a forever-key": HKDF-SHA256, ed25519, x25519, ML-DSA-87, ML-KEM-1024 — all
//   already in-tree and FIPS-standard.
//
//   b-MINIMAL: Node Zero is a PURE release-signing root — no card / no satellite / no openpgp / no
//   app-load. enc/kem are generated REAL+HELD anyway because the canonical fingerprint COMMITS them
//   (fp = SHA256(sign‖enc‖kem‖sig)); random enc/kem would permanently commit an undecryptable identity
//   and forfeit the ability to add capability later without re-minting.
//
// ── FROZEN forever ── the four domain-separation labels below are part of the key derivation for all
//   time: recovering Node Zero REQUIRES these exact bytes. They are GATED on Flint's independent
//   byte-confirm before the real mint. Do not edit without re-minting the identity.
//
// Runners:
//   Self-test (deterministic, co-witnessable — NO real artifacts):
//     npx tsx scripts/ceremony-keygen.ts --selftest [--master-hex <64hex>]
//   REAL mint (air-gap, ceremony only — CSPRNG masterSecret, writes artifacts, refuses on any KAT fail):
//     npx tsx scripts/ceremony-keygen.ts --out <dir> [--seedphrase-out <file>]

import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import {
  deriveCanonicalFingerprintHex,
  deriveNextAuthorityCommitment,
  deriveNextAuthorityKeypair,
  SIGN_PUB_LEN, ENC_PUB_LEN, KEM_PUB_LEN, SIG_PUB_LEN,
} from '../src/lib/identity/fingerprint.js';
import { generateMasterSecret, masterSecretToSeedPhrase, seedPhraseToMasterSecret } from '../src/lib/crypto/recovery.js';

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

/** The genesis attestation — the nac's card-less home (Flint C4). Matches DurableIdentity durable shape. */
export function buildGenesisAttestation(nz: NodeZero) {
  return {
    schema: 'svrnty:node-zero-genesis-attestation:v1',
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
  };
}

// ───────────────────────────────── CLI ─────────────────────────────────
function main() {
  const argv = process.argv.slice(2);
  const arg = (f: string): string | null => { const i = argv.indexOf(f); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
  const has = (f: string): boolean => argv.includes(f);

  const printKats = (masterSecret: Uint8Array) => {
    const { nz, kats, allPass } = runKats(masterSecret);
    console.log('\n=== NODE ZERO CEREMONY KEYGEN — KAT VECTOR (b-MINIMAL) ===');
    console.log(`  fingerprint      = ${nz.fingerprint}`);
    console.log(`  nac (epoch 1)    = ${nz.nac}`);
    console.log(`  sign_pub  sha256 = ${bytesToHex(sha256(nz.pubs.signPub))}  (${nz.pubs.signPub.length}B)`);
    console.log(`  enc_pub   sha256 = ${bytesToHex(sha256(nz.pubs.encPub))}  (${nz.pubs.encPub.length}B)`);
    console.log(`  kem_pub   sha256 = ${bytesToHex(sha256(nz.pubs.kemPub))}  (${nz.pubs.kemPub.length}B)`);
    console.log(`  sig_pub   sha256 = ${bytesToHex(sha256(nz.pubs.sigPub))}  (${nz.pubs.sigPub.length}B)`);
    console.log(`  ed_seed   sha256 = ${bytesToHex(sha256(nz.secrets.edSeed))}`);
    console.log(`  dsa_seed  sha256 = ${bytesToHex(sha256(nz.secrets.dsaSeed))}`);
    console.log(`  labels           = ${JSON.stringify(NODE_ZERO_HKDF_LABEL)}`);
    console.log('  --- KATs ---');
    for (const k of kats) console.log(`  [${k.pass ? 'PASS' : 'FAIL'}] ${k.name}  (${k.detail})`);
    console.log(`  => ${allPass ? 'ALL PASS' : 'FAILURES PRESENT'}`);
    return { nz, allPass };
  };

  if (has('--selftest')) {
    const mhex = arg('--master-hex');
    const ms = mhex ? hexToBytes(mhex) : new Uint8Array(32); // default: all-zero fixed vector (co-witnessable)
    if (ms.length !== 32) { console.error(`✗ --master-hex must be 64 hex chars (32B), got ${ms.length}B`); process.exit(1); }
    const { allPass } = printKats(ms);
    console.log(mhex ? '\n(self-test on provided masterSecret — NO artifacts written)' : '\n(self-test on all-ZERO fixed vector — deterministic, for independent co-witness; NO artifacts written)');
    process.exit(allPass ? 0 : 1);
  }

  const outDir = arg('--out');
  if (!outDir) {
    console.error('usage: ceremony-keygen.ts --selftest [--master-hex <64hex>]   |   --out <dir> [--seedphrase-out <file>]');
    process.exit(1);
  }

  // REAL MINT — CSPRNG masterSecret. Refuse to write anything unless every KAT passes.
  const masterSecret = generateMasterSecret(); // 32B crypto.getRandomValues
  const { nz, allPass } = printKats(masterSecret);
  if (!allPass) { console.error('\n✗ KAT FAILURE — refusing to write a Node Zero genesis. Nothing minted.'); process.exit(1); }

  mkdirSync(outDir, { recursive: true });
  const pubkeys = {
    sign_pub: b64(nz.pubs.signPub), enc_pub: b64(nz.pubs.encPub), kem_pub: b64(nz.pubs.kemPub), sig_pub: b64(nz.pubs.sigPub),
  };
  writeFileSync(join(outDir, 'pubkeys.json'), JSON.stringify(pubkeys, null, 2));
  writeFileSync(join(outDir, 'secret-seeds.json'), JSON.stringify({ ed_seed: b64(nz.secrets.edSeed), dsa_seed: b64(nz.secrets.dsaSeed) }, null, 2));
  writeFileSync(join(outDir, 'genesis-attestation.json'), JSON.stringify(buildGenesisAttestation(nz), null, 2));

  const seedPhrase = masterSecretToSeedPhrase(masterSecret);
  const spOut = arg('--seedphrase-out');
  if (spOut) writeFileSync(spOut, seedPhrase + '\n');

  console.log('\n=== ✓ REAL NODE ZERO GENESIS MINTED ===');
  console.log(`  → ${outDir}/pubkeys.json  (travels to build machine)`);
  console.log(`  → ${outDir}/secret-seeds.json  (SECRET — ed_seed+dsa_seed for airgap-sign; never leaves the air-gap)`);
  console.log(`  → ${outDir}/genesis-attestation.json  (fp + nac + epoch-0, the nac's home)`);
  console.log('\n  ⛔ COLD BACKUP — WRITE THIS DOWN ON PAPER. It is the ONLY recovery for the entire forever-key:');
  console.log(`\n     SEED PHRASE:  ${seedPhrase}\n`);
  console.log(`  masterSecret recovers ALL keys (identity + rotation authority) via the frozen HKDF labels.`);
  if (spOut) console.log(`  (also written to ${spOut} at operator request — treat as TOP SECRET; destroy after cold transcription.)`);

  // Flint D2 — zero secret material after backup + nac derivation.
  masterSecret.fill(0); nz.secrets.masterSecret.fill(0);
  nz.secrets.edSeed.fill(0); nz.secrets.dsaSeed.fill(0); nz.secrets.encSeed.fill(0);
  nz.secrets.kemSeed.fill(0); nz.secrets.dsaSecret.fill(0); nz.secrets.kemSecret.fill(0);
  process.exit(0);
}

main();
