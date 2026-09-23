// scripts/airgap-sign.ts — AIR-GAP release signer (runs on the air-gapped ceremony machine; Root-B G2, Flint-guided).
//
// Reads the build machine's sign-request.json + the genesis SECRET seeds, RECONSTRUCTS + VERIFIES the preimage
// (NEVER blind-signs), signs ONLY the ~130B preimage, and outputs sig-hex. The secret NEVER leaves this machine
// (no network, never written/logged; only the sig — which is public — comes out).
//
// FLINT #142416 do-no-harm — the whole security of the sovereign flow: a compromised/buggy build machine could
// hand a preimage for a MALICIOUS bundle_hash → blind-signing would make the forever-key attest malicious code.
// So BEFORE signing this:
//   1. re-derives publisher_fp = SHA256(signPub‖encPub‖kemPub‖sigPub) from the AIR-GAP's own pubkeys → == request.fp
//      (binds the preimage to OUR keys, rejects a substituted pubkey set)
//   2. re-encodes the preimage IN THE AIR-GAP from the fields (gv, our-fp, bundle_hash, counter, epoch) via the
//      frozen encodeReleaseSigningInput → byte-compare == request.preimage_hex (no blind trust of the sent hex)
//   3. confirms the secret seeds DERIVE the pubkeys being attested (else we'd sign with the wrong release-key)
//   4. DISPLAYS the bundle_hash for the operator (Flint GATE-3) to cross-check == the co-witnessed intended bundle
// Only after 1–4 pass does it call ed25519.sign(preimage) ‖ ml_dsa87.sign(preimage). Nothing else.
//
// Runner (air-gap): npx tsx scripts/airgap-sign.ts --request sign-request.json --secret secret-seeds.json --out sig.hex
//   secret-seeds.json = {"ed_seed":"<b64 32B>","dsa_seed":"<b64 32B>"}  (the ceremony release-key seeds; G0-generated)

import { readFileSync, writeFileSync } from 'node:fs';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { encodeReleaseSigningInput } from '../src/lib/crypto/release-object.js';
import { deriveCanonicalFingerprintHex } from '../src/lib/identity/fingerprint-canonical';

const die = (m: string): never => { console.error(`\n✗ ${m}`); process.exit(1); };
const argv = process.argv.slice(2);
const arg = (f: string): string | null => { const i = argv.indexOf(f); return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null; };
const reqFile = arg('--request') ?? die('--request <sign-request.json> required');
const secFile = arg('--secret') ?? die('--secret <secret-seeds.json> required');
const outFile = arg('--out') ?? 'sig.hex';
const b64 = (s: unknown): Uint8Array => { if (typeof s !== 'string') die('expected base64 string'); return new Uint8Array(Buffer.from(s as string, 'base64')); };

const req = JSON.parse(readFileSync(reqFile, 'utf8')) as {
  publisher_fp: string; grammar_version: number; version_counter: number; epoch: number; bundle_hash: string; preimage_hex: string;
  pubkeys: { sign_pub: string; enc_pub: string; kem_pub: string; sig_pub: string };
};
const sec = JSON.parse(readFileSync(secFile, 'utf8')) as { ed_seed: string; dsa_seed: string };

const signPub = b64(req.pubkeys.sign_pub), encPub = b64(req.pubkeys.enc_pub), kemPub = b64(req.pubkeys.kem_pub), sigPub = b64(req.pubkeys.sig_pub);

// 1. re-derive publisher_fp from the pubkeys → confirm == request.publisher_fp (SHA256(signPub‖encPub‖kemPub‖sigPub))
const fpHex = deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sigPub);
if (fpHex !== req.publisher_fp) die(`fp MISMATCH: SHA256(pubkeys) = ${fpHex} != request.publisher_fp ${req.publisher_fp} — substituted pubkeys? REFUSE.`);

// 2. re-encode the preimage from the fields → byte-compare == request.preimage_hex (no blind trust of the hex)
const preimage = encodeReleaseSigningInput({ grammarVersion: req.grammar_version, publisherFp: hexToBytes(fpHex), bundleHash: hexToBytes(req.bundle_hash), versionCounter: req.version_counter, epoch: req.epoch });
if (bytesToHex(preimage) !== req.preimage_hex) die(`preimage MISMATCH: re-encoded != request.preimage_hex — the sent preimage is NOT what these fields produce. REFUSE TO SIGN.`);

// 3. confirm the secret seeds derive the pubkeys being attested (never sign with the wrong release-key)
const edSeed = b64(sec.ed_seed), dsaSeed = b64(sec.dsa_seed);
if (edSeed.length !== 32) die(`ed_seed must be 32B, got ${edSeed.length}`);
if (dsaSeed.length !== 32) die(`dsa_seed must be 32B, got ${dsaSeed.length}`);
const dsaKeys = ml_dsa87.keygen(dsaSeed);
if (bytesToHex(ed25519.getPublicKey(edSeed)) !== bytesToHex(signPub)) die(`ed_seed does NOT derive signPub — wrong release-key for this genesis. REFUSE.`);
if (bytesToHex(dsaKeys.publicKey) !== bytesToHex(sigPub)) die(`dsa_seed does NOT derive sigPub — wrong release-key. REFUSE.`);

// 4. display for the operator's GATE-3 cross-check
console.log(`\n=== AIR-GAP SIGN — RECONSTRUCT+VERIFY PASSED (not blind-signing) ===`);
console.log(`  publisher_fp    = ${fpHex}`);
console.log(`  bundle_hash     = ${req.bundle_hash}`);
console.log(`  grammar_version = ${req.grammar_version}   version_counter = ${req.version_counter}   epoch = ${req.epoch}`);
console.log(`  preimage (${preimage.length}B) re-encoded BYTE-IDENTICAL to the request; seeds derive the attested pubkeys.`);
console.log(`  ⛔ OPERATOR (Flint GATE-3): confirm bundle_hash above == the co-witnessed intended genesis bundle BEFORE this sig is used.\n`);

// only now sign: ed25519.sign(preimage) ‖ ml_dsa87.sign(preimage). No network. Secret never written/logged.
const sig = concatBytes(ed25519.sign(preimage, edSeed), ml_dsa87.sign(preimage, dsaKeys.secretKey));
writeFileSync(outFile, bytesToHex(sig));
console.log(`✓ signed — sig (${sig.length}B) → ${outFile}. Bring ${outFile} to the build machine:`);
console.log(`  npx tsx scripts/sign-release.ts --pubkeys <pubkeys.json> --sig ${outFile}   → assemble release.json + full-chain verify (G4)`);
