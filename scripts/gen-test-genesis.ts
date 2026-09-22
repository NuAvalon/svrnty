// scripts/gen-test-genesis.ts — TEST helper: generate a THROWAWAY genesis (pubkeys.json + secret-seeds.json) to
// exercise the G4 ceremony flow (signer --pubkeys → airgap-sign → signer --pubkeys --sig) WITHOUT the real Root-B
// keys. NOT for production — the real genesis is minted air-gapped in the ceremony. Usage:
//   npx tsx scripts/gen-test-genesis.ts <out-dir>
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

const dir = process.argv[2] ?? '.';
const b64 = (u8: Uint8Array) => Buffer.from(u8).toString('base64');
const edSeed = new Uint8Array(randomBytes(32));
const dsaSeed = new Uint8Array(randomBytes(32));
const signPub = ed25519.getPublicKey(edSeed);
const sigPub = ml_dsa87.keygen(dsaSeed).publicKey;
// enc/kem pubkeys are only in the fp preimage (not used to sign) — random-but-valid-length for the test.
const encPub = new Uint8Array(randomBytes(32));
const kemPub = new Uint8Array(randomBytes(1568));

writeFileSync(join(dir, 'pubkeys.json'), JSON.stringify({ sign_pub: b64(signPub), enc_pub: b64(encPub), kem_pub: b64(kemPub), sig_pub: b64(sigPub) }, null, 2));
writeFileSync(join(dir, 'secret-seeds.json'), JSON.stringify({ ed_seed: b64(edSeed), dsa_seed: b64(dsaSeed) }, null, 2));
console.log(`✓ THROWAWAY test genesis → ${dir}/pubkeys.json + secret-seeds.json (NOT the real Root-B genesis)`);
