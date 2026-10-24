import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { base64ToUint8 } from '../src/lib/crypto/pq';
const mint = JSON.parse(readFileSync('/home/alpha/devin-sandbox/.svrnty-agent/mint.json','utf8'));
const nonce = '962b523f9b0bb82847d38272ab66128b';
const domain = 'svrnix:flint-devin:v1';
const preimage = utf8ToBytes(`${nonce}|${domain}`);   // declared format: utf8(nonce + "|" + domain)
const sig = ed25519.sign(preimage, base64ToUint8(mint.private.ed25519_seed));
console.log(JSON.stringify({ nonce, domain, preimage: 'utf8(nonce + "|" + domain)', sig: bytesToHex(sig) }));
