// TEST-ONLY helper for test_beacon_auth.py (never imported by product code): a client's side of poll/withdraw.
// stdin {"seed": 64 hex, "op", "H_e", "N", "nonce": 64 hex} -> stdout {"pk": 64 hex, "K": decimal, "sig": 128 hex}.
// Uses the SAME shared module (kInputs, authMessage) and the same pinned Poseidon as auth.mjs.
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { kInputs, authMessage } from './beacon-wire.mjs';

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const q = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(q.seed, 'hex')]);
const sk = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
const pk = Buffer.from(createPublicKey(sk).export({ format: 'jwk' }).x, 'base64url');
const P = await buildPoseidon();
const K = P.F.toObject(P(kInputs(pk)));
const sig = sign(null, authMessage(q.op, BigInt(q.H_e), BigInt(q.N), Buffer.from(q.nonce, 'hex')), sk);
process.stdout.write(JSON.stringify({ pk: pk.toString('hex'), K: K.toString(), sig: sig.toString('hex') }) + '\n', () => process.exit(0));
