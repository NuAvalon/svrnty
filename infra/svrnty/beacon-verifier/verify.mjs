#!/usr/bin/env node
// #588 mutual-trust beacon: the centurion's verifier, run by the satellite as ONE subprocess per deposit.
//
//   node verify.mjs --vkey <verification_key.json> --vkey-sha256 <hex pinned at satellite start> --now <unix seconds>
//   stdin: the raw deposit body { proof, publicSignals }
//   exit 0 + one JSON line {"ok":true,"e","H_e","N","K"} (canonical decimal) = accept; anything else = refuse.
//   exit 1 + {"ok":false,"reason":<code>} = refused; exit 2 = internal error (the caller refuses it the same way).
//
// Cheap checks first: wire (size, length, spelling, ranges, shape) -> epoch -> points (on curve, not the identity,
// pi_b in the prime-order subgroup: snarkjs checks only the curve equation and accepts the identity) -> vkey pin -> pairing.
// The vkey file is re-hashed on every run and must equal the sha the satellite pinned at start, so a vkey that changes while
// the satellite runs refuses every deposit until a restart re-pins it. No network, no state: the caller stores what we print.
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { buildBn128 } from 'ffjavascript';
import * as snarkjs from 'snarkjs';
import {
  parseDeposit, serializeSignals, serializeProof, R, WireError, EPOCH_SECONDS, GRACE_SECONDS,
} from '../../../src/lib/crypto/beacon-wire.mjs';

export { EPOCH_SECONDS, GRACE_SECONDS };   // the shared module's values, re-exported (never redefined here)
const MAX_STDIN = 16 * 1024 + 1;

class Refused extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}

/** Epoch rule: e = floor(now / week) on the SERVER clock; cur-1 / cur+1 only inside the grace window. */
export function epochOk(e, now) {
  const cur = BigInt(Math.floor(now / EPOCH_SECONDS));
  const start = Number(cur) * EPOCH_SECONDS;
  if (e === cur) return true;
  if (e === cur - 1n) return now < start + GRACE_SECONDS;
  if (e === cur + 1n) return now > start + EPOCH_SECONDS - GRACE_SECONDS;
  return false;
}

/** On-curve, not the identity, and pi_b in the r-order subgroup. Throws Refused. */
export async function checkPoints(proof, curve) {
  const g1 = (p) => curve.G1.fromObject([p[0], p[1], 1n]);
  const a = g1(proof.pi_a);
  const c = g1(proof.pi_c);
  const b = curve.G2.fromObject([proof.pi_b[0], proof.pi_b[1], [1n, 0n]]);
  for (const [name, p, G] of [['pi_a', a, curve.G1], ['pi_c', c, curve.G1], ['pi_b', b, curve.G2]]) {
    if (G.isZero(p)) throw new Refused(`point:${name}:identity`);
    if (!G.isValid(p)) throw new Refused(`point:${name}:off-curve`);
  }
  if (!curve.G2.isZero(curve.G2.timesScalar(b, R))) throw new Refused('point:pi_b:not-in-subgroup');
}

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--vkey', '--vkey-sha256', '--now'].includes(argv[i]) || argv[i + 1] === undefined) throw new Refused('usage');
    out[argv[i].slice(2)] = argv[i + 1];
  }
  if (!out.vkey || !/^[0-9a-f]{64}$/.test(out['vkey-sha256'] ?? '') || !/^[0-9]{1,12}$/.test(out.now ?? '')) {
    throw new Refused('usage');
  }
  return out;
}

// `groth16Verify` is a test seam only (default = the pinned snarkjs). snarkjs always receives values RE-SERIALIZED from the
// parsed bigints, never the raw body, so what is verified is exactly what the caller stores and dedupes on.
export async function verifyDeposit(raw, { vkeyPath, vkeySha256, now, groth16Verify = snarkjs.groth16.verify }) {
  let dep;
  try {
    dep = parseDeposit(raw);
  } catch (e) {
    if (e instanceof WireError) throw new Refused('wire');
    throw e;
  }
  if (!epochOk(dep.signals.e, now)) throw new Refused('epoch');
  const vbytes = readFileSync(vkeyPath);           // a file hash is cheaper than a G2 scalar mul: pin check first
  if (createHash('sha256').update(vbytes).digest('hex') !== vkeySha256) throw new Refused('vkey');
  const vkey = JSON.parse(vbytes.toString('utf8'));
  if (vkey.protocol !== 'groth16' || vkey.curve !== 'bn128' || vkey.nPublic !== 4) throw new Refused('vkey');
  // Our point-check curve is single-threaded. snarkjs's verify builds and caches its OWN (threaded) bn128; its worker threads
  // die with this process, because main() always ends in process.exit.
  const curve = await buildBn128(true);
  try {
    await checkPoints(dep.proof, curve);
  } finally {
    await curve.terminate();
  }
  const signals = serializeSignals(dep.signals);
  if (!(await groth16Verify(vkey, signals, serializeProof(dep.proof)))) throw new Refused('proof');
  const [e, H_e, N, K] = signals;
  return { ok: true, e, H_e, N, K };
}

async function main() {
  let code = 2;
  let line = { ok: false, reason: 'internal' };
  try {
    const a = args(process.argv.slice(2));
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > MAX_STDIN) throw new Refused('wire');
      chunks.push(chunk);
    }
    line = await verifyDeposit(Buffer.concat(chunks).toString('utf8'),
      { vkeyPath: a.vkey, vkeySha256: a['vkey-sha256'], now: Number(a.now) });
    code = 0;
  } catch (e) {
    if (e instanceof Refused) {
      line = { ok: false, reason: e.reason };
      code = 1;
    }
  }
  process.stdout.write(JSON.stringify(line) + '\n', () => process.exit(code));
}

// Run main() whenever THIS file is the entry point, however it was launched (symlink, relative path, encoded characters):
// compare real paths, never URL strings. A mismatch here used to mean exit 0 with empty stdout.
function isEntryPoint() {
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}
if (isEntryPoint()) main();
