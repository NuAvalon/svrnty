// R3 reference implementation, INDEPENDENT of the circuit (circomlibjs). Writes kat.json, input_A.json, input_B.json.
const { buildBabyjub, buildPoseidon } = require('circomlibjs'); const crypto = require('crypto'); const fs = require('fs');
const ascii = (s) => { const b = Buffer.from(s, 'ascii'); if (b.length > 31) throw new Error('tag too long'); return BigInt('0x' + b.toString('hex')); };
const sha = (s) => crypto.createHash('sha256').update(s).digest();
const hex64 = (v) => v.toString(16).padStart(64, '0');
(async () => {
  const bj = await buildBabyjub(); const F = bj.F; const O = (el) => F.toObject(el); const L = bj.subOrder; const poseidon = await buildPoseidon();
  const P_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const DS_SLOT = ascii('svrnty:588:slot:v1'), DS_NULL = ascii('svrnty:588:null:v1'), DS_K = ascii('svrnty:588:k:v1');
  const secret = (label) => (BigInt('0x' + sha(label).toString('hex')) % (L - 1n)) + 1n;
  const xA = secret('svrnty:588:kat:A'), xB = secret('svrnty:588:kat:B'), e = 1234n;
  const pk = sha('svrnty:588:kat:ed25519-one-time-key');            // 32 bytes standing in for the one-time Ed25519 key
  const n256 = BigInt('0x' + pk.toString('hex'));                    // the 32 bytes read as ONE big-endian 256-bit integer
  const pkLo = n256 & ((1n << 128n) - 1n), pkHi = n256 >> 128n;      // numeric split
  const K = O(poseidon([DS_K, pkLo, pkHi]));
  // The DISTINCT-K pair: each depositor has its OWN poll key in real use, so a store that delivers to "the slot's K" (or the first deposit's K
  // for both) must not be able to pass tests built on it. These are REAL Ed25519 one-time keys (throwaway seeds = SHA-256 of fixed labels), so
  // a test can really sign a poll/withdraw under them. Same split rule as K above: the 32 public-key bytes as ONE big-endian integer, lo/hi 128 bits.
  const edKey = (label) => {
    const seed = sha(label);
    const priv = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
    const pkb = Buffer.from(crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32));
    const n = BigInt('0x' + pkb.toString('hex')); const lo = n & ((1n << 128n) - 1n), hi = n >> 128n;
    return { seed, pkb, lo, hi, K: O(poseidon([DS_K, lo, hi])) };
  };
  const edA = edKey('svrnty:588:kat:ed25519-seed:A'), edB = edKey('svrnty:588:kat:ed25519-seed:B');
  if (new Set([edA.K, edB.K, K]).size !== 3) throw new Error('poll keys are not distinct');
  const side =(x, other_x) => {
    const P = bj.mulPointEscalar(bj.Base8, x), PO = bj.mulPointEscalar(bj.Base8, other_x);   // Y = other party's beacon key
    const Q = bj.mulPointEscalar(bj.Generator, other_x); // Y = 8*Q, Q = other_x * Generator
    const S = bj.mulPointEscalar(PO, x);
    const px = O(P[0]), py = O(P[1]), yx = O(PO[0]), yy = O(PO[1]);
    const pFirst = px < yx || (px === yx && py < yy);               // FULL-WIDTH integer comparison
    const [minx, miny, maxx, maxy] = pFirst ? [px, py, yx, yy] : [yx, yy, px, py];
    const H = O(poseidon([DS_SLOT, O(S[0]), O(S[1]), minx, miny, maxx, maxy, e]));
    const N = O(poseidon([DS_NULL, x, H]));
    return { P: [px, py], Y: [yx, yy], Q: [O(Q[0]), O(Q[1])], S: [O(S[0]), O(S[1])], pFirst, H, N };
  };
  const A = side(xA, xB), B = side(xB, xA);
  if (A.H !== B.H) throw new Error('slot differs between the two sides: ordering/ECDH bug');
  if (A.N === B.N) throw new Error('nullifiers equal');
  const inp = (x, s, N, Kv = K) => ({ e: e.toString(), H_e: s.H.toString(), N: N.toString(), K: Kv.toString(), x: x.toString(), Yx: s.Y[0].toString(), Yy: s.Y[1].toString(), Qx: s.Q[0].toString(), Qy: s.Q[1].toString() });
  fs.writeFileSync('build/input_A.json', JSON.stringify(inp(xA, A, A.N))); fs.writeFileSync('build/input_B.json', JSON.stringify(inp(xB, B, B.N)));
  fs.writeFileSync('build/input_Ae.json', JSON.stringify(inp(xA, A, A.N, edA.K)));   // A's witness with its OWN real Ed25519 poll key
  fs.writeFileSync('build/input_Be.json', JSON.stringify(inp(xB, B, B.N, edB.K)));   // B's witness with ITS OWN (same slot, same x, same N as before)
  const d = (v) => v.toString();
  const kat = {
    version: 'svrnty-588-slotbind-kat-v1', field_p: d(P_FIELD),
    tags: { DS_SLOT: { ascii: 'svrnty:588:slot:v1', dec: d(DS_SLOT), hex: hex64(DS_SLOT) }, DS_NULL: { ascii: 'svrnty:588:null:v1', dec: d(DS_NULL), hex: hex64(DS_NULL) }, DS_K: { ascii: 'svrnty:588:k:v1', dec: d(DS_K), hex: hex64(DS_K) } },
    derivations: { secrets: 'x = (SHA256(label) as BE int mod (L-1)) + 1, labels svrnty:588:kat:A / :B, L = babyjub subgroup order', beacon_key: 'P = x * Base8', Y: 'counterpart P', S: 'x * Y', order: 'pFirst = (Px,Py) < (Yx,Yy) lexicographic on the FULL integers (x, then y), min/max by that', H_e: 'Poseidon[DS_SLOT, Sx, Sy, minx, miny, maxx, maxy, e]', N: 'Poseidon[DS_NULL, x, H_e]', K: 'Poseidon[DS_K, pk_lo, pk_hi], pk = 32 bytes read as ONE big-endian 256-bit integer, lo = low 128 bits, hi = high 128 bits', wire_spelling: '64 lowercase hex, value < p (R1)' },
    epoch: d(e), pk_bytes_hex: pk.toString('hex'), pk_lo: d(pkLo), pk_hi: d(pkHi),
    K: { dec: d(K), hex: hex64(K) },
    ed25519_pair: {
      note: 'the DISTINCT-K pair: witnesses build/input_Ae.json (A with K_A) and build/input_Be.json (B with K_B); REAL Ed25519 throwaway keys, seed = SHA-256(label); pk bytes -> lo/hi by the same rule as K',
      A: { label: 'svrnty:588:kat:ed25519-seed:A', seed_hex: edA.seed.toString('hex'), pk_bytes_hex: edA.pkb.toString('hex'), pk_lo: d(edA.lo), pk_hi: d(edA.hi), K: { dec: d(edA.K), hex: hex64(edA.K) } },
      B: { label: 'svrnty:588:kat:ed25519-seed:B', seed_hex: edB.seed.toString('hex'), pk_bytes_hex: edB.pkb.toString('hex'), pk_lo: d(edB.lo), pk_hi: d(edB.hi), K: { dec: d(edB.K), hex: hex64(edB.K) } },
    },
    A: { x: d(xA), P: A.P.map(d), S: A.S.map(d), pFirst: A.pFirst, N: { dec: d(A.N), hex: hex64(A.N) } },
    B: { x: d(xB), P: B.P.map(d), S: B.S.map(d), pFirst: B.pFirst, N: { dec: d(B.N), hex: hex64(B.N) } },
    H_e: { dec: d(A.H), hex: hex64(A.H) },
  };
  fs.writeFileSync('build/kat.json', JSON.stringify(kat, null, 2)); console.log('ok H_e=' + hex64(A.H).slice(0, 16) + '.. pFirstA=' + A.pFirst + ' pFirstB=' + B.pFirst);
  process.exit(0);
})();
