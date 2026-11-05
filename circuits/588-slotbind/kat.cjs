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
  const side = (x, other_x) => {
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
  const inp = (x, s, N) => ({ e: e.toString(), H_e: s.H.toString(), N: N.toString(), K: K.toString(), x: x.toString(), Yx: s.Y[0].toString(), Yy: s.Y[1].toString(), Qx: s.Q[0].toString(), Qy: s.Q[1].toString() });
  fs.writeFileSync('build/input_A.json', JSON.stringify(inp(xA, A, A.N))); fs.writeFileSync('build/input_B.json', JSON.stringify(inp(xB, B, B.N)));
  const d = (v) => v.toString();
  const kat = {
    version: 'svrnty-588-slotbind-kat-v1', field_p: d(P_FIELD),
    tags: { DS_SLOT: { ascii: 'svrnty:588:slot:v1', dec: d(DS_SLOT), hex: hex64(DS_SLOT) }, DS_NULL: { ascii: 'svrnty:588:null:v1', dec: d(DS_NULL), hex: hex64(DS_NULL) }, DS_K: { ascii: 'svrnty:588:k:v1', dec: d(DS_K), hex: hex64(DS_K) } },
    derivations: { secrets: 'x = (SHA256(label) as BE int mod (L-1)) + 1, labels svrnty:588:kat:A / :B, L = babyjub subgroup order', beacon_key: 'P = x * Base8', Y: 'counterpart P', S: 'x * Y', order: 'pFirst = (Px,Py) < (Yx,Yy) lexicographic on the FULL integers (x, then y), min/max by that', H_e: 'Poseidon[DS_SLOT, Sx, Sy, minx, miny, maxx, maxy, e]', N: 'Poseidon[DS_NULL, x, H_e]', K: 'Poseidon[DS_K, pk_lo, pk_hi], pk = 32 bytes read as ONE big-endian 256-bit integer, lo = low 128 bits, hi = high 128 bits', wire_spelling: '64 lowercase hex, value < p (R1)' },
    epoch: d(e), pk_bytes_hex: pk.toString('hex'), pk_lo: d(pkLo), pk_hi: d(pkHi),
    K: { dec: d(K), hex: hex64(K) },
    A: { x: d(xA), P: A.P.map(d), S: A.S.map(d), pFirst: A.pFirst, N: { dec: d(A.N), hex: hex64(A.N) } },
    B: { x: d(xB), P: B.P.map(d), S: B.S.map(d), pFirst: B.pFirst, N: { dec: d(B.N), hex: hex64(B.N) } },
    H_e: { dec: d(A.H), hex: hex64(A.H) },
  };
  fs.writeFileSync('build/kat.json', JSON.stringify(kat, null, 2)); console.log('ok H_e=' + hex64(A.H).slice(0, 16) + '.. pFirstA=' + A.pFirst + ' pFirstB=' + B.pFirst);
  process.exit(0);
})();
