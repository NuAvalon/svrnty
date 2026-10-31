// R3-b: PointLess circuit vs the reference full-integer comparison, incl. pairs with EQUAL low-252 bits and different top bits.
const { execFileSync } = require('child_process'); const fs = require('fs'); const snarkjs = require('snarkjs');
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; const M = (1n << 252n) - 1n;
const ref = (ax, ay, bx, by) => (ax < bx || (ax === bx && ay < by)) ? 1 : 0;
const trunc = (ax, ay, bx, by) => { const l = (v) => v & M; return (l(ax) < l(bx) || (l(ax) === l(bx) && l(ay) < l(by))) ? 1 : 0; };  // the OLD 252-bit rule
const cases = [];
const lo = 0x123456789abcdefn << 100n;
cases.push(['equal low252, hi 0 vs 1', lo, 5n, lo + (1n << 252n), 5n]);
cases.push(['equal low252, hi 1 vs 0', lo + (1n << 252n), 5n, lo, 5n]);
cases.push(['equal low252, hi 2 vs 3', lo + (2n << 252n), 5n, lo + (3n << 252n), 5n]);   // 3<<252 + lo < p? checked below
cases.push(['x equal, y decides', 7n, 1n, 7n, 2n]); cases.push(['x equal, y equal', 7n, 9n, 7n, 9n]);
cases.push(['x differs only in top bits, y reverses low order', lo + (1n << 252n), 1n, lo, 9n]);
cases.push(['0 vs p-1', 0n, 0n, P - 1n, 0n]); cases.push(['p-1 vs 0', P - 1n, 0n, 0n, 0n]);
cases.push(['2^252-1 vs 2^252', M, 0n, 1n << 252n, 0n]); cases.push(['2^252 vs 2^252-1', 1n << 252n, 0n, M, 0n]);
let bad = 0, divergeFromOld = 0;
(async () => {
  for (const [name, ax, ay, bx, by] of cases) {
    if (![ax, ay, bx, by].every((v) => v >= 0n && v < P)) { console.log('SKIP (not a field element):', name); continue; }
    fs.writeFileSync('build/cmp_in.json', JSON.stringify({ ax: ax.toString(), ay: ay.toString(), bx: bx.toString(), by: by.toString() }));
    execFileSync('node', ['build/cmp_test_js/generate_witness.js', 'build/cmp_test_js/cmp_test.wasm', 'build/cmp_in.json', 'build/cmp.wtns'], { stdio: 'pipe' });
    const w = await snarkjs.wtns.exportJson('build/cmp.wtns'); const out = BigInt(w[1]);
    const r = BigInt(ref(ax, ay, bx, by)); const t = trunc(ax, ay, bx, by);
    if (out !== r) bad++; if (BigInt(t) !== r) divergeFromOld++;
    console.log((out === r ? 'ok  ' : 'BAD ') + name.padEnd(48), 'circuit=' + out, 'full-int ref=' + r, 'old 252-bit rule=' + t);
  }
  console.log(bad === 0 ? 'ALL MATCH full-width reference' : 'MISMATCHES: ' + bad, '| cases where the OLD truncated rule disagreed with full-width:', divergeFromOld);
  process.exit(bad ? 1 : 0);
})();
