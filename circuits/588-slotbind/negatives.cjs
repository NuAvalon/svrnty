const { buildBabyjub } = require('circomlibjs');
const fs = require('fs'); const { execFileSync } = require('child_process'); const crypto = require('crypto');
(async () => {
  const bj = await buildBabyjub(); const F = bj.F; const O = (e) => F.toObject(e); const L = bj.subOrder;
  const base = JSON.parse(fs.readFileSync('build/input_A.json'));
  const run = (name, input) => {
    fs.writeFileSync('build/neg.json', JSON.stringify(input));
    try { execFileSync('node', ['build/slotbind_js/generate_witness.js', 'build/slotbind_js/slotbind.wasm', 'build/neg.json', 'build/neg.wtns'], { stdio: 'pipe' }); console.log(name.padEnd(46), '=> ACCEPTED  (BAD if this is a negative)'); }
    catch (e) { const m = String(e.stderr || e.message).split('\n').find((l) => /Assert Failed|Error in template/.test(l)) || 'rejected'; console.log(name.padEnd(46), '=> rejected  (' + m.trim().slice(0, 70) + ')'); }
  };
  run('control: honest witness', base);
  run('NEG wrong slot H_e', { ...base, H_e: (BigInt(base.H_e) + 1n).toString() });
  run('NEG wrong nullifier N', { ...base, N: (BigInt(base.N) + 1n).toString() });
  run('NEG x + L (out of range, same P)', { ...base, x: (BigInt(base.x) + L).toString() });
  // Y on the curve but NOT in the prime-order subgroup (torsion component), with the honest Q (cannot satisfy 8Q = Y)
  let Yt = null;
  for (let i = 0; i < 2000 && !Yt; i++) { const buf = crypto.randomBytes(32); buf[31] &= 0x7f; const p = bj.unpackPoint(buf); if (p && bj.inCurve(p) && !bj.inSubgroup(p)) Yt = p; }
  if (Yt) run('NEG Y not in prime subgroup', { ...base, Yx: O(Yt[0]).toString(), Yy: O(Yt[1]).toString() });
  else console.log('could not sample a non-subgroup point');
  run('NEG Y = identity (0,1)', { ...base, Yx: '0', Yy: '1' });
})();
