const { buildBabyjub } = require('circomlibjs');
const fs = require('fs'); const { execFileSync } = require('child_process'); const crypto = require('crypto');
(async () => {
  const bj = await buildBabyjub(); const F = bj.F; const O = (e) => F.toObject(e); const L = bj.subOrder;
  const base = JSON.parse(fs.readFileSync('build/input_A.json'));
  let bad = 0;
  // A NEG counts as rejected ONLY if the witness generator failed with a circom assertion; any other failure (missing wasm, crash) is UNEXPECTED, not a pass.
  const run = (name, input, wantAccept = false) => {
    fs.writeFileSync('build/neg.json', JSON.stringify(input));
    let accepted = false, why = '';
    try { execFileSync('node', ['build/slotbind_js/generate_witness.js', 'build/slotbind_js/slotbind.wasm', 'build/neg.json', 'build/neg.wtns'], { stdio: 'pipe' }); accepted = true; }
    catch (e) { const err = String(e.stderr || e.message); why = err.split('\n').find((l) => /Assert Failed|Error in template/.test(l)) || ''; if (!/Assert Failed/.test(err)) { bad++; console.log(name.padEnd(46), '=> FAILED FOR A NON-ASSERT REASON  <== UNEXPECTED  (' + err.split('\n')[0].slice(0, 70) + ')'); return; } }
    const ok = accepted === wantAccept; if (!ok) bad++;
    console.log(name.padEnd(46), accepted ? '=> ACCEPTED' : '=> rejected  (' + why.trim().slice(0, 70) + ')', ok ? '' : ' <== UNEXPECTED');
  };
  run('control: honest witness', base, true);
  run('NEG wrong slot H_e', { ...base, H_e: (BigInt(base.H_e) + 1n).toString() });
  run('NEG wrong nullifier N', { ...base, N: (BigInt(base.N) + 1n).toString() });
  run('NEG x + L (out of range, same P)', { ...base, x: (BigInt(base.x) + L).toString() });
  // Y on the curve but NOT in the prime-order subgroup (torsion component), with the honest Q (cannot satisfy 8Q = Y)
  let Yt = null;
  for (let i = 0; i < 2000 && !Yt; i++) { const buf = crypto.randomBytes(32); buf[31] &= 0x7f; const p = bj.unpackPoint(buf); if (p && bj.inCurve(p) && !bj.inSubgroup(p)) Yt = p; }
  if (Yt) run('NEG Y not in prime subgroup', { ...base, Yx: O(Yt[0]).toString(), Yy: O(Yt[1]).toString() });
  else { bad++; console.log('could not sample a non-subgroup point  <== UNEXPECTED'); }
  run('NEG Y = identity (0,1)', { ...base, Yx: '0', Yy: '1' });
  console.log(bad ? `negatives: ${bad} UNEXPECTED => RED` : 'negatives: all as expected => GREEN');
  process.exit(bad ? 1 : 0);
})();
