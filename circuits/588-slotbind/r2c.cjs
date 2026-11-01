// R2-c (static): every public wire (outputs + public inputs, indices 1..nOut+nPub) appears in >= 1 circuit constraint of the r1cs.
// Usage: node r2c.cjs <file.r1cs>   exit 0 = all constrained, 1 = some public wire appears in NO constraint.
const snarkjs = require('snarkjs');
(async () => {
  const j = await snarkjs.r1cs.exportJson(process.argv[2]);
  const nPub = j.nOutputs + j.nPubInputs; const seen = new Set();
  for (const c of j.constraints) for (const lc of c) for (const w of Object.keys(lc)) seen.add(Number(w));
  const missing = []; for (let w = 1; w <= nPub; w++) if (!seen.has(w)) missing.push(w);
  console.log(`${process.argv[2]}: constraints=${j.constraints.length} publicWires=${nPub} unconstrained=[${missing}]`, missing.length ? '=> RED' : '=> GREEN');
  process.exit(missing.length ? 1 : 0);
})();
