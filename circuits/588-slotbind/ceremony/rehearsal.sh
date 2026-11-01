#!/bin/bash
# #588 phase-2 DRESS REHEARSAL (DRAFT, apollo). Throwaway keys, worthless for security. Run ./build.sh first, then:
#   PTAU=/path/to/ppot_0080_14.ptau ceremony/rehearsal.sh
# Chain: z0 (groth16 setup) -> archie -> weft -> peter -> random beacon -> verify -> export vkey -> prove KAT A and B -> verify,
# then NEGs: a proof checked against a vkey from a DIFFERENT chain must fail, and a contribution wrapper that times out must fail loud.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PTAU:?set PTAU}"
S=node_modules/.bin/snarkjs
W=build/rehearsal; rm -rf "$W"; mkdir -p "$W"
# prepare takes ~15 min here; write to a temp name and rename, so an interrupted run can never leave a truncated file that the next run trusts
[ -s build/ptau_prepared.ptau ] || { $S powersoftau prepare phase2 "$PTAU" build/ptau_prepared.ptau.tmp >/dev/null && mv build/ptau_prepared.ptau.tmp build/ptau_prepared.ptau; }
$S groth16 setup build/slotbind.r1cs build/ptau_prepared.ptau $W/z0.zkey >/dev/null
ceremony/contribute.sh $W/z0.zkey $W/z1.zkey archie | tail -1
ceremony/contribute.sh $W/z1.zkey $W/z2.zkey weft  | tail -1
ceremony/contribute.sh $W/z2.zkey $W/z3.zkey peter | tail -1
BEACON=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')   # rehearsal only: the real one is pre-announced
$S zkey beacon $W/z3.zkey $W/final.zkey "$BEACON" 10 -n="rehearsal beacon" >/dev/null
$S zkey verify build/slotbind.r1cs build/ptau_prepared.ptau $W/final.zkey 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'ZKey Ok|ZKey Not' | tail -1
$S zkey export verificationkey $W/final.zkey $W/vkey.json >/dev/null
for k in A B; do
  $S groth16 prove $W/final.zkey build/w_$k.wtns $W/proof_$k.json $W/public_$k.json >/dev/null
  echo "KAT $k: $($S groth16 verify $W/vkey.json $W/public_$k.json $W/proof_$k.json 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tail -1)"
done
# NEG 1: a different chain's vkey must reject this proof
$S groth16 setup build/slotbind.r1cs build/ptau_prepared.ptau $W/o0.zkey >/dev/null
{ head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } | $S zkey contribute $W/o0.zkey $W/o1.zkey --name=other >/dev/null
$S zkey export verificationkey $W/o1.zkey $W/other_vkey.json >/dev/null
echo "NEG other-chain vkey: $($S groth16 verify $W/other_vkey.json $W/public_A.json $W/proof_A.json 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tail -1) (want Invalid proof)"
# NEG 2: the wrapper must fail loud on a timeout and leave no output zkey
if LIMIT=1 ceremony/contribute.sh $W/z0.zkey $W/t1.zkey slow >/dev/null 2>&1; then echo "NEG timeout: wrapper passed (BAD)"; else echo "NEG timeout: failed loud, output present=$([ -e $W/t1.zkey ] && echo yes || echo no) (want no)"; fi
echo "vkey sha256 $(sha256sum $W/vkey.json | cut -c1-64)  final.zkey sha256 $(sha256sum $W/final.zkey | cut -c1-64)"
