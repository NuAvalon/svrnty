#!/bin/bash
# THROWAWAY single-party setup + proof of the KAT-A witness, for the R1 integration test and timing ONLY.
# NOT the ceremony. The keys are worthless for security and must never ship. Run ./build.sh first.
# Usage: PTAU=/path/to/ppot_0080_14.ptau ./throwaway-prove.sh   (PSE file is not phase-2 prepared; this prepares a local copy)
set -euo pipefail
cd "$(dirname "$0")"
: "${PTAU:?set PTAU=/path/to/ppot_0080_14.ptau}"
S=node_modules/.bin/snarkjs
[ -s build/ptau_prepared.ptau ] || { $S powersoftau prepare phase2 "$PTAU" build/ptau_prepared.ptau.tmp >/dev/null && mv build/ptau_prepared.ptau.tmp build/ptau_prepared.ptau; }
$S groth16 setup build/slotbind.r1cs build/ptau_prepared.ptau build/z0.zkey >/dev/null
# entropy from the OS via stdin, never on a command line (Flint ceremony hygiene)
{ head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } | $S zkey contribute build/z0.zkey build/z1.zkey --name=throwaway >/dev/null
$S zkey export verificationkey build/z1.zkey build/vkey.json >/dev/null
a=$(date +%s.%N); $S groth16 prove build/z1.zkey build/w_A.wtns build/proof_A.json build/public_A.json >/dev/null; b=$(date +%s.%N)
echo "prove A: $(python3 -c "print(round($b-$a,2))") s (node, this machine)"
$S groth16 verify build/vkey.json build/public_A.json build/proof_A.json 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tail -1
