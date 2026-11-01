#!/bin/bash
# #588 slot-binding circuit: reproducible build + checks. Usage: CIRCOM=/path/to/circom ./build.sh
# Needs: `npm ci` in this directory first (exact snarkjs/circomlib/circomlibjs from package-lock.json).
# Fails closed on: unknown circom binary, r1cs sha256 != pins.json, any public wire unconstrained (R2-c), any KAT witness rejected.
set -euo pipefail
cd "$(dirname "$0")"
: "${CIRCOM:?set CIRCOM=/path/to/circom (see pins.json for accepted binary sha256)}"
PINS=pins.json
bin_sha=$(sha256sum "$CIRCOM" | cut -d' ' -f1)
node -e "const p=require('./$PINS');process.exit(Object.values(p.circom_binaries_sha256).includes('$bin_sha')?0:1)" || { echo "REFUSED: circom binary sha256 $bin_sha is not pinned in $PINS"; exit 1; }
rm -rf build && mkdir -p build
"$CIRCOM" slotbind.circom --r1cs --wasm --sym --O2 -l node_modules -o build >/dev/null
got=$(sha256sum build/slotbind.r1cs | cut -d' ' -f1)
want=$(node -p "require('./$PINS').r1cs_sha256")
[ "$got" = "$want" ] || { echo "REFUSED: r1cs sha256 $got != pinned $want"; exit 1; }
echo "r1cs sha256 OK ($got)"
# The witness-generator wasm is what devices run. It is deterministic per compiler version but differs between versions, so it is pinned per version (the version is identified by the pinned binary hash above).
ver=$(node -p "const p=require('./$PINS');Object.entries(p.circom_binaries_sha256).find(([v,h])=>h==='$bin_sha')[0]")
wgot=$(sha256sum build/slotbind_js/slotbind.wasm | cut -d' ' -f1)
wwant=$(node -p "require('./$PINS').wasm_sha256['$ver']")
[ "$wgot" = "$wwant" ] || { echo "REFUSED: wasm sha256 $wgot != pinned $wwant (circom $ver)"; exit 1; }
echo "wasm sha256 OK ($wgot, circom $ver)"
# witness_calculator.js drives the wasm on devices; generate_witness.js is the node entry the KAT loop below executes. Both enforced like the wasm, BEFORE anything runs (Athena #2932).
jgot=$(sha256sum build/slotbind_js/witness_calculator.js | cut -d' ' -f1)
jwant=$(node -p "require('./$PINS').witness_calculator_js_sha256['$ver']")
[ "$jgot" = "$jwant" ] || { echo "REFUSED: witness_calculator.js sha256 $jgot != pinned $jwant (circom $ver)"; exit 1; }
echo "witness_calculator.js sha256 OK ($jgot)"
ggot=$(sha256sum build/slotbind_js/generate_witness.js | cut -d' ' -f1)
gwant=$(node -p "require('./$PINS').generate_witness_js_sha256['$ver']")
[ "$ggot" = "$gwant" ] || { echo "REFUSED: generate_witness.js sha256 $ggot != pinned $gwant (circom $ver)"; exit 1; }
echo "generate_witness.js sha256 OK ($ggot)"
echo "recorded, not enforced: sym $(sha256sum build/slotbind.sym | cut -d' ' -f1)"
node r2c.cjs build/slotbind.r1cs
node kat.cjs
for s in A B; do node build/slotbind_js/generate_witness.js build/slotbind_js/slotbind.wasm build/input_$s.json build/w_$s.wtns; echo "KAT witness $s accepted"; done
# NOT `cmp ... && echo ...`: under set -e a failing command in the non-final position of an && list does NOT abort the script (it would print BUILD_OK on a KAT mismatch).
cmp <(node -e "const k=require('./kat.json');console.log(JSON.stringify(k))") <(node -e "const k=require('./build/kat.json');console.log(JSON.stringify(k))") >/dev/null || { echo "REFUSED: built KAT differs from the pinned kat.json"; exit 1; }
echo "KAT matches pinned kat.json"
"$CIRCOM" cmp_test.circom --r1cs --wasm --O2 -l node_modules -o build >/dev/null
node cmp_test.cjs | tail -1
node negatives.cjs
echo BUILD_OK
