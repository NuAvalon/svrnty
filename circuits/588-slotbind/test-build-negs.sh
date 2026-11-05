#!/bin/bash
# NEGs for build.sh itself: each mutation of a COPY of this directory must make build.sh exit nonzero with the expected REFUSED line.
# Usage: CIRCOM=/path/to/circom ./test-build-negs.sh   (~1 min per case; uses a temp copy, never touches the real build/ or pins)
set -uo pipefail
cd "$(dirname "$0")"
: "${CIRCOM:?set CIRCOM}"
ver=$(node -p "const p=require('./pins.json');const h=require('crypto').createHash('sha256').update(require('fs').readFileSync('$CIRCOM')).digest('hex');Object.entries(p.circom_binaries_sha256).find(([v,x])=>x===h)[0]")
fail=0
case_() { # name, file, node-expression mutating the parsed/raw file text `t`, expected REFUSED substring
  local name=$1 file=$2 expr=$3 want=$4 tmp; tmp=$(mktemp -d)
  mkdir "$tmp/c"; cp -r ./*.circom ./*.cjs ./*.json ./build.sh "$tmp/c/" 2>/dev/null; ln -s "$PWD/node_modules" "$tmp/c/node_modules"
  node -e "const fs=require('fs');let t=fs.readFileSync('$tmp/c/$file','utf8');t=($expr);fs.writeFileSync('$tmp/c/$file',t)"
  out=$(CIRCOM="$CIRCOM" bash "$tmp/c/build.sh" 2>&1); rc=$?
  if [ $rc -ne 0 ] && grep -q "$want" <<<"$out" && ! grep -q BUILD_OK <<<"$out"; then echo "NEG $name: refused as expected (rc=$rc)"; else echo "NEG $name: NOT REFUSED (rc=$rc) <== RED"; fail=1; fi
  rm -rf "$tmp"
}
case_ "KAT differs from pinned kat.json" kat.json "t.replace(/[0-9a-f]{8}/, '00000000')" "built KAT differs"
case_ "r1cs pin changed"        pins.json "(()=>{const j=JSON.parse(t);j.r1cs_sha256='0'+j.r1cs_sha256.slice(1);return JSON.stringify(j,null,2)})()" "r1cs sha256"
case_ "wasm pin changed"        pins.json "(()=>{const j=JSON.parse(t);j.wasm_sha256['$ver']='0'+j.wasm_sha256['$ver'].slice(1);return JSON.stringify(j,null,2)})()" "wasm sha256"
case_ "witness_calculator.js pin changed" pins.json "(()=>{const j=JSON.parse(t);j.witness_calculator_js_sha256['$ver']='0'+j.witness_calculator_js_sha256['$ver'].slice(1);return JSON.stringify(j,null,2)})()" "witness_calculator.js sha256"
case_ "generate_witness.js pin changed"   pins.json "(()=>{const j=JSON.parse(t);j.generate_witness_js_sha256['$ver']='0'+j.generate_witness_js_sha256['$ver'].slice(1);return JSON.stringify(j,null,2)})()" "generate_witness.js sha256"
[ $fail -eq 0 ] && echo "build NEGs: all refused => GREEN" || { echo "build NEGs: RED"; exit 1; }
