#!/bin/bash
# Mutants for the JS harnesses build.sh relies on (Flint #3088): each harness must EXIT NONZERO on its own failure.
#   r2c.cjs      : slotbind with the K*K constraint removed (K in no constraint)      -> r2c must exit 1   (control: real r1cs -> 0)
#   kat.cjs      : a copy whose slot ordering ignores the comparison (always P first) -> kat must throw, exit != 0 (control -> 0)
#   cmp_test.cjs : fullcmp with the top 2 bits ignored (the old 252-bit rule)         -> cmp_test must exit 1 (control -> 0)
# Each case: (1) the COMPILE runs on its own and must exit 0 for every control AND every mutant (a mutant that breaks the compile is not a pass),
# then (2) the harness runs alone and is scored on ITS rc AND on its own failure text (so an unrelated throw does not count as caught).
# Usage: CIRCOM=/path/to/circom ./test-harness-negs.sh ; works in temp copies, never touches build/.
set -uo pipefail
cd "$(dirname "$0")"
: "${CIRCOM:?set CIRCOM}"
fail=0
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mk() { mkdir -p "$T/$1/build"; cp ./*.circom ./*.cjs ./*.json "$T/$1/"; ln -s "$PWD/node_modules" "$T/$1/node_modules"; }
red() { echo "RED  $*"; fail=1; }
compile() { # dir, circuit, flags...  -> must exit 0
  local d=$1 c=$2; shift 2
  (cd "$T/$d" && "$CIRCOM" "$c" "$@" -l node_modules -o build >/dev/null 2>&1); local rc=$?
  [ $rc -eq 0 ] && echo "     $d: compile rc=0" || red "$d: compile rc=$rc (the mutant/control must COMPILE for the harness to be tested)"
  return $rc
}
run() { # dir, name, wantzero(0|1), must-contain text, cmd...   -> scored on the harness rc and its own text
  local d=$1 name=$2 want=$3 txt=$4; shift 4
  local out rc; out=$(cd "$T/$d" && "$@" 2>&1); rc=$?
  if { [ "$want" = 0 ] && [ $rc -eq 0 ]; } || { [ "$want" = 1 ] && [ $rc -ne 0 ]; }; then
    if grep -qF -- "$txt" <<<"$out"; then echo "ok   $name (harness rc=$rc, saw: $txt)"; else red "$name: rc ok ($rc) but the harness's own text '$txt' was not printed"; fi
  else red "$name: harness rc=$rc, wanted $([ "$want" = 0 ] && echo 0 || echo nonzero)"; fi
}
# --- r2c.cjs ---
mk r2c; compile r2c slotbind.circom --r1cs --O2 && run r2c "r2c control (real circuit)" 0 "=> GREEN" node r2c.cjs build/slotbind.r1cs
sed -i 's/signal Ksq; Ksq <== K \* K;/signal Ksq;/' "$T/r2c/slotbind.circom"; grep -q 'Ksq <==' "$T/r2c/slotbind.circom" && red "r2c mutant did not apply"
compile r2c slotbind.circom --r1cs --O2 && run r2c "r2c on K*K-removed circuit" 1 "=> RED" node r2c.cjs build/slotbind.r1cs
# --- kat.cjs ---
mk kat; run kat "kat control" 0 "ok H_e=" node kat.cjs
sed -i 's/const pFirst = px < yx || (px === yx \&\& py < yy);/const pFirst = true;/' "$T/kat/kat.cjs"; grep -q 'const pFirst = true;' "$T/kat/kat.cjs" || red "kat mutant did not apply"
run kat "kat with ordering ignored" 1 "slot differs between the two sides" node kat.cjs
# --- cmp_test.cjs ---
mk cmp; compile cmp cmp_test.circom --r1cs --wasm --O2 && run cmp "cmp_test control" 0 "ALL MATCH full-width reference" node cmp_test.cjs
sed -i 's/ahi <== ab.out\[252\] + 2 \* ab.out\[253\];/ahi <== 0;/; s/bhi <== bb.out\[252\] + 2 \* bb.out\[253\];/bhi <== 0;/' "$T/cmp/fullcmp.circom"; [ "$(grep -c '[ab]hi <== 0;' "$T/cmp/fullcmp.circom")" = 2 ] || red "cmp mutant did not apply"
compile cmp cmp_test.circom --r1cs --wasm --O2 && run cmp "cmp_test on truncated comparator" 1 "MISMATCHES" node cmp_test.cjs
[ $fail -eq 0 ] && echo "harness NEGs: all as expected => GREEN" || { echo "harness NEGs: RED"; exit 1; }
