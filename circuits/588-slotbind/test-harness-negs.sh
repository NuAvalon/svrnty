#!/bin/bash
# Mutants for the JS harnesses build.sh relies on (Flint #3088): each harness must EXIT NONZERO on its own failure.
#   r2c.cjs      : slotbind with the K*K constraint removed (K in no constraint)      -> r2c must exit 1   (control: real r1cs -> 0)
#   kat.cjs      : a copy whose slot ordering ignores the comparison (always P first) -> kat must throw, exit != 0 (control -> 0)
#   cmp_test.cjs : fullcmp with the top 2 bits ignored (the old 252-bit rule)         -> cmp_test must exit 1 (control -> 0)
# Usage: CIRCOM=/path/to/circom ./test-harness-negs.sh ; works in temp copies, never touches build/.
set -uo pipefail
cd "$(dirname "$0")"
: "${CIRCOM:?set CIRCOM}"
fail=0
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mk() { mkdir -p "$T/$1/build"; cp ./*.circom ./*.cjs ./*.json "$T/$1/"; ln -s "$PWD/node_modules" "$T/$1/node_modules"; }
expect() { # name, want_rc_is_zero(0|1), actual rc
  if { [ "$2" = 0 ] && [ "$3" -eq 0 ]; } || { [ "$2" = 1 ] && [ "$3" -ne 0 ]; }; then echo "ok   $1 (rc=$3)"; else echo "RED  $1 (rc=$3, wanted $([ "$2" = 0 ] && echo 0 || echo nonzero))"; fail=1; fi
}
# --- r2c.cjs ---
mk r2c; (cd "$T/r2c" && "$CIRCOM" slotbind.circom --r1cs --O2 -l node_modules -o build >/dev/null 2>&1 && node r2c.cjs build/slotbind.r1cs >/dev/null 2>&1); expect "r2c control (real circuit)" 0 $?
sed -i 's/signal Ksq; Ksq <== K \* K;/signal Ksq;/' "$T/r2c/slotbind.circom"; grep -q 'Ksq <==' "$T/r2c/slotbind.circom" && { echo "RED  r2c mutant did not apply"; fail=1; }
(cd "$T/r2c" && "$CIRCOM" slotbind.circom --r1cs --O2 -l node_modules -o build >/dev/null 2>&1 && node r2c.cjs build/slotbind.r1cs >/dev/null 2>&1); expect "r2c on K*K-removed circuit" 1 $?
# --- kat.cjs ---
mk kat; (cd "$T/kat" && node kat.cjs >/dev/null 2>&1); expect "kat control" 0 $?
sed -i 's/const pFirst = px < yx || (px === yx \&\& py < yy);/const pFirst = true;/' "$T/kat/kat.cjs"; grep -q 'const pFirst = true;' "$T/kat/kat.cjs" || { echo "RED  kat mutant did not apply"; fail=1; }
(cd "$T/kat" && node kat.cjs >/dev/null 2>&1); expect "kat with ordering ignored" 1 $?
# --- cmp_test.cjs ---
mk cmp; (cd "$T/cmp" && "$CIRCOM" cmp_test.circom --r1cs --wasm --O2 -l node_modules -o build >/dev/null 2>&1 && node cmp_test.cjs >/dev/null 2>&1); expect "cmp_test control" 0 $?
sed -i 's/ahi <== ab.out\[252\] + 2 \* ab.out\[253\];/ahi <== 0;/; s/bhi <== bb.out\[252\] + 2 \* bb.out\[253\];/bhi <== 0;/' "$T/cmp/fullcmp.circom"; [ "$(grep -c '[ab]hi <== 0;' "$T/cmp/fullcmp.circom")" = 2 ] || { echo "RED  cmp mutant did not apply"; fail=1; }
(cd "$T/cmp" && "$CIRCOM" cmp_test.circom --r1cs --wasm --O2 -l node_modules -o build >/dev/null 2>&1 && node cmp_test.cjs >/dev/null 2>&1); expect "cmp_test on truncated comparator" 1 $?
[ $fail -eq 0 ] && echo "harness NEGs: all as expected => GREEN" || { echo "harness NEGs: RED"; exit 1; }
