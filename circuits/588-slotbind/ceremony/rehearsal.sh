#!/bin/bash
# #588 phase-2 DRESS REHEARSAL (DRAFT v2, apollo). Throwaway keys, worthless for security. Run ./build.sh first, then:
#   PTAU=/path/to/ppot_0080_14.ptau ceremony/rehearsal.sh
# EVERY check is an assertion: any deviation exits nonzero, so rc 0 means every line below passed (Flint #3074).
# Chain: z0 (groth16 setup) -> archie -> weft -> peter -> random beacon -> verify -> export vkey -> prove KAT A and B -> verify.
# NEGs (each must refuse): wrong hand-off sha, wrong expected chain (dropped contribution), swapped ptau, unpinned tool, other-chain vkey, timeout.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${PTAU:?set PTAU (the PSE ppot_0080_14.ptau; the prepared copy is built/checked here)}"
PSE_PTAU=$PTAU; unset PTAU   # contribute.sh reads $PTAU as its own override; it must see the prepared default, not this
S=node_modules/.bin/snarkjs
pin() { node -p "require('./pins.json').$1"; }
fail() { echo "REHEARSAL FAILED: $*" >&2; exit 1; }
sha() { sha256sum "$1" | cut -d' ' -f1; }
strip() { sed 's/\x1b\[[0-9;]*m//g'; }
W=build/rehearsal; rm -rf "$W"; mkdir -p "$W"
# the prepared file: build it if absent (temp + rename), then it MUST equal the pinned hash
[ -s build/ptau_prepared.ptau ] || { $S powersoftau prepare phase2 "$PSE_PTAU" build/ptau_prepared.ptau.tmp >/dev/null && mv build/ptau_prepared.ptau.tmp build/ptau_prepared.ptau; }
[ "$(sha build/ptau_prepared.ptau)" = "$(pin phase1_ptau.prepared_sha256)" ] || fail "prepared ptau differs from the pin"
echo "ASSERT prepared ptau == pinned $(pin phase1_ptau.prepared_sha256 | cut -c1-12)…"
$S groth16 setup build/slotbind.r1cs build/ptau_prepared.ptau $W/z0.zkey >/dev/null
[ "$(sha $W/z0.zkey)" = "$(pin phase2_tooling.z0_sha256)" ] || fail "z0 differs from the pinned stage-0 hash"
echo "ASSERT z0 == pinned stage 0 $(pin phase2_tooling.z0_sha256 | cut -c1-12)…"
stage_sha() { echo "$1" | sed -n 's/^OK: .* stage sha256 = \([0-9a-f]\{64\}\).*/\1/p'; }
prev=$W/z0.zkey; chain=""; names=(archie weft peter)
for i in 0 1 2; do
  n=${names[$i]}; chain=${chain:+$chain|}$n; out=$W/z$((i+1)).zkey
  res=$(ceremony/contribute.sh "$prev" "$out" "$n" "$(sha "$prev")" "$chain") || fail "contribution $n refused"
  echo "$res" | tail -3
  grep -q "pins.json sha256 = $(sha pins.json)   test seams set: none" <<<"$res" || fail "$n: transcript lacks the pins.json sha256 / 'test seams set: none' line"
  [ "$(stage_sha "$res")" = "$(sha "$out")" ] || fail "printed stage sha256 != file sha256 for $n"
  prev=$out
done
BEACON=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')   # rehearsal only: the real one is pre-announced
$S zkey beacon $W/z3.zkey $W/final.zkey "$BEACON" 10 -n="rehearsal beacon" >/dev/null
v=$($S zkey verify build/slotbind.r1cs build/ptau_prepared.ptau $W/final.zkey 2>&1 | strip) || fail "final zkey verify exited nonzero"
grep -q 'ZKey Ok!' <<<"$v" || fail "final chain: ZKey Ok! missing"
got=$(sed -n 's/^\[INFO\]  snarkJS: contribution #\([0-9]*\) \(.*\):$/\1 \2/p' <<<"$v" | sort -n | cut -d' ' -f2- | paste -sd'|')
[ "$got" = "archie|weft|peter|rehearsal beacon" ] || fail "final chain list is [$got]"
echo "ASSERT final chain verifies, contributions == [$got]"
$S zkey export verificationkey $W/final.zkey $W/vkey.json >/dev/null
for k in A B; do
  $S groth16 prove $W/final.zkey build/w_$k.wtns $W/proof_$k.json $W/public_$k.json >/dev/null
  r=$($S groth16 verify $W/vkey.json $W/public_$k.json $W/proof_$k.json 2>&1 | strip) || fail "KAT $k verify exited nonzero"
  [[ "$r" == *"OK!"* ]] || fail "KAT $k did not verify: $r"
  echo "ASSERT KAT $k proof verifies under the final vkey"
done
# --- NEGs: each MUST refuse and leave no output zkey ---
neg() { # name, expect-substring, command...
  local name=$1 want=$2; shift 2
  local out; if out=$("$@" 2>&1); then fail "NEG $name: the command SUCCEEDED"; fi
  [[ "$out" == *"$want"* ]] || fail "NEG $name: refused, but not for the expected reason ($want): $out"
  echo "ASSERT NEG $name: refused ($want)"
}
in1=$W/z1.zkey; in1sha=$(sha $in1)
neg "wrong hand-off sha"        "does not match the expected hand-off" ceremony/contribute.sh $in1 $W/n1.zkey weft "$(printf '0%.0s' {1..64})" "archie|weft"
neg "dropped contribution"      "chain contribution list is" ceremony/contribute.sh $in1 $W/n2.zkey weft "$in1sha" "weft"
neg "wrong last name"           "must end with this contributor's name" ceremony/contribute.sh $in1 $W/n3.zkey weft "$in1sha" "archie|peter"
neg "swapped ptau (the PSE file, not the prepared one)" "ptau is not the pinned prepared file" env PTAU="$PSE_PTAU" ceremony/contribute.sh $in1 $W/n4.zkey weft "$in1sha" "archie|weft"
sed 's/"snarkjs_cli_cjs_sha256": "./"snarkjs_cli_cjs_sha256": "0/' pins.json > $W/pins_bad.json
neg "unpinned snarkjs"          "build/cli.cjs differs from the pin" env PINS=$W/pins_bad.json ceremony/contribute.sh $in1 $W/n5.zkey weft "$in1sha" "archie|weft"
neg "timeout"                   "timed out" env LIMIT=1 ceremony/contribute.sh $in1 $W/n6.zkey weft "$in1sha" "archie|weft"
for f in n1 n2 n3 n4 n5 n6; do [ ! -e $W/$f.zkey ] || fail "NEG left an output zkey: $f"; done
echo "ASSERT no NEG left an output zkey"
# other-chain vkey must reject this proof (and exit nonzero)
$S groth16 setup build/slotbind.r1cs build/ptau_prepared.ptau $W/o0.zkey >/dev/null
{ head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } | $S zkey contribute $W/o0.zkey $W/o1.zkey --name=other >/dev/null
$S zkey export verificationkey $W/o1.zkey $W/other_vkey.json >/dev/null
if r=$($S groth16 verify $W/other_vkey.json $W/public_A.json $W/proof_A.json 2>&1 | strip); then fail "NEG other-chain vkey: verify exited 0"; fi
[[ "$r" == *"Invalid proof"* ]] || fail "NEG other-chain vkey: not 'Invalid proof': $r"
echo "ASSERT NEG other-chain vkey: Invalid proof"
echo "vkey sha256 $(sha $W/vkey.json)  final.zkey sha256 $(sha $W/final.zkey)"
echo "REHEARSAL PASSED (every ASSERT above held)"
