#!/bin/bash
# #588 phase-2 contribution wrapper (DRAFT v2, apollo; Flint R1-R3 + nit). One contributor step, fail loud, fail closed.
# Usage: ceremony/contribute.sh <in.zkey> <out.zkey> <name> <expected_in_sha256> <expected_chain>
#   expected_chain = the contribution names the chain must contain AFTER this step, in order, joined with '|'
#                    (e.g. the 3rd contributor passes "archie|weft|peter"); its last element must equal <name>.
# Refuses (nonzero, no output zkey) unless ALL hold, in this order, BEFORE any contribution is made:
#   - snarkjs is the pinned tool: version, and sha256 of build/cli.cjs and build/main.cjs, equal pins.json (phase2_tooling)
#   - the r1cs is the pinned one, and the ptau is the pinned PREPARED file (pins.json phase1_ptau.prepared_sha256)
#   - sha256(<in.zkey>) == <expected_in_sha256>   (the hand-off pin: one operator cannot give different contributors different forks)
# and AFTER the contribution: the whole-chain `zkey verify` passes AND its contribution list == <expected_chain>, exactly.
# Entropy: 64 bytes from the OS CSPRNG, hex, ONE line on stdin WITH the trailing newline (snarkjs reads it with readline; without the newline
# it hangs, hence the timeout). Never on a command line, never logged, never written to disk. snarkjs also mixes 64 more OS CSPRNG bytes.
# Prints the transcript line "stage sha256 = X": the NEXT contributor must pass X as <expected_in_sha256>.
set -euo pipefail
die() { echo "FAILED: $*" >&2; exit 1; }
# resolve caller-relative paths BEFORE changing directory (a relative path must not silently point somewhere else)
[ $# -eq 5 ] || die "usage: contribute.sh <in.zkey> <out.zkey> <name> <expected_in_sha256> <expected_chain>"
IN=$(realpath -e -- "$1") || die "input zkey $1 not found"
OUT=$(realpath -m -- "$2"); NAME=$3; EXP_IN=$4; EXP_CHAIN=$5
cd "$(dirname "$0")/.."
PINS=${PINS:-pins.json}   # test seam for the NEGs only; the real run never sets it
R1CS=${R1CS:-build/slotbind.r1cs}; PTAU=${PTAU:-build/ptau_prepared.ptau}; LIMIT=${LIMIT:-300}
S=node_modules/.bin/snarkjs
pin() { node -p "require('./$PINS').$1"; }
[[ "$NAME" =~ ^[A-Za-z0-9._\ -]+$ ]] || die "name must be non-empty and use only letters, digits, space . _ -"
[[ "$EXP_IN" =~ ^[0-9a-f]{64}$ ]] || die "expected_in_sha256 must be 64 lowercase hex"
[ "${EXP_CHAIN##*|}" = "$NAME" ] || die "expected_chain must end with this contributor's name"
[ ! -e "$OUT" ] || die "refusing to overwrite $OUT"
# 1. the tool is the pinned tool
[ "$(node -p "require('./node_modules/snarkjs/package.json').version")" = "$(pin phase2_tooling.snarkjs_version)" ] || die "snarkjs version is not the pinned one"
[ "$(sha256sum node_modules/snarkjs/build/cli.cjs | cut -d' ' -f1)" = "$(pin phase2_tooling.snarkjs_cli_cjs_sha256)" ] || die "snarkjs build/cli.cjs differs from the pin"
[ "$(sha256sum node_modules/snarkjs/build/main.cjs | cut -d' ' -f1)" = "$(pin phase2_tooling.snarkjs_main_cjs_sha256)" ] || die "snarkjs build/main.cjs differs from the pin"
# 2. the circuit and the phase-1 base are the pinned ones
[ "$(sha256sum "$R1CS" | cut -d' ' -f1)" = "$(pin r1cs_sha256)" ] || die "r1cs differs from the pin"
[ "$(sha256sum "$PTAU" | cut -d' ' -f1)" = "$(pin phase1_ptau.prepared_sha256)" ] || die "ptau is not the pinned prepared file"
# 3. the hand-off pin
[ "$(sha256sum "$IN" | cut -d' ' -f1)" = "$EXP_IN" ] || die "input zkey sha256 does not match the expected hand-off sha256"
# contribute
if ! { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } | timeout "$LIMIT" $S zkey contribute "$IN" "$OUT" --name="$NAME" >/dev/null 2>&1; then
  rm -f "$OUT"; die "contribute exited nonzero or timed out after ${LIMIT}s (no output kept)"
fi
LOG="$OUT.verify.log"
if ! timeout "$LIMIT" $S zkey verify "$R1CS" "$PTAU" "$OUT" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$LOG" || ! grep -q 'ZKey Ok!' "$LOG"; then
  rm -f "$OUT"; die "zkey verify rejected the chain (output removed; log $LOG)"
fi
GOT_CHAIN=$(sed -n 's/^\[INFO\]  snarkJS: contribution #\([0-9]*\) \(.*\):$/\1 \2/p' "$LOG" | sort -n | cut -d' ' -f2- | paste -sd'|')
if [ "$GOT_CHAIN" != "$EXP_CHAIN" ]; then rm -f "$OUT"; die "chain contribution list is [$GOT_CHAIN], expected [$EXP_CHAIN] (output removed)"; fi
echo "chain: $GOT_CHAIN"
echo "OK: $NAME contributed. stage sha256 = $(sha256sum "$OUT" | cut -d' ' -f1)   (out=$OUT)"
