#!/bin/bash
# #588 phase-2 contribution wrapper (DRAFT, apollo). One contributor step, fail loud.
# Usage: ceremony/contribute.sh <in.zkey> <out.zkey> <contributor-name>
# - Entropy: 64 bytes from the OS CSPRNG, hex, ONE line on stdin ending in a newline (snarkjs reads it with readline; without the
#   newline it hangs forever, which is why there is a timeout). Entropy is never on a command line, never logged, never written to disk.
# - snarkjs also mixes 64 more OS CSPRNG bytes of its own (Flint), so a typed/leaked entropy string alone is not fatal.
# - A timeout or any nonzero exit prints FAILED and exits nonzero; the output zkey is removed if it did not verify.
# - After the contribution it re-verifies the WHOLE chain against the r1cs and the phase-1 ptau and prints the chain's contribution hashes.
set -euo pipefail
cd "$(dirname "$0")/.."
IN=${1:?in.zkey}; OUT=${2:?out.zkey}; NAME=${3:?contributor name}
R1CS=${R1CS:-build/slotbind.r1cs}; PTAU=${PTAU:-build/ptau_prepared.ptau}; LIMIT=${LIMIT:-300}
S=node_modules/.bin/snarkjs
[ -s "$IN" ] || { echo "FAILED: input zkey $IN missing"; exit 1; }
[ ! -e "$OUT" ] || { echo "FAILED: refusing to overwrite $OUT"; exit 1; }
if ! { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; } | timeout "$LIMIT" $S zkey contribute "$IN" "$OUT" --name="$NAME" >/dev/null 2>&1; then
  rm -f "$OUT"; echo "FAILED: contribute exited nonzero or timed out after ${LIMIT}s (no output kept)"; exit 1
fi
if ! timeout "$LIMIT" $S zkey verify "$R1CS" "$PTAU" "$OUT" > "$OUT.verify.log" 2>&1; then
  rm -f "$OUT"; echo "FAILED: zkey verify rejected the chain (output removed; log $OUT.verify.log)"; exit 1
fi
sed 's/\x1b\[[0-9;]*m//g' "$OUT.verify.log" | grep -E 'ZKey Ok|Contribution|Response Hash' -A4 | grep -E 'ZKey Ok|#|[0-9a-f]{8} [0-9a-f]{8}' | head -40
echo "OK: $NAME contributed; out=$OUT sha256=$(sha256sum "$OUT" | cut -c1-64)"
