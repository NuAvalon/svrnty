# infra/fed-qa/x_sig.sh — SHARED tag#3 request-auth signer (sourced by the G3-G6 + S7 cells).
# One impl, no two-impl drift (shared by the recovery + adversarial cells).
#
# Emits the svrnty-psi-auth tag#3 signature the keystone's verify_request_signature expects
# (satellite.py:709/:691/:740/:744), used by /send · /retrieve · /msg/status · /ack:
#   preimage = `svrnty-psi-auth:{fp}:{unix_seconds}`   (UTF-8, whole seconds)
#   sig      = Ed25519(sig_seed, preimage)             (RFC8032 PureEdDSA — deterministic)
#   wire     = `{unix_seconds}:{base64(sig)}`          (base64 has no ':', split is unambiguous)
#   window   = ±30s
# Auth key = the identity's BOUND sig_pubkey. The seeder SELF-BINDs, so *_SIGNKEY (= base64 of the
# raw 32B ed25519 seed, emitted by seed_keystone.mts) is BOTH the identity key and the tag#3 key.
#
# openssl path chosen because RFC8032 ed25519 is deterministic: given the same 32B seed + message,
# openssl's signature is BYTE-IDENTICAL to @noble/curves (the seeder's signer) and python-cryptography.
# VERIFIED pre-commit against a known-answer vector (embedded in xsig_selftest below) — so a cell that
# passes xsig_selftest is emitting signatures the keystone will accept, with zero cross-impl hazard.
#
# This file is SOURCED (`. x_sig.sh`) — it defines functions only, sets no shell options, leaves no
# globals. Requires: openssl 3.0+ (ed25519 `-rawin`), base64, mktemp. Call xsig_selftest first and
# SKIP honestly (never fake) if it returns non-zero — a runner without ed25519 openssl can't sign.

# _pem_from_seed <seed_b64> -> stdout: path to a temp PKCS8 PEM (caller rm's it). Empty on failure.
# PKCS8 DER = 16B Ed25519 private-key prefix + the raw 32B seed (null byte in the prefix survives the
# redirect-to-file; it must NOT be captured in a shell var).
xsig__pem_from_seed() {
  local seed_b64="$1" der pem
  der=$(mktemp) || return 1
  pem=$(mktemp) || { rm -f "$der"; return 1; }
  { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
    printf '%s' "$seed_b64" | base64 -d; } > "$der" 2>/dev/null
  if openssl pkey -inform DER -in "$der" -out "$pem" 2>/dev/null; then
    rm -f "$der"; printf '%s' "$pem"
  else
    rm -f "$der" "$pem"; return 1
  fi
}

# xsig__sign_at <pem> <fp> <unix> -> stdout: base64(sig) over svrnty-psi-auth:fp:unix. Empty on fail.
xsig__sign_at() {
  local pem="$1" fp="$2" unix="$3" pre sig
  pre=$(mktemp) || return 1
  printf 'svrnty-psi-auth:%s:%s' "$fp" "$unix" > "$pre"
  sig=$(openssl pkeyutl -sign -inkey "$pem" -rawin -in "$pre" 2>/dev/null | base64 | tr -d '\n')
  rm -f "$pre"
  [ -n "$sig" ] && printf '%s' "$sig"
}

# xsig_wire_from_seed <seed_b64> <fp> -> stdout: tag#3 wire "{unix}:{b64sig}" (current time). Empty on fail.
xsig_wire_from_seed() {
  local seed_b64="$1" fp="$2" pem unix sig
  pem=$(xsig__pem_from_seed "$seed_b64") || return 1
  [ -n "$pem" ] || return 1
  unix=$(date +%s)
  sig=$(xsig__sign_at "$pem" "$fp" "$unix")
  rm -f "$pem"
  [ -n "$sig" ] && printf '%s:%s' "$unix" "$sig"
}

# xsig_wire_throwaway <fp> -> stdout: a WELL-FORMED tag#3 wire signed by a FRESH, unbound ed25519 key
# (not any registered identity). For wrong-key / spoof tests: the shape is valid, the key is wrong, so
# the keystone's _verify_with_key against the real bound sig_pubkey MUST fail (403). Empty on fail.
xsig_wire_throwaway() {
  local fp="$1" pem unix sig
  pem=$(mktemp) || return 1
  openssl genpkey -algorithm ed25519 -out "$pem" 2>/dev/null || { rm -f "$pem"; return 1; }
  unix=$(date +%s)
  sig=$(xsig__sign_at "$pem" "$fp" "$unix")
  rm -f "$pem"
  [ -n "$sig" ] && printf '%s:%s' "$unix" "$sig"
}

# xsig_selftest -> 0 iff this runner's openssl reproduces the known-answer ed25519 vector (same bytes
# as @noble / python-cryptography). Prints PASS/FAIL to stderr. Cells gate on this before signing.
xsig_selftest() {
  local pem got
  local seed='iKqr3d0+q1Pz8X0kq2m5Yf3nQ6sVbW1cDe4fGhIjKlM='
  local fp='deadbeefcafe0001' unix='1760007000'
  local want='sVZ/BnCPqDbf23Tl35JO2ZnKFqWOu6PLOi4BPrWwsTzH9ykyw2+tMVmBiRZgIzYIF9RjSZouvCvs98pdz6C2CQ=='
  pem=$(xsig__pem_from_seed "$seed") || { echo "xsig_selftest: FAIL (openssl cannot import ed25519 raw seed — need openssl 3.0+)" >&2; return 1; }
  got=$(xsig__sign_at "$pem" "$fp" "$unix")
  rm -f "$pem"
  if [ "$got" = "$want" ]; then
    echo "xsig_selftest: PASS (openssl ed25519 == @noble/python known-answer — safe to sign)" >&2
    return 0
  fi
  echo "xsig_selftest: FAIL (sig mismatch; got='${got:-<empty>}') — DO NOT sign; SKIP honestly" >&2
  return 1
}
