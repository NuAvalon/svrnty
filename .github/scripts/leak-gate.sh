#!/usr/bin/env bash
# leak-gate.sh (v3) — secret / PII scanner for pull-request diffs.
#
# Fails ONLY on real credentials/secrets/PII introduced in ADDED lines — matched as a
# secret VALUE being assigned (not a bare keyword/identifier/path), so it does not self-DoS
# on a crypto/identity app's normal vocabulary. Test material rides by FILE PATH; a single
# line rides with an explicit `leak-gate-ignore` pragma. Ridden lines are REPORTED (a logged
# escape-hatch stays reviewable — no silent bypass).
#
# v3 (post-review, Flint + Hypatia): dropped the maintainer-HANDLE block (`palberts` is the
# already-public GitHub handle → RIDE-class, FP'd on CODEOWNERS/commit-refs; @gmail stays as
# the PII block); added DB connection strings, JWTs (3-segment), Stripe secret keys; made
# pragma/path rides visible in the report.
#
# Usage:  leak-gate.sh [BASE_REF]     (BASE_REF defaults to origin/main)
#         leak-gate.sh --stdin        (read pre-extracted "path:line<TAB>content" from stdin)
# Exit:   0 = clean   1 = secret/PII found   2 = could not compute diff
set -uo pipefail

# ── pattern kit ──────────────────────────────────────────────────────────────
Q="['\"]"                                   # one single- or double-quote
VALUE="[^'\"[:space:]]{6,}"                 # a non-trivial quoted literal (≥6 non-space, non-quote)

# (a) hardcoded secret ASSIGNED a quoted literal: keyword … = "value" | key: 'value' | "api_key":"value"
GEN="(api[_-]?key|secret|token|passphrase|passwd|password|credential|private[_-]?key|client[_-]?secret)[a-z0-9_]*${Q}?[[:space:]]*[:=]+[[:space:]]*${Q}${VALUE}${Q}"
# (b) high-entropy provider tokens — anchored to a token boundary so "task-"/"risk-" don't hit.
#     incl. Stripe SECRET/restricted keys (sk_live_/rk_live_) — NOT pk_live_ (publishable = public by design).
PROV="(^|[^a-z0-9])(gho_[a-z0-9]{16,}|github_pat_[a-z0-9_]{20,}|sk-[a-z0-9_-]{20,}|xox[baprs]-[a-z0-9-]{10,}|akia[0-9a-z]{16}|aiza[a-z0-9_-]{30,}|(sk|rk)_live_[a-z0-9]{16,})"
# (c) JWT — 3 segments, header+payload both base64url-encode JSON => both start eyJ (bare eyJ FPs on any base64 of '{\"').
JWT="eyj[a-z0-9_-]{10,}\.eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}"
# (d) DB connection string with EMBEDDED creds (user:pass@host); a credential-free URL doesn't match.
DBCONN="(postgres|postgresql|mysql|mongodb\+srv|mongodb|redis|amqp)://[^@[:space:]/]+:[^@[:space:]/]+@"
# (e) PEM private key header
PEM="-----begin [a-z0-9 ]*private key"
# (f) project env-secret being ASSIGNED (distinguishes APEX_X=val from a legit process.env.APEX_X read)
ENVK="(^|[^a-z0-9])(apex_|zk_|l2_)[a-z0-9_]*[[:space:]]*=[[:space:]]*${Q}?[a-z0-9]"
# (g) PII — consumer email domains (the actual maintainer-PII block; handle is public → not blocked)
EMAIL="@(gmail|yahoo|hotmail|outlook|icloud|protonmail)\.[a-z]"
PHONE="[0-9]{3}[-.][0-9]{3}[-.][0-9]{4}"

BLOCK_RE="(${GEN}|${PROV}|${JWT}|${DBCONN}|${PEM}|${ENVK}|${EMAIL}|${PHONE})"

# ── ride list (by construction, no live secrets) — REPORTED, never silent ─────
PATH_RIDE="(\.(test|spec|stories)\.[a-z]+:|(^|[:/ ])(e2e|__tests__|__mocks__|fixtures?|mocks?|tests?)/)"
PRAGMA_RIDE="(leak-gate-ignore|allowlist[ -]secret)"
# never flag the gate's own FILE (it necessarily contains the pattern strings). Scope to the
# file PATH — NOT a bare "leak-gate" substring, which would also swallow the leak-gate-ignore
# pragma and hide it from the ride report.
SELF="leak-gate[a-z0-9._-]*\.sh:"

# ── input: extracted added lines from git, OR raw from stdin (--stdin) ────────
if [ "${1:-}" = "--stdin" ]; then
  added="$(cat)"
else
  BASE_REF="${1:-origin/main}"
  if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
    echo "leak-gate: cannot resolve base ref '$BASE_REF' (checkout with fetch-depth: 0)" >&2
    exit 2
  fi
  added="$(git diff --no-color -U0 "${BASE_REF}...HEAD" | awk '
    /^\+\+\+ b\// { file = substr($0, 7); next }
    /^@@ /        { match($0, /\+[0-9]+/); ln = substr($0, RSTART+1, RLENGTH-1) - 1; next }
    /^\+/         { ln++; print file ":" ln "\t" substr($0, 2) }
  ')"
fi

# ── scan: split blocked lines into real hits vs (reported) rides ──────────────
blocked="$(printf '%s\n' "$added" | grep -iE "$BLOCK_RE" | grep -ivE "$SELF" || true)"
hits=""; rides=""
if [ -n "$blocked" ]; then
  rides="$(printf '%s\n' "$blocked" | grep -iE "${PATH_RIDE}|${PRAGMA_RIDE}" || true)"
  hits="$( printf '%s\n' "$blocked" | grep -ivE "$PATH_RIDE" | grep -ivE "$PRAGMA_RIDE" || true)"
fi
ride_n="$(printf '%s\n' "$rides" | grep -c . || true)"

report_rides() {
  [ "$ride_n" -gt 0 ] || return 0
  echo
  echo "ℹ️  ${ride_n} line(s) matched a secret pattern but RODE (test-path or leak-gate-ignore) — review these:"
  printf '%s\n' "$rides" | sed 's/^/    /'
}

if [ -n "$hits" ]; then
  echo "❌ leak-gate: secret/PII in added lines (scrub before merge):"
  printf '%s\n' "$hits" | sed 's/^/    /'
  report_rides
  echo
  echo "False positive? If a test value, put it in a test file; if a deliberate already-public"
  echo "placeholder, add a 'leak-gate-ignore' pragma comment on that line (it will be reported)."
  exit 1
fi

echo "✅ leak-gate: no secrets/PII in added lines."
report_rides
exit 0
