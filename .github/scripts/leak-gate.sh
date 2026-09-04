#!/usr/bin/env bash
# leak-gate.sh — secret / PII scanner for pull-request diffs.
#
# Fails ONLY on real credentials, secrets, or personal data introduced in ADDED lines.
# It does not flag pre-existing content or internal naming already present in history —
# a PR is judged on what it introduces, so the gate never re-blocks a merge for material
# that is already public. Test, fixture, and example lines are ignored (they carry test
# values, not live secrets).
#
# Usage:  leak-gate.sh [BASE_REF]     (BASE_REF defaults to origin/main)
# Exit:   0 = clean   1 = secret/PII found   2 = could not compute diff
set -uo pipefail

BASE_REF="${1:-origin/main}"

# --- What counts as a hard block (case-insensitive). ---
# secrets:  api keys, generic secret/token/password/passphrase, PEM private keys,
#           provider token prefixes, and project env-secret prefixes
# PII:      consumer email domains, US phone numbers, maintainer name, IPv4 addresses
# NB: POSIX ERE (grep -E) — no PCRE (?:…); IPv4 uses a plain capturing group.
BLOCK_RE='(api[_-]?key|secret|token|password|passphrase|BEGIN [A-Z ]*PRIVATE KEY|gho_|sk-|ZK_|L2_|APEX_|@(gmail|yahoo|hotmail|icloud)|[0-9]{3}[-.][0-9]{3}[-.][0-9]{4}|palberts|peter alberts|([0-9]{1,3}\.){3}[0-9]{1,3})'

# --- Ignore test/fixture/example material (test values, not live secrets). ---
# Matched against the whole "path:line<TAB>content" string, so it skips both test FILES
# (by path, e.g. foo.test.ts / e2e/…) and inline placeholder/example markers (by content).
# Word-boundaried so it excludes the word "test" but NOT substrings like "latest" — a
# bare-substring match there would be a false-negative (a secret in latest_keys.md would
# be skipped). '2e2' / 'e2e' etc. are bounded by digits or path separators, which count.
EXCLUDE_RE='(^|[^a-zA-Z])(test|e2e|spec|placeholder|example|fixture|sample|mock)([^a-zA-Z]|$)'

# Never flag the gate's own file (it necessarily contains the pattern strings).
SELF='leak-gate'

# --- Added lines of the PR diff (merge-base, three-dot), tagged path:line. ---
if ! git rev-parse --verify "$BASE_REF" >/dev/null 2>&1; then
  echo "leak-gate: cannot resolve base ref '$BASE_REF' (checkout with fetch-depth: 0)" >&2
  exit 2
fi

added="$(git diff --no-color -U0 "${BASE_REF}...HEAD" | awk '
  /^\+\+\+ b\// { file = substr($0, 7); next }        # current file (skip +++ header)
  /^@@ /        { match($0, /\+[0-9]+/); ln = substr($0, RSTART+1, RLENGTH-1) - 1; next }
  /^\+/         { ln++; print file ":" ln "\t" substr($0, 2) }   # an added line
')"

hits="$(printf '%s\n' "$added" \
  | grep -iE "$BLOCK_RE" \
  | grep -ivE "$EXCLUDE_RE" \
  | grep -v "$SELF" || true)"

if [ -n "$hits" ]; then
  echo "❌ leak-gate: secret/PII in added lines (scrub before merge):"
  echo "$hits"
  echo
  echo "False positive (a test value / already-public)? Add a test/fixture marker to the"
  echo "line or move it into a test file. Pre-existing and internal-naming refs are not flagged."
  exit 1
fi

echo "✅ leak-gate: no secrets/PII in added lines."
exit 0
