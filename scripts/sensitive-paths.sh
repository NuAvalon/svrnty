#!/usr/bin/env bash
# S42 sensitive-paths patterns (Flint lane:svrnty #217): built from CODEOWNERS at run time, plus the extras
# below, so the code-owner fence and the PR-body check can never drift apart. Used by .github/workflows/qa.yml
# and pinned by scripts/sensitive-paths.test.ts.
# bash [[ == ]] globs: `*` also matches `/`, so `dir/*` covers nested files (over-match = the safe side).
#   scripts/sensitive-paths.sh patterns [CODEOWNERS]       one pattern per line; exit 1 if CODEOWNERS yields no path
#   scripts/sensitive-paths.sh match <path> [CODEOWNERS]   exit 0 iff <path> is sensitive
#   scripts/sensitive-paths.sh extras                      the extras (in neither file; Flint #217)
set -euo pipefail

EXTRAS=('src/lib/headless/*' 'app/api/*' 'middleware.ts' 'package.json' 'package-lock.json')

build_patterns() {
  local file="$1" path _owners p n=0
  [[ -r "$file" ]] || { echo "::error::cannot read $file" >&2; return 1; }
  PATTERNS=()
  while read -r path _owners || [[ -n "${path:-}" ]]; do
    [[ -z "${path:-}" || "$path" == \#* ]] && continue
    p="${path#/}"                    # strip the leading /
    [[ "$p" == */ ]] && p="${p}*"    # dir/ → dir/*
    PATTERNS+=("$p")
    n=$((n + 1))
  done < "$file"
  (( n > 0 )) || { echo "::error::$file parsed to no paths: refusing to skip the sensitive-paths check" >&2; return 1; }
  PATTERNS+=("${EXTRAS[@]}")
}

is_sensitive() {
  local f="$1" p
  for p in "${PATTERNS[@]}"; do
    # shellcheck disable=SC2053  # the right side is a glob on purpose
    [[ "$f" == $p ]] && return 0
  done
  return 1
}

case "${1:-}" in
  patterns) build_patterns "${2:-CODEOWNERS}"; printf '%s\n' "${PATTERNS[@]}" ;;
  match)    [[ -n "${2:-}" ]] || { echo "usage: $0 match <path> [CODEOWNERS]" >&2; exit 2; }
            build_patterns "${3:-CODEOWNERS}"; is_sensitive "$2" ;;
  extras)   printf '%s\n' "${EXTRAS[@]}" ;;
  *)        echo "usage: $0 patterns [CODEOWNERS] | match <path> [CODEOWNERS] | extras" >&2; exit 2 ;;
esac
