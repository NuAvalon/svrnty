#!/bin/bash
# pre-deploy-audit.sh — Catches architecture violations before deploy
# Run: bash scripts/pre-deploy-audit.sh
# Exit 0 = clean, Exit 1 = violations found

set -euo pipefail

ERRORS=0
SVRNTY_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== svrnty pre-deploy audit ==="
echo "Directory: $SVRNTY_DIR"
echo ""

# 1. API routes must NOT use server-side filesystem for user data
echo "--- Check 1: No server-side fs in API routes ---"
VIOLATIONS=$(grep -rn "from 'fs'\|from \"fs\"\|require('fs')\|from 'os'\|from \"os\"\|homedir()\|readFileSync\|writeFileSync\|fs/promises" \
    "$SVRNTY_DIR/app/api/" 2>/dev/null || true)

if [ -n "$VIOLATIONS" ]; then
    echo "❌ FAIL: API routes use server-side filesystem"
    echo "   Identity and contacts live in IndexedDB (client-side)."
    echo "   Server-side fs access will fail on Hetzner and leak data between users."
    echo ""
    echo "$VIOLATIONS" | while read -r line; do
        echo "   $line"
    done
    echo ""
    ERRORS=$((ERRORS + 1))
else
    echo "✅ PASS: No server-side fs in API routes"
fi

# 1b. API routes must NOT import server-side identity (transitive fs)
echo ""
echo "--- Check 1b: No SoverentityIdentity / identity/core in API routes ---"
ID_VIOLATIONS=$(grep -rn "import.*SoverentityIdentity\|from '@/lib/identity/core'\|from \"@/lib/identity/core\"\|from '@/lib/identity/core.ts'\|require(.*identity/core" \
    "$SVRNTY_DIR/app/api/" 2>/dev/null || true)

if [ -n "$ID_VIOLATIONS" ]; then
    echo "❌ FAIL: API routes import server-side identity manager"
    echo "   That class writes to ~/.soverentity — use IndexedDB BrowserIdentity only."
    echo ""
    echo "$ID_VIOLATIONS" | while read -r line; do
        echo "   $line"
    done
    echo ""
    ERRORS=$((ERRORS + 1))
else
    echo "✅ PASS: No server-side identity imports in API routes"
fi

# 2. No hardcoded secrets
echo ""
echo "--- Check 2: No hardcoded secrets ---"
SECRETS=$(grep -rn "re_[a-zA-Z0-9]\{20,\}\|sk-[a-zA-Z0-9]\{20,\}\|AKIA[A-Z0-9]\{16\}" \
    "$SVRNTY_DIR/src/" "$SVRNTY_DIR/app/" 2>/dev/null || true)

if [ -n "$SECRETS" ]; then
    echo "❌ FAIL: Possible hardcoded secrets found"
    echo "$SECRETS" | while read -r line; do
        echo "   $line"
    done
    ERRORS=$((ERRORS + 1))
else
    echo "✅ PASS: No hardcoded secrets"
fi

# 3. .env not committed
echo ""
echo "--- Check 3: .env not in git ---"
ENV_IN_GIT=$(cd "$SVRNTY_DIR" && git ls-files --cached .env .env.local .env.production 2>/dev/null || true)

if [ -n "$ENV_IN_GIT" ]; then
    echo "❌ FAIL: .env files tracked in git"
    echo "   $ENV_IN_GIT"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ PASS: .env files not in git"
fi

# 4. PQ crypto imports present (not accidentally removed)
echo ""
echo "--- Check 4: Post-quantum crypto intact ---"
PQ_PRESENT=$(grep -rn "ml-kem\|ml-dsa\|@noble/post-quantum\|ML-KEM\|ML-DSA" \
    "$SVRNTY_DIR/src/lib/crypto/" 2>/dev/null || true)

if [ -z "$PQ_PRESENT" ]; then
    echo "❌ FAIL: Post-quantum crypto references missing from src/lib/crypto/"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ PASS: Post-quantum crypto intact ($(echo "$PQ_PRESENT" | wc -l) references)"
fi

# 5. mutual-trust.ts exists (keystone)
echo ""
echo "--- Check 5: ZKP mutual trust module present ---"
if [ -f "$SVRNTY_DIR/src/lib/crypto/mutual-trust.ts" ]; then
    echo "✅ PASS: mutual-trust.ts present"
else
    echo "❌ FAIL: mutual-trust.ts missing — ZKP is load-bearing"
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
echo "================================"
if [ $ERRORS -eq 0 ]; then
    echo "✅ All checks passed. Safe to deploy."
    exit 0
else
    echo "❌ $ERRORS violation(s) found. DO NOT DEPLOY."
    exit 1
fi
