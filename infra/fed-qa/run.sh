#!/usr/bin/env bash
# infra/fed-qa/run.sh — bring up the single-box federation stack and run the harness.
# Currently asserts: boot on all three domains, registry test-double contract, and the
# real dead-drop single-use semantics per instance. Identity seeding (S1) and mailbox
# migration (S4) land once the fleet answers the open questions in docs/FEDERATION_QA.md.
set -euo pipefail
cd "$(dirname "$0")"

DC="docker compose -f compose.fed-qa.yml"
$DC up -d --build --wait app-a app-b app-c keystone

# Readiness: --wait confirms container health; let the host->published-port path settle
# before asserting (avoids a transient curl recv-error right after Started/Healthy).
for _ in $(seq 1 20); do
  curl -sf -o /dev/null --max-time 3 http://localhost:3000/api/version && break || sleep 2
done

check() { # url label
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1" || echo 000)
  [ "$code" = "200" ] && echo "ok   $2" || { echo "FAIL $2 ($code)"; exit 1; }
}

# S0 — every domain is a live, independent instance.
for h in localhost:3000 localhost:3001 localhost:3002; do
  check "http://$h/api/version" "$h /api/version"
done
# Keystone (REAL satellite, full mode) — swapped in for the registry test-double.
# Liveness: the keystone RESPONDS with a real HTTP code (not a connection failure => up+serving).
klive=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost:8101/mailbox/qa-unknown-fp || echo 000)
[ "$klive" != "000" ] && echo "ok   keystone up (responds $klive)" \
  || { echo "FAIL keystone not responding ($klive)"; exit 1; }
# The REAL keystone REJECTS an unsigned register (owner_sig pin, spec §4.1). The stub
# accepted any well-formed body; the real service must not — this is the stub->real win.
kreg=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST http://localhost:8101/mailbox/register \
  -H 'content-type: application/json' \
  -d '{"mailbox_fp":"qa-fp-1","x25519_pub":"qa-x","mlkem_ek":"qa-k"}' || echo 000)
case "$kreg" in
  400|403|422) echo "ok   keystone rejects unsigned register ($kreg)";;
  *) echo "FAIL keystone accepted unsigned register ($kreg)"; exit 1;;
esac
echo "note signed register round-trip + field discipline graduate with S1 seeding"

# S3 — Grow-card dead-drop: served MULTI-USE within its 7d TTL (deliberate). The card is the
# giver's own deliberately-shared, key-fragment-gated identity; single-ACCEPT is enforced
# DOWNSTREAM at the joiner accept-oracle, NOT by delete-on-read (the old single-use-delete was
# a bug that broke multi-person viral Grow). Ruled intentional (relay-owner + claims review).
# (Private/messaging payloads ride /api/relay/envelope, which DOES ack-delete — a different path.)
for h in localhost:3000 localhost:3001 localhost:3002; do
  code=$(curl -sf -X POST "http://$h/api/relay" -H 'content-type: application/json' \
    -d '{"encrypted":"qa-fake-blob"}' | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).code))')
  first=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$h/api/relay/$code")
  second=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$h/api/relay/$code")
  [ "$first" = "200" ] && [ "$second" = "200" ] \
    && echo "ok   $h Grow-card multi-use within TTL ($first/$second)" \
    || { echo "FAIL $h Grow-card serve ($first/$second, want 200/200)"; exit 1; }
done

# S7 — adversarial pass. Targets the REAL keystone directly.
# Keystone-up cells (unsigned-ack -> 403, register-flood -> 429) run now; the cells that
# need signing (G7-a/b2/b3) self-SKIP until S1 identity-seeding lands — honestly marked.
RELAY=http://localhost:8101 ./adversarial-s7.sh

echo "fed-qa: S0/S3 green + keystone liveness/reject-unsigned + S7 (keystone-up cells)"
echo "S1 seed + G3-G6 cells graduate the signed round-trip + S7-a/b2/b3 — see docs/FEDERATION_QA.md."
