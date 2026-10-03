#!/usr/bin/env bash
# infra/fed-qa/run.sh — bring up the single-box federation stack and run the harness.
# Currently asserts: boot on all three domains, registry test-double contract, and the
# real dead-drop single-use semantics per instance. Identity seeding (S1) and mailbox
# migration (S4) land once the fleet answers the open questions in docs/FEDERATION_QA.md.
set -euo pipefail
cd "$(dirname "$0")"

DC="docker compose -f compose.fed-qa.yml"
$DC up -d --build --wait app-a app-b app-c registry

check() { # url label
  code=$(curl -s -o /dev/null -w '%{http_code}' "$1")
  [ "$code" = "200" ] && echo "ok   $2" || { echo "FAIL $2 ($code)"; exit 1; }
}

# S0 — every domain is a live, independent instance.
for h in app-a:3000 app-b:3000 app-c:3000; do
  check "http://$h/api/version" "$h /api/version"
done
check "http://registry:8100/mailbox/nope" > /dev/null || true # probe returns 404 by design

# Registry contract — register then fetch (round-trip preserves pubkeys, epoch 0).
curl -sf -X POST http://registry:8100/mailbox/register \
  -H 'content-type: application/json' \
  -d '{"mailbox_fp":"qa-fp-1","x25519_pub":"qa-x","mlkem_ek":"qa-k"}' > /dev/null
curl -sf http://registry:8100/mailbox/qa-fp-1 | grep -q '"qa-x"' \
  && echo "ok   registry round-trip" || { echo "FAIL registry"; exit 1; }
curl -s http://registry:8100/mailbox/qa-fp-1 | grep -q owner_identity_fp \
  && { echo "FAIL registry leaks owner_identity_fp"; exit 1; } \
  || echo "ok   registry field discipline"

# S3 — dead-drop single-use semantics per domain (create → resolve → 404).
for h in app-a:3000 app-b:3000 app-c:3000; do
  code=$(curl -sf -X POST "http://$h/api/relay" -H 'content-type: application/json' \
    -d '{"encrypted":"qa-fake-blob"}' | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).code))')
  first=$(curl -s -o /dev/null -w '%{http_code}' "http://$h/api/relay/$code")
  second=$(curl -s -o /dev/null -w '%{http_code}' "http://$h/api/relay/$code")
  [ "$first" = "200" ] && [ "$second" = "404" ] \
    && echo "ok   $h dead-drop single-use" \
    || { echo "FAIL $h dead-drop ($first/$second)"; exit 1; }
done

echo "fed-qa smoke: all green (S0/S3 + registry contract)"
echo "S1/S4/S5/S7 pending — see docs/FEDERATION_QA.md open questions."
