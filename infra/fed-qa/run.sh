#!/usr/bin/env bash
# infra/fed-qa/run.sh — bring up the single-box federation stack and run the harness.
# Currently asserts: boot on all three domains, registry test-double contract, and the
# real dead-drop multi-use semantics per instance. Identity seeding (S1) and mailbox
# migration (S4) land once the fleet answers the open questions in docs/FEDERATION_QA.md.
#
# Runs from the HOST: instances are reached on their published ports
# (app-a :3000, app-b :3001, app-c :3002, registry :8100). Compose healthchecks
# make `up --wait` block until each instance actually serves.
set -euo pipefail
cd "$(dirname "$0")"

DC="docker compose -f compose.fed-qa.yml"
$DC up -d --build --wait app-a app-b app-c registry

check() { # url label
  code=$(curl -s -o /dev/null -w '%{http_code}' "$1")
  [ "$code" = "200" ] && echo "ok   $2" || { echo "FAIL $2 ($code)"; exit 1; }
}

# S0 — every domain is a live, independent instance.
for h in localhost:3000 localhost:3001 localhost:3002; do
  check "http://$h/api/version" "$h /api/version"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8100/mailbox/nope)" = "404" ] \
  && echo "ok   registry probe 404" || { echo "FAIL registry probe"; exit 1; }

# Registry contract — register then fetch, in the REAL wire shape
# (mailbox-registry-client.ts): {mailbox_fp, x25519_pk, mlkem1024_pk,
# owner_identity_fp, epoch, owner_sig} → GET returns pubkeys + epoch only.
REG_BODY=$(node -e '
  const c = require("crypto");
  const x = c.randomBytes(32).toString("hex");
  const k = c.randomBytes(1568).toString("hex");
  const fp = c.createHash("sha256").update(x + k).digest("hex");
  console.log(JSON.stringify({
    mailbox_fp: fp, x25519_pk: x, mlkem1024_pk: k,
    owner_identity_fp: c.randomBytes(32).toString("hex"),
    epoch: 0, owner_sig: Buffer.from(c.randomBytes(64)).toString("base64"),
  }));')
REG_FP=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).mailbox_fp))')
REG_X=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).x25519_pk))')
curl -sf -X POST http://localhost:8100/mailbox/register \
  -H 'content-type: application/json' -d "$REG_BODY" > /dev/null
curl -sf "http://localhost:8100/mailbox/$REG_FP" | grep -q "\"$REG_X\"" \
  && echo "ok   registry round-trip" || { echo "FAIL registry"; exit 1; }
curl -s "http://localhost:8100/mailbox/$REG_FP" | grep -q owner_identity_fp \
  && { echo "FAIL registry leaks owner_identity_fp"; exit 1; } \
  || echo "ok   registry field discipline"
# Shape validation mirrors the real contract — a short-key body must 400.
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:8100/mailbox/register \
  -H 'content-type: application/json' \
  -d "{\"mailbox_fp\":\"$REG_FP\",\"x25519_pk\":\"qa-x\",\"mlkem1024_pk\":\"qa-k\",\"owner_identity_fp\":\"o\",\"epoch\":0,\"owner_sig\":\"s\"}")" = "400" ] \
  && echo "ok   registry shape validation" || { echo "FAIL registry shape validation"; exit 1; }

# S3 — dead-drop serves for the code's TTL: MULTI-USE (both GETs 200), not
# consume-on-view (app/api/relay/[code]/route.ts).
for h in localhost:3000 localhost:3001 localhost:3002; do
  code=$(curl -sf -X POST "http://$h/api/relay" -H 'content-type: application/json' \
    -d '{"encrypted":"qa-fake-blob"}' | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).code))')
  first=$(curl -s -o /dev/null -w '%{http_code}' "http://$h/api/relay/$code")
  second=$(curl -s -o /dev/null -w '%{http_code}' "http://$h/api/relay/$code")
  [ "$first" = "200" ] && [ "$second" = "200" ] \
    && echo "ok   $h dead-drop multi-use (TTL-bounded)" \
    || { echo "FAIL $h dead-drop ($first/$second)"; exit 1; }
done

echo "fed-qa smoke: all green (S0/S3 + registry contract)"
echo "S1/S4/S5/S7 pending — see docs/FEDERATION_QA.md open questions."
