#!/usr/bin/env bash
# infra/fed-qa/run.sh — bring up the single-box federation stack and run the harness.
# Currently asserts: boot on all three domains, registry test-double contract (real
# fp-binding + owner_sig verification), and the real dead-drop multi-use semantics
# per instance. `run.sh s8` additionally runs the mailbox-expiry/rebuild scenario
# (G3) against a short-TTL registry. Identity seeding (S1) and mailbox migration
# (S4) land once the fleet answers the open questions in docs/FEDERATION_QA.md.
#
# Runs from the HOST: instances are reached on their published ports
# (app-a :3000, app-b :3001, app-c :3002, registry :8100, registry-ttl :8101).
# Compose healthchecks make `up --wait` block until each instance actually serves.
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-smoke}"
DC="docker compose -f compose.fed-qa.yml"
if [ "$MODE" = "s8" ]; then
  $DC --profile s8 up -d --build --wait app-a app-b app-c registry registry-ttl
else
  $DC up -d --build --wait app-a app-b app-c registry
fi

check() { # url label
  code=$(curl -s -o /dev/null -w '%{http_code}' "$1")
  [ "$code" = "200" ] && echo "ok   $2" || { echo "FAIL $2 ($code)"; exit 1; }
}
expect() { # expected_code url label [curl args...]
  exp="$1"; url="$2"; label="$3"; shift 3
  code=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url")
  [ "$code" = "$exp" ] && echo "ok   $label" || { echo "FAIL $label (want $exp got $code)"; exit 1; }
}

# mint_reg <epoch> — emits one line per field for eval:
#   OWNER_FP, OWNER_PK, REG_BODY (real shape, real Ed25519 owner_sig, fp≡SHA256(raw pubkeys))
mint_reg() {
  local epoch="$1"
  node -e '
    const c = require("crypto");
    const x = c.randomBytes(32), k = c.randomBytes(1568);
    const fp = c.createHash("sha256").update(Buffer.concat([x, k])).digest("hex");
    const { publicKey, privateKey } = c.generateKeyPairSync("ed25519");
    const ownerFp = c.randomBytes(32).toString("hex");
    const ownerPk = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    const epoch = Number(process.argv[1]);
    const sig = c.sign(null, Buffer.from(`svrnty-mailbox-reg-v1:${ownerFp}:${fp}:${epoch}`), privateKey);
    const body = {
      mailbox_fp: fp, x25519_pk: x.toString("hex"), mlkem1024_pk: k.toString("hex"),
      owner_identity_fp: ownerFp, epoch, owner_sig: sig.toString("base64"),
    };
    console.log(`OWNER_FP=${ownerFp}`);
    console.log(`OWNER_PK=${ownerPk}`);
    console.log(`REG_BODY=${JSON.stringify(body)}`);
  ' "$epoch"
}
seed_owner() { # registry_port owner_fp owner_pk — stub-only test channel (not wire shape)
  curl -sf -X PUT "http://localhost:$1/_test/identity/$2" \
    -H 'content-type: application/json' -d "{\"ed25519_pk\":\"$3\"}" > /dev/null
}

# S0 — every domain is a live, independent instance.
for h in localhost:3000 localhost:3001 localhost:3002; do
  check "http://$h/api/version" "$h /api/version"
done
expect 404 "http://localhost:8100/mailbox/nope" "registry probe 404"

# Registry contract — register then fetch, in the REAL wire shape
# (mailbox-registry-client.ts): {mailbox_fp, x25519_pk, mlkem1024_pk,
# owner_identity_fp, epoch, owner_sig} → GET returns pubkeys + epoch only.
eval "$(mint_reg 0)"
seed_owner 8100 "$OWNER_FP" "$OWNER_PK"
REG_FP=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).mailbox_fp))')
REG_X=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).x25519_pk))')
expect 201 "http://localhost:8100/mailbox/register" "registry register" \
  -X POST -H 'content-type: application/json' -d "$REG_BODY"
curl -sf "http://localhost:8100/mailbox/$REG_FP" | grep -q "\"$REG_X\"" \
  && echo "ok   registry round-trip" || { echo "FAIL registry"; exit 1; }
curl -s "http://localhost:8100/mailbox/$REG_FP" | grep -q owner_identity_fp \
  && { echo "FAIL registry leaks owner_identity_fp"; exit 1; } \
  || echo "ok   registry field discipline"

# Negatives — the stub now enforces the real contract:
# short keys → 400; fp≢SHA256(pubkeys) → 400; bad sig → 403; unseeded owner → 403.
expect 400 "http://localhost:8100/mailbox/register" "registry shape validation" \
  -X POST -H 'content-type: application/json' \
  -d "{\"mailbox_fp\":\"$REG_FP\",\"x25519_pk\":\"qa-x\",\"mlkem1024_pk\":\"qa-k\",\"owner_identity_fp\":\"o\",\"epoch\":0,\"owner_sig\":\"s\"}"
BAD_FP_BODY=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>{const b=JSON.parse(d);b.mailbox_fp="0".repeat(64);console.log(JSON.stringify(b))})')
expect 400 "http://localhost:8100/mailbox/register" "registry fp-binding reject" \
  -X POST -H 'content-type: application/json' -d "$BAD_FP_BODY"
BAD_SIG_BODY=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>{const b=JSON.parse(d);b.owner_sig=Buffer.alloc(64).toString("base64");console.log(JSON.stringify(b))})')
expect 403 "http://localhost:8100/mailbox/register" "registry bad-sig reject" \
  -X POST -H 'content-type: application/json' -d "$BAD_SIG_BODY"
eval "$(mint_reg 0)"   # fresh owner, never seeded
expect 403 "http://localhost:8100/mailbox/register" "registry unseeded-owner reject" \
  -X POST -H 'content-type: application/json' -d "$REG_BODY"

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

if [ "$MODE" = "s8" ]; then
  # S8 (G3) — mailbox expiry → rebuild → works again. registry-ttl runs the same
  # stub with MAILBOX_TTL_MS=3000 standing in for the satellite's 30-day GC.
  eval "$(mint_reg 0)"
  seed_owner 8101 "$OWNER_FP" "$OWNER_PK"
  FP=$(echo "$REG_BODY" | node -e 'process.stdin.on("data",d=>console.log(JSON.parse(d).mailbox_fp))')
  expect 201 "http://localhost:8101/mailbox/register" "s8 register" \
    -X POST -H 'content-type: application/json' -d "$REG_BODY"
  expect 200 "http://localhost:8101/mailbox/$FP" "s8 mailbox live"
  sleep 4
  expect 404 "http://localhost:8101/mailbox/$FP" "s8 GC expired mailbox"
  # Rebuild: re-register the same fp — GC'd state is gone, epoch floor resets.
  expect 201 "http://localhost:8101/mailbox/register" "s8 rebuild register" \
    -X POST -H 'content-type: application/json' -d "$REG_BODY"
  expect 200 "http://localhost:8101/mailbox/$FP" "s8 rebuilt mailbox serves pubkeys"
  echo "fed-qa s8: expiry→rebuild green (wire level; pointer-republish + beacon rehydration ride S4)"
  exit 0
fi

echo "fed-qa smoke: all green (S0/S3 + registry contract incl. fp-binding + owner_sig)"
echo "S1/S4/S5/S7 pending — see docs/FEDERATION_QA.md open questions. S8: run.sh s8"
