#!/usr/bin/env bash
# infra/fed-qa/run.sh — bring up the single-box federation stack and run the harness.
#
# HOST-DRIVEN: `docker compose` runs here, so we assert against the PUBLISHED localhost
# ports — compose SERVICE names (app-a, registry) only resolve INSIDE the `fed` network,
# never from the host that runs compose. (Asserting service-name URLs from the host was a
# bug: it 000'd before any check ran.)
#
# Asserts: S0 boot on all three domains · registry test-double contract · S3 dead-drop
# REAL contract (MULTI-USE within TTL; single-ACCEPT is enforced DOWNSTREAM at the joiner
# accept-oracle, NOT by relay delete-on-read — see app/api/relay/[code]/route.ts) · S1
# headless-mint K identities. S4 (migration) / S5 / S7 land per docs/FEDERATION_QA.md.
set -euo pipefail
cd "$(dirname "$0")"

DC="docker compose -f compose.fed-qa.yml"
$DC up -d --build --wait app-a app-b app-c registry

# Published host ports (compose: app-a->3000, app-b->3001, app-c->3002, registry->8100).
A=localhost:3000; B=localhost:3001; C=localhost:3002; REG=localhost:8100

check() { # url label
  code=$(curl -s -o /dev/null -w '%{http_code}' "$1")
  [ "$code" = "200" ] && echo "ok   $2" || { echo "FAIL $2 ($code)"; exit 1; }
}

# S0 — every domain is a live, independent instance.
for hp in "$A svrnty.is" "$B relay-b.test" "$C relay-c.test"; do
  set -- $hp
  check "http://$1/api/version" "S0 $2 /api/version"
done

# Registry contract — register then fetch (round-trip preserves pubkeys; never owner_identity_fp).
curl -sf -X POST "http://$REG/mailbox/register" \
  -H 'content-type: application/json' \
  -d '{"mailbox_fp":"qa-fp-1","x25519_pub":"qa-x","mlkem_ek":"qa-k"}' > /dev/null
curl -sf "http://$REG/mailbox/qa-fp-1" | grep -q '"qa-x"' \
  && echo "ok   registry round-trip" || { echo "FAIL registry"; exit 1; }
curl -s "http://$REG/mailbox/qa-fp-1" | grep -q owner_identity_fp \
  && { echo "FAIL registry leaks owner_identity_fp"; exit 1; } \
  || echo "ok   registry field discipline"

# S3 — dead-drop REAL contract. The card is served for the code's TTL = MULTI-USE (one Grow
# link → N joiners, up to GROW_INVITE_CAP). Single-ACCEPT is enforced DOWNSTREAM at the
# joiner accept-oracle (isCodeOutstanding ∧ codeUnderCap ∧ !alreadyAccepted), NOT by relay
# delete-on-read — the old delete-on-read was itself a bug that broke multi-person Grow
# (app/api/relay/[code]/route.ts). So: create → GET twice both 200 → unknown code 404.
# Code extraction is node-free (host may have no node); grep the JSON field.
for hp in "$A" "$B" "$C"; do
  code=$(curl -sf -X POST "http://$hp/api/relay" -H 'content-type: application/json' \
    -d '{"encrypted":"qa-fake-blob"}' | grep -oE '"code":"[^"]+"' | head -1 | cut -d'"' -f4)
  first=$(curl -s -o /dev/null -w '%{http_code}' "http://$hp/api/relay/$code")
  second=$(curl -s -o /dev/null -w '%{http_code}' "http://$hp/api/relay/$code")
  miss=$(curl -s -o /dev/null -w '%{http_code}' "http://$hp/api/relay/ZZnotreal")
  [ "$first" = "200" ] && [ "$second" = "200" ] && [ "$miss" = "404" ] \
    && echo "ok   $hp dead-drop multi-use (200/200) + unknown=404" \
    || { echo "FAIL $hp dead-drop (first=$first second=$second miss=$miss)"; exit 1; }
done

# S1 — mint K headless identities; assert cards sign + Invariant-1 (full 64-hex, independent
# recompute, defeating canonicalClaimMatches' prefix-leniency) + subject_type=agent + distinct.
# Client-behaviour (needs NO satellite image) → runs pre-CONVERGE, like S0/S3; does NOT
# graduate a G-gate. Needs node + the repo's node_modules (present in dev/CI). Emits the K
# durable_ids as JSON → feeds the glyph-distribution QA.
if command -v node >/dev/null 2>&1 && [ -d ../../node_modules ]; then
  S1_K="${S1_K:-10}" npx tsx cells/s1_mint.mts \
    && echo "ok   S1 mint (${S1_K:-10} identities)" || { echo "FAIL S1 mint"; exit 1; }
else
  echo "skip S1 — needs node + repo node_modules; from repo root: S1_K=10 npx tsx infra/fed-qa/cells/s1_mint.mts"
fi

echo "fed-qa smoke: S0 + registry contract + S3 (real multi-use contract) green; S1 run-or-skipped above."
echo "S4 (migration) / S5 / S7 pending — see docs/FEDERATION_QA.md open questions."
