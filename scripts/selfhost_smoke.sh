#!/usr/bin/env bash
# selfhost_smoke.sh — prove the self-host compose actually works, from a clean start.
#
# Run from the repo root on a machine with Docker + the Compose plugin:
#   scripts/selfhost_smoke.sh            # build, test, then remove everything it created
#   scripts/selfhost_smoke.sh --keep     # leave the smoke stack running for inspection
#
# It never touches your real setup: its own compose project (svrnty-smoke), its own throwaway
# env file (not your .env), and it starts only `app` + `registration` (no Caddy, so it needs
# no ports and no domain). Everything it creates is removed at the end unless --keep.
#
# Checks:
#   1. compose refuses to start without SATELLITE_ADMIN_KEY (fails loud, not a restart loop)
#   2. the satellite starts healthy and trusts the app as its proxy (the name resolves)
#   3. the app serves /api/version
#   4. the app reaches the satellite (/api/satellite/trust/psi/satellite-key = 200, not 502)
#   5. a relay deposit lands in the mailbox database on the relay_data volume
#   6. the deposit survives `restart app` AND a recreate (the `up --build` update path)
#   7. the documented housekeeping command runs; a wrong admin key is refused
set -euo pipefail

PROJECT="svrnty-smoke"
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1
[[ -f docker-compose.yml && -d infra/svrnty ]] || { echo "run from the svrnty repo root" >&2; exit 2; }

WORK="$(mktemp -d)"
ENVF="$WORK/smoke.env"
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*" >&2; exit 1; }
dc()   { docker compose -p "$PROJECT" --env-file "$ENVF" "$@"; }
cleanup() {
  if [[ $KEEP -eq 0 ]]; then
    docker compose -p "$PROJECT" --env-file "$ENVF" down -v --remove-orphans >/dev/null 2>&1 || true
  else
    echo "  (--keep: stack left running; remove with: docker compose -p $PROJECT --env-file $ENVF down -v)"
  fi
  [[ $KEEP -eq 1 ]] || rm -rf "$WORK"
}
trap cleanup EXIT

echo "svrnty self-host smoke (project $PROJECT)"

# 1. Without the admin key, compose must refuse up front.
printf 'NEXT_PUBLIC_SVRNTY_DOMAIN=smoke.invalid\n' > "$ENVF"
if dc config >/dev/null 2>"$WORK/noadmin.err"; then
  fail "compose accepted a config with no SATELLITE_ADMIN_KEY"
fi
grep -q "SATELLITE_ADMIN_KEY" "$WORK/noadmin.err" || fail "compose failed, but not on SATELLITE_ADMIN_KEY: $(head -c 300 "$WORK/noadmin.err")"
pass "compose refuses to start without SATELLITE_ADMIN_KEY"

printf 'SATELLITE_ADMIN_KEY=%s\n' "$(openssl rand -hex 32)" >> "$ENVF"
dc config >/dev/null || fail "compose config invalid with the key set"

echo "  ...building and starting app + registration (first build takes a few minutes)"
dc up -d --build app registration >/dev/null

# 2. Satellite healthy + proxy name resolved.
for _ in $(seq 1 90); do
  st="$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q registration)" 2>/dev/null || echo none)"
  [[ "$st" == "healthy" ]] && break
  sleep 2
done
[[ "$st" == "healthy" ]] || { dc logs --tail 30 registration >&2; fail "satellite not healthy (status: $st)"; }
pass "satellite healthy"
logs="$(dc logs registration 2>&1)"
grep -q "Mode: FULL" <<<"$logs" || fail "satellite not in FULL mode"
grep -q "did not resolve" <<<"$logs" && fail "satellite could not resolve its trusted proxy name (app)"
pass "satellite in FULL mode, trusted proxy name resolved"

# 3. App up.
ver=""
for _ in $(seq 1 60); do
  ver="$(dc exec -T app wget -qO- http://localhost:3000/api/version 2>/dev/null || true)"
  [[ -n "$ver" ]] && break
  sleep 2
done
[[ "$ver" == *svrnty-frontend* ]] || fail "app /api/version did not answer"
pass "app serves /api/version"

# 4. App -> satellite hop.
code="$(dc exec -T app sh -c 'wget -S -qO /dev/null http://localhost:3000/api/satellite/trust/psi/satellite-key 2>&1 | awk "/HTTP\//{c=\$2} END{print c}"')"
[[ "$code" == "200" ]] || fail "app -> satellite hop returned ${code:-nothing} (502 = satellite unreachable)"
pass "app reaches the satellite (/api/satellite/trust/psi/satellite-key 200)"

# 5. Relay deposit lands on the volume.
MBX="mbx2_$(openssl rand -hex 32)"
dc exec -T app wget -qO /dev/null --header 'Content-Type: application/json' \
  --post-data "{\"mailbox_id\":\"$MBX\",\"blob\":\"smoke-test-envelope\"}" \
  http://localhost:3000/api/relay/envelope || fail "relay deposit was refused"
count() {
  dc exec -T app node -e '
    const { DatabaseSync } = require("node:sqlite");
    const d = new DatabaseSync(process.env.RELAY_DB_PATH || "/data/relay/mailbox.sqlite", { readOnly: true });
    console.log(d.prepare("SELECT count(*) AS c FROM envelopes WHERE mailbox_id = ?").get(process.argv[1]).c);
  ' "$MBX" 2>/dev/null | tr -d '\r'
}
[[ "$(count)" == "1" ]] || fail "deposit not found in the relay database"
dc exec -T app grep -q ' /data/relay ' /proc/mounts || fail "/data/relay is not a mounted volume"
pass "deposit stored in /data/relay/mailbox.sqlite (a mounted volume)"

# 6. Survives restart and recreate.
dc restart app >/dev/null
for _ in $(seq 1 60); do [[ "$(count)" == "1" ]] && break; sleep 2; done
[[ "$(count)" == "1" ]] || fail "deposit lost after 'restart app'"
pass "deposit survives restart"
dc up -d --force-recreate --no-deps app >/dev/null
for _ in $(seq 1 60); do [[ "$(count)" == "1" ]] && break; sleep 2; done
[[ "$(count)" == "1" ]] || fail "deposit lost after recreating the app container"
pass "deposit survives recreate (the 'up --build' update path)"

# 7. The documented housekeeping command runs (both cleanup routes accept the key from inside the stack).
dc exec -T registration python3 -c "import os,urllib.request as u; [u.urlopen(u.Request('http://localhost:8101'+p, method='POST', headers={'X-Admin-Key': os.environ['SATELLITE_ADMIN_KEY']})) for p in ('/msg/cleanup','/admin/cleanup')]" \
  || fail "the documented cleanup command failed"
code="$(dc exec -T registration python3 -c "import urllib.request as u,urllib.error as e
try: u.urlopen(u.Request('http://localhost:8101/msg/cleanup', method='POST', headers={'X-Admin-Key': 'wrong-key-0123456789abcdef'})); print(200)
except e.HTTPError as x: print(x.code)")"
[[ "$code" == "403" ]] || fail "cleanup accepted a wrong admin key (got $code)"
pass "documented cleanup runs with the key; a wrong key gets 403"

echo "ALL PASS"
