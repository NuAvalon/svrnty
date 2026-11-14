#!/usr/bin/env bash
# selfhost_csp_check.sh — prove a page served through this Caddyfile still carries the app's script policy.
#
# The app sets its own Content-Security-Policy with a new nonce on every response. A
# Content-Security-Policy line in the Caddyfile replaces that header, and nothing tells you: the
# page still works, with no script protection. So look at what a browser would actually receive.
#
# Usage: scripts/selfhost_csp_check.sh <docker-network-with-the-app-on-it> [path-to-Caddyfile]
# Publishes no ports and removes its own container. Exit 0 = one header with a nonce.
set -euo pipefail

NET="${1:?usage: selfhost_csp_check.sh <docker-network> [Caddyfile]}"
FILE="$(realpath "${2:-Caddyfile}")"
[[ -f "$FILE" ]] || { echo "no Caddyfile at $FILE" >&2; exit 2; }

NAME="svrnty-csp-check-$$"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$NAME" --network "$NET" -e SVRNTY_DOMAIN=localhost \
  -v "$FILE:/etc/caddy/Caddyfile:ro" caddy:2-alpine >/dev/null

headers=""
for _ in $(seq 1 30); do
  headers="$(docker exec "$NAME" wget -S --no-check-certificate -T 5 -O /dev/null https://localhost/ 2>&1 || true)"
  grep -q ' 200 ' <<<"$headers" && break
  sleep 1
done
grep -q ' 200 ' <<<"$headers" || { echo "FAIL  no 200 for / through this Caddyfile"; exit 1; }

csp="$(grep -i '^ *content-security-policy:' <<<"$headers" || true)"
count="$(grep -c . <<<"$csp" || true)"
[[ "$count" == "1" ]] || { echo "FAIL  expected exactly one Content-Security-Policy header, got $count"; exit 1; }
if ! grep -q "'nonce-" <<<"$csp"; then
  echo "FAIL  the served policy has no nonce, so the app's script protection is off."
  echo "      Your Caddyfile is replacing it. Remove its Content-Security-Policy line."
  exit 1
fi
echo "PASS  one Content-Security-Policy header, with a nonce, through this Caddyfile"
