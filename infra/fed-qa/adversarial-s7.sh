#!/usr/bin/env bash
# infra/fed-qa/adversarial-s7.sh — S7 ADVERSARIAL PASS (per fed-qa/README.md).
#
# G7 launch-gate cells. Proves the satellite keystone's NO-SILENT-LOSS + ANTI-SPAM defenses RESIST
# attack. Contract grounded first-hand vs the vendored keystone infra/svrnty/satellite.py — line
# cites inline.
#
# ACCEPTANCE (locked): the sender can ALWAYS distinguish, HONESTLY, three states —
#   DELIVERED (only on an AUTHENTICATED ack) / PENDING (durable retry) / EXPIRED (sender-visible TTL).
#   Never a silent drop. Never a false "delivered". These cells attack each of those guarantees.
#
# AUTH (tag#3, satellite.py:709/:691/:740/:744 — the live code, which supersedes the stale
#   "{fp}:{minute}" signature docstring; comment != code): preimage `svrnty-psi-auth:{fp}:{unix_seconds}`,
#   wire `{unix_seconds}:{base64(sig)}`, sig = Ed25519(bound_sig_seed, preimage), ±30s. The seeder
#   SELF-BINDs, so *_SIGNKEY (base64 raw 32B ed25519 seed) is identity key AND tag#3 auth key.
#   Signing is done by the SHARED ./x_sig.sh (one impl for the recovery + adversarial cells; openssl
#   == @noble/curves byte-for-byte, RFC8032-deterministic — gated on xsig_selftest so a runner without
#   ed25519 openssl SKIPs, never fakes).
#
# FIXTURES (shared seeder seed_keystone.mts, sourced by run.sh as fed-qa-fixtures.env):
#   VICTIM_FP / VICTIM_SIGNKEY — registered+bound recipient;  SENDER_FP / SENDER_SIGNKEY — registered+
#   bound identity, ALLOWED-sender → VICTIM.  (ignores the VICTIM_NEW_* pair — that's G4's.)
#
# GRADUATION: these cells hit the REAL keystone's /send·/ack·/msg/status — endpoints that EXIST only
#   in SATELLITE_MODE=full. Mode-gated on /health .mode=="full"; expiry needs SATELLITE_MSG_TTL_DAYS=0.
#   Until the vendor-swap brings up a full-mode keystone + runs the seeder, cells SKIP — honestly
#   marked, NOT faked (fed-qa: "an always-green job is worse than none").
#
# Run: RELAY=http://app-a:3000 ./adversarial-s7.sh     (RELAY = the keystone under test)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

RELAY="${RELAY:-http://app-a:3000}"
PASS=0; FAIL=0; SKIP=0
ok()   { echo "ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL $1"; FAIL=$((FAIL+1)); }
skip() { echo "skip $1"; SKIP=$((SKIP+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

# ── GRADUATION PROBE (mode-aware) ─────────────────────────────────────────────────────────────
# /send·/ack·/retrieve are require_full_mode (satellite.py:541 → 403 "Endpoint disabled" in registry
# mode). A bare 403 therefore does NOT prove the keystone is up for messaging — the registry stub AND
# a registry-mode keystone both 403 /ack. Gate on /health .mode so b1 (unsigned-ack→403) can't pass
# for the WRONG reason (endpoint-disabled vs auth-rejected).
health=$(curl -s --max-time 5 "$RELAY/health" 2>/dev/null || true)
mode=$(printf '%s' "$health" | jq -r '.mode // empty' 2>/dev/null || true)
if [ "$mode" != "full" ]; then
  echo "S7 adversarial: keystone not in FULL messaging mode (/health .mode='${mode:-unreachable}') — SKIP, gate-graduate on vendor-swap + SATELLITE_MODE=full."
  skip "G7-a force-expiry-visible"
  skip "G7-b ack-spoof-auth (b1/b2/b3)"
  skip "G7-c mailbox-flood / anti-spam"
  echo "S7: ${PASS} ok / ${FAIL} fail / ${SKIP} skip (pending full-mode keystone — not faked)"
  exit 0
fi

# Shared tag#3 signer + known-answer selftest (the ONLY place either cell-set builds a signature).
SIGNER_OK=0
if [ -f "$HERE/x_sig.sh" ]; then
  . "$HERE/x_sig.sh"
  if xsig_selftest; then SIGNER_OK=1; fi
else
  echo "S7: x_sig.sh not found next to the cell — authenticated cells will SKIP (b1/c1 still run)." >&2
fi

# Fixtures from the shared seeder.
VICTIM_FP="${VICTIM_FP:-}"; VICTIM_SIGNKEY="${VICTIM_SIGNKEY:-}"
SENDER_FP="${SENDER_FP:-}"; SENDER_SIGNKEY="${SENDER_SIGNKEY:-}"
# Authenticated cells need the seeder fixtures AND a working signer.
have_auth() { [ "$SIGNER_OK" = "1" ] && [ -n "$VICTIM_FP" ] && [ -n "$VICTIM_SIGNKEY" ] \
                                     && [ -n "$SENDER_FP" ] && [ -n "$SENDER_SIGNKEY" ]; }

# deposit_to_victim -> echoes a numeric message_id (empty on failure). SENDER authenticates (tag#3)
#   and is an allowed-sender → VICTIM (seeded). blob = 120 random bytes b64 (>=89B + ~8 bits/byte
#   entropy → passes reject_plaintext satellite.py:606/:622).
deposit_to_victim() {
  local sig blob
  sig=$(xsig_wire_from_seed "$SENDER_SIGNKEY" "$SENDER_FP") || return 1
  blob=$(head -c 256 /dev/urandom | base64 | tr -d '\n')
  curl -s --max-time 10 -X POST "$RELAY/send" -H 'content-type: application/json' \
    -d "{\"recipient\":\"$VICTIM_FP\",\"sender_fingerprint\":\"$SENDER_FP\",\"encrypted_blob\":\"$blob\",\"signature\":\"$sig\"}" \
    | jq -r '.message_id // empty' 2>/dev/null
}
# status_as <fp> <signkey> <msg_id> -> echoes .status ("queued"|"delivered"|"expired"); sender or
#   recipient of the message may read it (satellite.py:2251).
status_as() {
  local sig
  sig=$(xsig_wire_from_seed "$2" "$1") || return 1
  curl -s --max-time 10 "$RELAY/msg/status/$3?fingerprint=$1" -H "X-Signature: $sig" \
    | jq -r '.status // empty' 2>/dev/null
}

# ── G7-b — ACK-SPOOF → AUTHENTICATED ACK (enforces the NO-FALSE-DELIVERED guarantee) ───────────
# satellite.py:2200 verify_request_signature(fp,x_sig) else 403;  :2211 UPDATE ... WHERE recipient = ?
# A forged / cross-user ack must NEVER flip a message to "delivered" — the worst failure (sender
# thinks it sent; it didn't). NOTE (:2217): /ack echoes len(message_ids), NOT rows-affected — so
# recipient-binding is observable ONLY via /msg/status, never the ack response.

# b1 — UNSIGNED ack rejected (403). No key/fixtures needed; runs whenever the keystone is full-mode up.
c=$(code -X POST "$RELAY/ack/${VICTIM_FP:-any-fp}" -H 'content-type: application/json' -d '{"message_ids":[1]}')
[ "$c" = "403" ] && ok "G7-b1 unsigned ack rejected (403)" \
                 || bad "G7-b1 unsigned ack NOT rejected ($c) — FALSE-DELIVERED hole"

if have_auth; then
  # b2 — WRONG-KEY ack: a well-formed tag#3 wire over svrnty-psi-auth:VICTIM_FP:unix, but signed by a
  #   THROWAWAY key (not VICTIM's bound sig_pubkey) → verify fails → 403.
  twsig=$(xsig_wire_throwaway "$VICTIM_FP")
  c=$(code -X POST "$RELAY/ack/$VICTIM_FP" -H 'content-type: application/json' \
         -H "X-Signature: $twsig" -d '{"message_ids":[1]}')
  [ "$c" = "403" ] && ok "G7-b2 wrong-key ack rejected (403)" \
                   || bad "G7-b2 wrong-key ack accepted ($c) — impersonated delivered-ack"
  # b2+ POSITIVE CONTROL: VICTIM's CORRECT sig (empty message_ids) must NOT 403 — proves the b2 403
  #   is wrong-KEY-specific, not an always-reject endpoint (:2204 empty ids → {"acked":0}, 200).
  vsig=$(xsig_wire_from_seed "$VICTIM_SIGNKEY" "$VICTIM_FP")
  c=$(code -X POST "$RELAY/ack/$VICTIM_FP" -H 'content-type: application/json' \
         -H "X-Signature: $vsig" -d '{"message_ids":[]}')
  [ "$c" != "403" ] && ok "G7-b2+ correct-key ack authenticates ($c, not 403) — b2's 403 is wrong-key-specific" \
                    || bad "G7-b2+ correct-key ack ALSO 403 — b2 is an always-reject false-pass, not a real wrong-key test"

  # b3 — RECIPIENT-BINDING: a VALID (own-key) ack only marks the SIGNER's OWN messages (:2211 WHERE
  #   recipient = fp). SENDER (validly signed as itself) acking VICTIM's message marks ZERO rows → the
  #   message NEVER reads "delivered". Positive control: VICTIM acking its OWN message DOES deliver,
  #   proving the non-flip is meaningful (not a dead ack path).
  id1=$(deposit_to_victim)
  if printf '%s' "$id1" | grep -qE '^[0-9]+$'; then
    ssig=$(xsig_wire_from_seed "$SENDER_SIGNKEY" "$SENDER_FP")
    code -X POST "$RELAY/ack/$SENDER_FP" -H 'content-type: application/json' \
         -H "X-Signature: $ssig" -d "{\"message_ids\":[$id1]}" >/dev/null   # SENDER cross-acks VICTIM's msg
    s1=$(status_as "$SENDER_FP" "$SENDER_SIGNKEY" "$id1")
    [ "$s1" != "delivered" ] && ok "G7-b3 cross-user ack marks ZERO ($id1→'$s1', not delivered) — recipient-binding holds" \
                             || bad "G7-b3 cross-user ack FLIPPED to delivered — recipient-binding BROKEN (false-delivered)"
    id2=$(deposit_to_victim)
    if printf '%s' "$id2" | grep -qE '^[0-9]+$'; then
      vack=$(xsig_wire_from_seed "$VICTIM_SIGNKEY" "$VICTIM_FP")
      code -X POST "$RELAY/ack/$VICTIM_FP" -H 'content-type: application/json' \
           -H "X-Signature: $vack" -d "{\"message_ids\":[$id2]}" >/dev/null   # correct recipient acks
      s2=$(status_as "$SENDER_FP" "$SENDER_SIGNKEY" "$id2")
      [ "$s2" = "delivered" ] && ok "G7-b3+ correct-recipient ack DOES deliver ($id2→delivered) — b3 non-flip is meaningful" \
                              || bad "G7-b3+ correct-recipient ack did NOT deliver ($id2→'$s2') — ack path broken, b3 inconclusive"
    else
      skip "G7-b3+ positive-control deposit failed (no msg_id)"
    fi
  else
    skip "G7-b3 cross-user-ack (deposit to VICTIM failed — no msg_id; check SENDER→VICTIM allowed-sender seed)"
  fi
else
  skip "G7-b2 wrong-key-ack (needs x_sig.sh selftest-PASS + seeder VICTIM_*/SENDER_*)"
  skip "G7-b3 cross-user-ack (needs x_sig.sh selftest-PASS + seeder fixtures)"
fi

# ── G7-a — FORCE-EXPIRY must stay SENDER-VISIBLE in the PRE-PURGE window ───────────────────────
# satellite.py:59 SATELLITE_MSG_TTL_DAYS (run the fed-qa keystone with =0 → immediate expiry); :2259
# retrieved→"delivered" (checked FIRST); :2261 ttl_expired→"expired"; else "queued".
# ★ PURGE-SEAM (locked): /msg/status is the PRE-purge substrate. POST-purge (/msg/cleanup, admin-
#   gated) it 404s (ambiguous with never-existed) → NOT the terminal authority. The CLIENT send-outbox
#   (G6-d Case-2) resolves saw-queued+404 → EXPIRED, durable, relay-independent. No-silent-loss UNION
#   = G7-a (pre-purge relay) ∪ Case-2 (post-purge client). THIS cell asserts ONLY the relay half; it
#   must NOT claim the relay is authoritative post-purge.
# Attack: deposit → NEVER retrieve → SENDER's /msg/status must read EXPIRED (sender LEARNS), and must
#   NEVER read "delivered" (no authenticated ack was ever sent).
if have_auth; then
  ida=$(deposit_to_victim)
  if printf '%s' "$ida" | grep -qE '^[0-9]+$'; then
    sa=$(status_as "$SENDER_FP" "$SENDER_SIGNKEY" "$ida")
    [ "$sa" = "expired" ] && ok "G7-a expiry sender-visible pre-purge ($ida→expired)" \
                          || bad "G7-a expiry NOT sender-visible ($ida→'$sa') — needs SATELLITE_MSG_TTL_DAYS=0; silent-loss risk"
    [ "$sa" != "delivered" ] || bad "G7-a UNSENT message shows 'delivered' — false-delivered (no ack was sent)"
  else
    skip "G7-a expiry (deposit to VICTIM failed — no msg_id)"
  fi
else
  skip "G7-a expiry-sender-visible-PRE-purge (needs signer + seeder fixtures + SATELLITE_MSG_TTL_DAYS=0)"
fi

# ── G7-c — MAILBOX-FLOOD / ANTI-SPAM can't deny a victim's real messages ───────────────────────
# c1 — STORAGE-BLOAT DoS: the real keystone PINS owner_sig on /mailbox/register (satellite.py:1210,
#   verify steps :1219-1223) — so an UNSIGNED register flood is rejected at validation (422 missing
#   owner_sig / 400 non-hex) and/or by the :423 /mailbox 10/min limiter (429) BEFORE it can create a
#   row. Either way the flood is BOUNDED — rejected (4xx), never stored (never 2xx). [A STUB that
#   accepts any body would be bounded only by the limiter; the real keystone validates first, a
#   stronger bound.] The limiter-for-VALID-registers path needs a mailbox-identity fixture the shared
#   seeder doesn't provide → out of scope here.
c=""; for i in $(seq 1 12); do c=$(code -X POST "$RELAY/mailbox/register" \
      -H 'content-type: application/json' -d '{"mailbox_fp":"flood","x25519_pub":"x","mlkem_ek":"k"}'); done
case "$c" in
  4*) ok "G7-c1 unsigned register flood rejected ($c, 4xx) — storage-bloat DoS bounded, not fail-open" ;;
  2*) bad "G7-c1 unsigned register ACCEPTED ($c) — storage-bloat DoS fail-open" ;;
  *)  bad "G7-c1 unsigned register flood → unexpected $c (want 4xx reject; 5xx/000 = server error/unreachable)" ;;
esac
# c2 — ring-cap-keeps-newest under flood (MAX_BLOBS_PER_RENDEZVOUS, satellite.py:46 "evict oldest,
#   NEVER drop newest"). Needs a rendezvous-tag deposit+readback fixture the shared seeder does NOT
#   provide (beacon ring, not the message queue) — out of seeder scope; honest-skip until it lands.
skip "G7-c2 ring-cap-keeps-newest-under-flood (needs rendezvous-tag deposit+readback fixture)"

echo "S7 adversarial: ${PASS} ok / ${FAIL} fail / ${SKIP} skip"
[ "$FAIL" = "0" ] || exit 1
