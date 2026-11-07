"""Mutual-trust beacon: poll / withdraw / nonce on the centurion (dark). Run from infra/svrnty with node on PATH (or BEACON_NODE):
python3 -m pytest -q test_beacon_auth.py

Deposits use the verifier test seam; poll and withdraw use the REAL auth.mjs (pinned Poseidon + node:crypto Ed25519), with keys
and signatures made by beacon-verifier/test-sign.mjs from the same shared module a client imports. Responses are compared as
BYTES: a poll before the completing deposit must equal "no match" (13b), and every refusal of an authenticated call must be one
fixed byte string whatever failed (no N-exists oracle).
"""
import json
import os
import shutil
import sqlite3
import subprocess

import pytest

import beacon_centurion as bc

NODE = os.environ.get("BEACON_NODE") or shutil.which("node") or "node"
SIGN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon-verifier", "test-sign.mjs")
NOW = 2900 * 604800 + 5
EPOCH = "2900"
SLOT = "123456789012345678901234567890"
N_A, N_B = "1000000000000000000001", "2000000000000000000002"
SEED_A, SEED_B, SEED_X = "a1" * 32, "b2" * 32, "c3" * 32
AUTH_REFUSED = bc.refused("auth")


def client(seed, op, slot, n, nonce_hex):
    out = subprocess.run([NODE, SIGN], input=json.dumps({"seed": seed, "op": op, "H_e": slot, "N": n, "nonce": nonce_hex}),
                         capture_output=True, text=True, timeout=60, check=True).stdout
    return json.loads(out)


def k_of(seed):
    return client(seed, "poll", "1", "1", "00" * 32)["K"]


class FakeVerifier:
    def __call__(self, raw, now):
        return json.loads(raw)["_t"]


def dep(c, slot, n, k):
    return c.deposit(json.dumps({"_t": {"ok": True, "e": EPOCH, "H_e": slot, "N": n, "K": k}}).encode(), "10.0.0.1")


class Clock:
    def __init__(self):
        self.t = NOW

    def __call__(self):
        return self.t


@pytest.fixture
def cen(tmp_path):
    clk = Clock()
    c = bc.Centurion(str(tmp_path / "beacon.db"), verifier=FakeVerifier(), clock=clk, node=NODE, per_epoch_cap=100,
                     ip_per_minute=1000)
    c.clk = clk
    return c


def get_nonce(c, op, slot, n):
    r = c.nonce(json.dumps({"op": op, "H_e": slot, "N": n}).encode(), "10.0.0.2")
    d = json.loads(r)
    assert set(d) == {"nonce"} and len(d["nonce"]) == 64
    return d["nonce"]


def call(c, op, seed, slot, n, *, nonce=None, sign_op=None, sign_n=None, pk_seed=None):
    """One authenticated call as a client makes it; the overrides build the NEGs."""
    nonce = nonce or get_nonce(c, op, slot, n)
    s = client(seed, sign_op or op, slot, sign_n or n, nonce)
    pk = client(pk_seed, "poll", "1", "1", "00" * 32)["pk"] if pk_seed else s["pk"]
    body = json.dumps({"H_e": slot, "N": n, "pk": pk, "sig": s["sig"], "nonce": nonce}).encode()
    return (c.poll if op == "poll" else c.withdraw)(body, "10.0.0.3")


@pytest.fixture(scope="module")
def keys():
    return {"A": k_of(SEED_A), "B": k_of(SEED_B), "X": k_of(SEED_X)}


def rows(c, sql):
    with sqlite3.connect(c.db_path) as db:
        return db.execute(sql).fetchall()


def test_poll_before_the_completing_deposit_is_byte_identical_to_no_match_13b(cen, keys):
    assert dep(cen, SLOT, N_A, keys["A"]) == bc.ACCEPTED
    assert call(cen, "poll", SEED_A, SLOT, N_A) == bc.NONE


def test_lone_poll_bytes_do_not_depend_on_matches_elsewhere_12(tmp_path, keys):
    out = []
    for other in (False, True):
        c = bc.Centurion(str(tmp_path / f"o{other}.db"), verifier=FakeVerifier(), clock=lambda: NOW, node=NODE,
                         ip_per_minute=1000)
        dep(c, SLOT, N_A, keys["A"])
        if other:
            dep(c, "77", "5", keys["X"])
            dep(c, "77", "6", keys["B"])
        out.append(call(c, "poll", SEED_A, SLOT, N_A))
    assert out[0] == out[1] == bc.NONE


def test_poll_right_after_the_completing_deposit_sees_the_match_for_either_owner_13a(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    dep(cen, SLOT, N_B, keys["B"])
    assert call(cen, "poll", SEED_A, SLOT, N_A) == bc.MATCH
    assert call(cen, "poll", SEED_B, SLOT, N_B) == bc.MATCH
    assert rows(cen, "SELECT polled_n1, polled_n2 FROM beacon_matches") == [(1, 1)]


def test_distinct_k_each_owner_polls_only_its_own_nullifier(cen, keys):
    """Flint #5249: K_A != K_B. A's key sees the match for N_A only and can neither poll nor withdraw N_B."""
    assert keys["A"] != keys["B"]
    dep(cen, SLOT, N_A, keys["A"])
    dep(cen, SLOT, N_B, keys["B"])
    assert call(cen, "poll", SEED_A, SLOT, N_B) == AUTH_REFUSED
    assert call(cen, "withdraw", SEED_A, SLOT, N_B) == AUTH_REFUSED
    assert rows(cen, "SELECT polled_n1, polled_n2 FROM beacon_matches") == [(0, 0)]
    assert call(cen, "poll", SEED_A, SLOT, N_A) == bc.MATCH


def test_every_auth_failure_is_the_same_bytes_and_still_runs_the_authenticator(cen, keys, monkeypatch):
    dep(cen, SLOT, N_A, keys["A"])
    spawned = []
    real = cen._authenticate
    monkeypatch.setattr(cen, "_authenticate", lambda req: (spawned.append(req["N"]), real(req))[1])
    outs = [
        call(cen, "poll", SEED_X, SLOT, N_A),               # wrong key for a deposited N (K mismatch)
        call(cen, "poll", SEED_A, SLOT, "424242"),          # an N nobody deposited (no N-exists oracle)
        call(cen, "poll", SEED_A, SLOT, N_A, sign_n=N_B),    # signature over another N
        call(cen, "poll", SEED_A, SLOT, N_A, pk_seed=SEED_X),  # someone else's pk with A's signature
    ]
    assert outs == [AUTH_REFUSED] * 4
    assert len(spawned) == 4                                # the no-deposit case is not a fast path


def test_nonce_is_single_use_bound_to_op_slot_n_and_expires(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    nn = get_nonce(cen, "poll", SLOT, N_A)
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=nn) == bc.NONE
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=nn) == AUTH_REFUSED            # replay
    w = get_nonce(cen, "withdraw", SLOT, N_A)
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=w, sign_op="poll") == AUTH_REFUSED   # issued for withdraw
    other = get_nonce(cen, "poll", SLOT, N_B)
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=other) == AUTH_REFUSED          # issued for another N
    old = get_nonce(cen, "poll", SLOT, N_A)
    cen.clk.t += bc.NONCE_TTL_SECONDS + 1
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=old) == AUTH_REFUSED            # expired
    fresh = get_nonce(cen, "poll", SLOT, N_A)
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=fresh) == bc.NONE


def test_a_nonce_from_another_centurion_instance_is_refused(tmp_path, keys):
    a = bc.Centurion(str(tmp_path / "x.db"), verifier=FakeVerifier(), clock=lambda: NOW, node=NODE, ip_per_minute=1000)
    b = bc.Centurion(str(tmp_path / "x.db"), verifier=FakeVerifier(), clock=lambda: NOW, node=NODE, ip_per_minute=1000)
    dep(a, SLOT, N_A, keys["A"])
    assert call(b, "poll", SEED_A, SLOT, N_A, nonce=get_nonce(a, "poll", SLOT, N_A)) == AUTH_REFUSED


def test_a_refused_call_does_not_burn_the_nonce_the_owner_can_still_use_it(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    nn = get_nonce(cen, "poll", SLOT, N_A)
    assert call(cen, "poll", SEED_X, SLOT, N_A, nonce=nn) == AUTH_REFUSED
    assert call(cen, "poll", SEED_A, SLOT, N_A, nonce=nn) == bc.NONE
    assert len(rows(cen, "SELECT * FROM beacon_used_nonces")) == 1


def test_withdraw_a_lone_deposit_marks_it_without_deleting_and_it_can_no_longer_match(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    assert call(cen, "withdraw", SEED_A, SLOT, N_A) == bc.WITHDRAWN
    assert rows(cen, "SELECT n, withdrawn_at IS NOT NULL FROM beacon_deposits") == [(N_A, 1)]
    assert dep(cen, SLOT, N_B, keys["B"]) == bc.ACCEPTED
    assert rows(cen, "SELECT count(*) FROM beacon_matches") == [(0,)]
    assert call(cen, "poll", SEED_B, SLOT, N_B) == bc.NONE
    assert call(cen, "poll", SEED_A, SLOT, N_A) == bc.NONE
    assert call(cen, "withdraw", SEED_A, SLOT, N_A) == bc.WITHDRAWN                 # idempotent
    assert dep(cen, SLOT, N_A, keys["A"]) == bc.ALREADY                             # first K wins for the epoch


def test_withdraw_after_a_match_is_inert_and_answers_match(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    dep(cen, SLOT, N_B, keys["B"])
    before = rows(cen, "SELECT * FROM beacon_deposits ORDER BY n")
    assert call(cen, "withdraw", SEED_A, SLOT, N_A) == bc.MATCH
    assert rows(cen, "SELECT * FROM beacon_deposits ORDER BY n") == before
    assert call(cen, "poll", SEED_B, SLOT, N_B) == bc.MATCH


def test_a_third_n_at_a_slot_that_already_holds_two_rows_is_an_alarm_even_if_one_was_withdrawn(cen, keys):
    dep(cen, SLOT, N_A, keys["A"])
    call(cen, "withdraw", SEED_A, SLOT, N_A)
    dep(cen, SLOT, N_B, keys["B"])
    assert dep(cen, SLOT, "3000000000000000000003", keys["X"]) == bc.ACCEPTED
    assert rows(cen, "SELECT count(*) FROM beacon_deposits") == [(2,)]
    assert rows(cen, "SELECT count(*) FROM beacon_matches") == [(0,)]
    assert rows(cen, "SELECT n FROM beacon_security_alarms") == [("3000000000000000000003",)]


@pytest.mark.parametrize("raw", [
    b"", b"[]", b'{"op":"poll","H_e":"1"}', b'{"op":"poll","H_e":"1","N":"1","x":"1"}', b'{"op":"Poll","H_e":"1","N":"1"}',
    b'{"op":"poll","H_e":"01","N":"1"}', b'{"op":"poll","H_e":"1","N":1}',
])
def test_nonce_request_is_strict(cen, raw):
    assert cen.nonce(raw, "10.0.0.2") == bc.refused("wire")


@pytest.mark.parametrize("patch", [
    {"extra": "1"}, {"N": "007"}, {"pk": "AB" * 32}, {"sig": "ab" * 63}, {"nonce": "ab" * 33}, {"H_e": 5},
])
def test_poll_body_is_strict_and_refused_before_spawning(cen, keys, patch, monkeypatch):
    dep(cen, SLOT, N_A, keys["A"])
    good = {"H_e": SLOT, "N": N_A, "pk": "ab" * 32, "sig": "ab" * 64, "nonce": get_nonce(cen, "poll", SLOT, N_A)}
    monkeypatch.setattr(cen, "_authenticate", lambda req: pytest.fail("spawned on a malformed body"))
    assert cen.poll(json.dumps({**good, **patch}).encode(), "10.0.0.3") == bc.refused("wire")


@pytest.mark.parametrize("stdout,code,ok", [
    (b'{"ok":true}\n', 0, True),
    (b"", 0, False), (b'{"ok":true}', 0, False), (b'{"ok":true}\n{"ok":true}\n', 0, False), (b'{"ok":true}\n', 2, False),
    (b'{"ok": true}\n', 0, False), (b'{"ok":true,"x":1}\n', 0, False), (b'{"ok":false,"reason":"auth"}\n', 1, False),
])
def test_auth_output_is_parsed_fail_closed(stdout, code, ok):
    assert bc.parse_auth_output(code, stdout) is ok
