"""Mutual-trust beacon, the centurion's deposit path + store (dark). Run from infra/svrnty: python3 -m pytest -q test_beacon_centurion.py

The verifier subprocess is replaced by a test seam returning canonical tuples, except in the timeout test, which spawns a real
process tree to prove the whole group dies. Responses are compared as BYTES: a lone deposit must look the same no matter what
else is stored, and the deposit that completes a bond must look like any other accepted deposit (the poll delivers the match).
"""
import json
import os
import sqlite3
import sys
import time

import pytest

import beacon_centurion as bc

NOW = 2900 * 604800 + 5
EPOCH = "2900"


def tup(slot, n, k="9", e=EPOCH):
    return {"ok": True, "e": e, "H_e": slot, "N": n, "K": k}


class FakeVerifier:
    """Maps a raw body to a tuple; counts calls (so 'refused BEFORE spawning' is checkable)."""
    def __init__(self):
        self.calls = 0

    def __call__(self, raw, now):
        self.calls += 1
        return json.loads(raw)["_t"]


def body(t):
    return json.dumps({"_t": t}).encode()


@pytest.fixture
def cen(tmp_path):
    fv = FakeVerifier()
    c = bc.Centurion(str(tmp_path / "beacon.db"), verifier=fv, clock=lambda: NOW, per_epoch_cap=100, ip_per_minute=1000)
    c.fv = fv
    return c


def rows(c, table):
    with sqlite3.connect(c.db_path) as db:
        return db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def test_flag_defaults_off(monkeypatch):
    monkeypatch.delenv(bc.FLAG_ENV, raising=False)
    assert bc.enabled() is False
    monkeypatch.setenv(bc.FLAG_ENV, "1")
    assert bc.enabled() is True
    monkeypatch.setenv(bc.FLAG_ENV, "true")          # only the exact value "1" turns it on
    assert bc.enabled() is False


def test_store_is_durable_mode(cen):
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_lone_deposit_response_is_byte_identical_whatever_else_exists(tmp_path):
    out = []
    for others in ([], [tup("777", "5")], [tup("777", "5"), tup("777", "6"), tup("888", "1")]):
        fv = FakeVerifier()
        c = bc.Centurion(str(tmp_path / f"b{len(others)}.db"), verifier=fv, clock=lambda: NOW, per_epoch_cap=100, ip_per_minute=1000)
        for o in others:
            c.deposit(body(o), "10.0.0.2")
        out.append(c.deposit(body(tup("123", "42")), "10.0.0.1"))
    assert out[0] == out[1] == out[2] == bc.ACCEPTED


def test_completing_deposit_looks_like_any_accepted_one_and_writes_the_match(cen):
    assert cen.deposit(body(tup("123", "42", k="1")), "a") == bc.ACCEPTED
    assert cen.deposit(body(tup("123", "43", k="2")), "b") == bc.ACCEPTED       # completes the bond: same bytes
    with sqlite3.connect(cen.db_path) as db:
        n1, n2, formed, released = db.execute("SELECT n1, n2, formed_at, released_at FROM beacon_matches").fetchone()
    assert (n1, n2) == ("42", "43") and released == formed                       # release on match


def test_match_orders_nullifiers_numerically_not_as_strings(cen):
    cen.deposit(body(tup("1", "9")), "a")
    cen.deposit(body(tup("1", "10")), "b")
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("SELECT n1, n2 FROM beacon_matches").fetchone() == ("9", "10")


def test_same_nullifier_again_is_already_and_adds_nothing(cen):
    cen.deposit(body(tup("123", "42", k="1")), "a")
    assert cen.deposit(body(tup("123", "42", k="7")), "a") == bc.ALREADY          # a new K never replaces the first
    assert rows(cen, "beacon_deposits") == 1 and rows(cen, "beacon_matches") == 0
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("SELECT k FROM beacon_deposits").fetchone()[0] == "1"


def test_third_nullifier_at_a_matched_slot_is_silent_outside_and_an_alarm_inside(cen):
    cen.deposit(body(tup("123", "42")), "a")
    cen.deposit(body(tup("123", "43")), "b")
    before = (rows(cen, "beacon_deposits"), rows(cen, "beacon_matches"))
    assert cen.deposit(body(tup("123", "44")), "c") == bc.ACCEPTED
    assert (rows(cen, "beacon_deposits"), rows(cen, "beacon_matches")) == before
    assert rows(cen, "beacon_security_alarms") == 1
    with sqlite3.connect(cen.db_path) as db:
        slot, n, raw = db.execute("SELECT slot, n, raw FROM beacon_security_alarms").fetchone()
    assert (slot, n) == ("123", "44") and json.loads(raw)["_t"]["N"] == "44"      # the evidence is kept


def test_refusals_and_verifier_reasons_pass_through_without_echo(cen):
    def refusing(raw, now):
        return {"ok": False, "reason": "proof"}
    cen.verifier = refusing
    r = cen.deposit(body(tup("123", "42")), "a")
    assert r == bc.refused("proof") and b"42" not in r
    assert rows(cen, "beacon_deposits") == 0


def test_oversized_body_refused_before_spawning(cen):
    assert cen.deposit(b"x" * (bc.MAX_BODY_BYTES + 1), "a") == bc.refused("wire")
    assert cen.fv.calls == 0


def test_rate_limit_is_checked_before_spawning(tmp_path):
    fv = FakeVerifier()
    c = bc.Centurion(str(tmp_path / "r.db"), verifier=fv, clock=lambda: NOW, per_epoch_cap=100, ip_per_minute=2)
    for i in range(2):
        c.deposit(body(tup(str(100 + i), "1")), "1.2.3.4")
    assert c.deposit(body(tup("200", "1")), "1.2.3.4") == bc.refused("rate")
    assert fv.calls == 2                                       # the third never reached the verifier
    assert c.deposit(body(tup("201", "1")), "5.6.7.8") == bc.ACCEPTED


def test_cap_counts_only_open_epochs_fails_closed_and_never_evicts(tmp_path):
    fv = FakeVerifier()
    t = {"now": NOW}
    c = bc.Centurion(str(tmp_path / "c.db"), verifier=fv, clock=lambda: t["now"], per_epoch_cap=2, ip_per_minute=1000)
    c.deposit(body(tup("1", "1")), "a")
    c.deposit(body(tup("2", "1")), "a")
    assert c.deposit(body(tup("3", "1")), "a") == bc.refused("full")             # full: refuse new...
    assert rows(c, "beacon_deposits") == 2                                         # ...and evict nothing
    t["now"] = NOW + 604800 + 3600                                                 # next epoch, past the grace window
    assert c.deposit(body(tup("4", "1", e="2901")), "a") == bc.ACCEPTED            # a closed epoch can't block new ones
    assert rows(c, "beacon_deposits") == 3


def test_a_failure_inside_the_transaction_leaves_no_rows(cen, monkeypatch):
    cen.deposit(body(tup("123", "42")), "a")
    monkeypatch.setattr(bc, "_insert_match", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError):
        cen.deposit(body(tup("123", "43")), "b")
    assert rows(cen, "beacon_deposits") == 1 and rows(cen, "beacon_matches") == 0     # the 2nd deposit rolled back too


def test_verifier_timeout_kills_the_whole_process_group(tmp_path):
    marker = tmp_path / "grandchild.pid"
    hang = ("import os, subprocess, sys, time;"
            f"p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']);"
            f"open({str(marker)!r}, 'w').write(str(p.pid)); time.sleep(60)")
    c = bc.Centurion(str(tmp_path / "t.db"), verify_cmd=[sys.executable, "-c", hang], clock=lambda: NOW,
                     per_epoch_cap=10, ip_per_minute=10, timeout_s=1.5, vkey_path=None)
    t0 = time.monotonic()
    assert c.deposit(b'{"proof":{},"publicSignals":[]}', "a") == bc.refused("timeout")
    assert time.monotonic() - t0 < 10
    gpid = int(marker.read_text())
    for _ in range(50):                                        # give the kernel a moment to reap
        try:
            os.kill(gpid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("the grandchild outlived the timeout")
    assert rows(c, "beacon_deposits") == 0


@pytest.mark.parametrize("stdout,code", [
    (b"", 0),                                                                           # the old fail-open: exit 0, nothing printed
    (b'{"ok":true,"e":"2900","H_e":"1","N":"2","K":"3"}', 0),                            # no newline
    (b'{"ok":true,"e":"2900","H_e":"1","N":"2","K":"3"}\n{"ok":true}\n', 0),            # two lines
    (b'{"ok":true,"e":"2900","H_e":"1","N":"2","K":"3","x":1}\n', 0),                   # extra key
    (b'{"ok":true,"e":"2900","H_e":"1","N":"007","K":"3"}\n', 0),                       # non-canonical N
    (b'{"ok":"yes","e":"2900","H_e":"1","N":"2","K":"3"}\n', 0),                        # ok not exactly true
    (b'{"ok":true,"e":"2900","H_e":"1","N":"2","K":"3"}\n', 2),                         # right line, wrong exit code
])
def test_verifier_output_is_parsed_fail_closed(tmp_path, stdout, code):
    script = f"import sys; sys.stdout.buffer.write({stdout!r}); sys.exit({code})"
    c = bc.Centurion(str(tmp_path / "o.db"), verify_cmd=[sys.executable, "-c", script], clock=lambda: NOW,
                     per_epoch_cap=10, ip_per_minute=10, timeout_s=10)
    assert c.deposit(b"{}", "a") == bc.refused("internal")
    assert rows(c, "beacon_deposits") == 0


FIX = os.environ.get("BEACON_FIXTURES")
NODE = os.environ.get("BEACON_NODE", "node")


@pytest.mark.skipif(not (FIX and os.path.exists(os.path.join(FIX or "", "vkey.json"))),
                    reason="needs the rehearsal THROWAWAY fixtures in $BEACON_FIXTURES")
def test_end_to_end_real_proofs_through_the_real_verifier_form_one_bond(tmp_path):
    """Two real throwaway proofs (same slot, different nullifiers) through node + the pinned snarkjs -> exactly one match."""
    e = int(json.load(open(os.path.join(FIX, "public_A.json")))[0])
    c = bc.Centurion(str(tmp_path / "e2e.db"), vkey_path=os.path.join(FIX, "vkey.json"), node=NODE,
                     clock=lambda: e * bc.EPOCH_SECONDS + 5, per_epoch_cap=10, ip_per_minute=10, timeout_s=60)
    dep = lambda who: json.dumps({"proof": json.load(open(os.path.join(FIX, f"proof_{who}.json"))),
                                  "publicSignals": json.load(open(os.path.join(FIX, f"public_{who}.json")))}).encode()
    assert c.deposit(dep("A"), "a") == bc.ACCEPTED
    assert c.deposit(dep("A"), "a") == bc.ALREADY
    assert c.deposit(dep("B"), "b") == bc.ACCEPTED
    with sqlite3.connect(c.db_path) as db:
        (n1, n2, rel, formed), = db.execute("SELECT n1, n2, released_at, formed_at FROM beacon_matches").fetchall()
        assert db.execute("SELECT count(*) FROM beacon_deposits").fetchone()[0] == 2
    ns = sorted((json.load(open(os.path.join(FIX, f"public_{w}.json")))[2] for w in "AB"), key=int)
    assert [n1, n2] == ns and rel == formed


def test_python_epoch_constants_equal_the_shared_js_module():
    """Python can't import the JS module, so it keeps its own copy; this pins the copy to beacon-wire.mjs (the one the
    prover and verify.mjs import). A drift here = every deposit lands in an epoch the other side never matches."""
    import subprocess
    wire = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon-verifier", "beacon-wire.mjs")  # the copy the image runs; CI pins it to src/lib/crypto
    code = ("import(process.argv[1]).then(m => process.stdout.write(JSON.stringify("
            "{e: m.EPOCH_SECONDS ?? null, g: m.GRACE_SECONDS ?? null})))")
    out = subprocess.run([NODE, "-e", code, os.path.realpath(wire)], capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(out.stdout) == {"e": bc.EPOCH_SECONDS, "g": bc.GRACE_SECONDS}
