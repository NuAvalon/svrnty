"""Mutual-trust beacon: centurion hardening before any route is wired (dark). Run from infra/svrnty:
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q test_beacon_hardening.py

A global bound on verifier/authenticator processes in flight; rate-limit keys per IPv6 /64 in a table of bounded size that
fails closed when every entry is active; the alarm count a health check reads (counts only); and ONE entry point whose
response to any internal exception is the fixed refused("internal") bytes.
"""
import json
import threading

import pytest

import beacon_centurion as bc

NOW = 2900 * 604800 + 5
EPOCH = "2900"


def body(slot, n, k="9"):
    return json.dumps({"_t": {"ok": True, "e": EPOCH, "H_e": slot, "N": n, "K": k}}).encode()


class BlockingVerifier:
    """Each call announces itself and waits until released, so a test can hold N processes 'in flight'."""
    def __init__(self):
        self.calls, self.inside = 0, threading.Semaphore(0)
        self.release = threading.Event()

    def __call__(self, raw, now):
        self.calls += 1
        self.inside.release()
        assert self.release.wait(30)
        return json.loads(raw)["_t"]


def test_global_inflight_bound_refuses_before_spawning_and_frees_after(tmp_path):
    bv = BlockingVerifier()
    c = bc.Centurion(str(tmp_path / "s.db"), verifier=bv, clock=lambda: NOW, ip_per_minute=1000, max_inflight=2)
    out = {}
    ts = [threading.Thread(target=lambda i=i: out.__setitem__(i, c.deposit(body(str(10 + i), "1"), f"10.0.0.{i}")))
          for i in range(2)]
    for t in ts:
        t.start()
    for _ in range(2):
        assert bv.inside.acquire(timeout=30)
    assert c.deposit(body("99", "1"), "10.0.1.1") == bc.refused("rate")         # a third, from another IP: no process
    assert bv.calls == 2
    bv.release.set()
    for t in ts:
        t.join(30)
    assert out == {0: bc.ACCEPTED, 1: bc.ACCEPTED}
    assert c.deposit(body("98", "1"), "10.0.1.1") == bc.ACCEPTED                # the slots came back


def test_the_authenticator_shares_the_same_bound(tmp_path, monkeypatch):
    bv = BlockingVerifier()
    c = bc.Centurion(str(tmp_path / "a.db"), verifier=bv, clock=lambda: NOW, ip_per_minute=1000, max_inflight=1)
    t = threading.Thread(target=lambda: c.deposit(body("10", "1"), "10.0.0.1"))
    t.start()
    assert bv.inside.acquire(timeout=30)
    monkeypatch.setattr(c, "_authenticate", lambda req: pytest.fail("spawned past the bound"))
    nonce = json.loads(c.nonce(json.dumps({"op": "poll", "H_e": "10", "N": "1"}).encode(), "10.0.0.2"))["nonce"]
    poll = json.dumps({"H_e": "10", "N": "1", "pk": "ab" * 32, "sig": "ab" * 64, "nonce": nonce}).encode()
    assert c.poll(poll, "10.0.0.3") == bc.refused("rate")
    bv.release.set()
    t.join(30)


def test_ipv6_is_limited_per_slash64_and_ipv4_mapped_is_ipv4(tmp_path):
    c = bc.Centurion(str(tmp_path / "v6.db"), verifier=lambda raw, now: json.loads(raw)["_t"], clock=lambda: NOW,
                     ip_per_minute=1)
    assert c.deposit(body("1", "1"), "2001:db8:1:2::1") == bc.ACCEPTED
    assert c.deposit(body("2", "1"), "2001:db8:1:2:ffff:ffff:ffff:ffff") == bc.refused("rate")   # same /64
    assert c.deposit(body("3", "1"), "2001:db8:1:3::1") == bc.ACCEPTED                            # next /64
    assert c.deposit(body("4", "1"), "1.2.3.4") == bc.ACCEPTED
    assert c.deposit(body("5", "1"), "::ffff:1.2.3.4") == bc.refused("rate")                      # = 1.2.3.4


def test_ip_table_is_bounded_sweeps_stale_and_fails_closed_when_all_active(tmp_path):
    t = {"now": NOW}
    calls = []
    c = bc.Centurion(str(tmp_path / "b.db"), verifier=lambda raw, now: (calls.append(1), json.loads(raw)["_t"])[1],
                     clock=lambda: t["now"], ip_per_minute=1000, max_ip_keys=3)
    for i in range(3):
        assert c.deposit(body(str(i), "1"), f"10.0.0.{i}") == bc.ACCEPTED
    assert c.deposit(body("50", "1"), "10.0.9.9") == bc.refused("rate")         # full of ACTIVE keys: refuse, evict no one
    assert len(calls) == 3
    t["now"] = NOW + 61                                                           # every key is now stale
    assert c.deposit(body("51", "1"), "10.0.9.9") == bc.ACCEPTED
    assert len(c._ip_hits) <= 3


def test_alarm_count_is_a_number_for_the_health_check(tmp_path):
    c = bc.Centurion(str(tmp_path / "al.db"), verifier=lambda raw, now: json.loads(raw)["_t"], clock=lambda: NOW,
                     ip_per_minute=1000)
    assert c.alarm_count() == 0
    c.deposit(body("7", "1"), "a")
    c.deposit(body("7", "2"), "a")
    assert c.alarm_count() == 0
    c.deposit(body("7", "3"), "a")                                               # a third N at a matched slot
    assert c.alarm_count() == 1


def test_handle_turns_any_internal_exception_into_the_fixed_bytes(tmp_path, monkeypatch):
    c = bc.Centurion(str(tmp_path / "h.db"), verifier=lambda raw, now: json.loads(raw)["_t"], clock=lambda: NOW,
                     ip_per_minute=1000)
    assert c.handle("deposit", body("8", "1"), "a") == bc.ACCEPTED
    monkeypatch.setattr(bc, "_insert_match", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret detail")))
    out = c.handle("deposit", body("8", "2"), "a")
    assert out == bc.refused("internal")
    assert b"secret" not in out and b"Traceback" not in out
    assert c.handle("nope", b"{}", "a") == bc.refused("usage")
    for op in ("nonce", "poll", "withdraw"):
        assert c.handle(op, b"not json", "a") == bc.refused("wire")
