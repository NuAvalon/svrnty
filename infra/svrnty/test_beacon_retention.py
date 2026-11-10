"""Mutual-trust beacon: closed epochs are deleted, only if switched on (dark). Run from infra/svrnty: python3 -m pytest -q test_beacon_retention.py

The match table is a record of who bonded with whom, so rows go once their epoch can never be used again. This deletes data, so the code
default is OFF. Real SQLite files throughout; the verifier and the authenticator are test seams.
"""
import json
import os
import sqlite3
import sys

import pytest

import beacon_centurion as bc

WEEK = bc.EPOCH_SECONDS
E = 2900


def at(epoch, seconds=5):
    return epoch * WEEK + seconds


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


class FakeVerifier:
    def __call__(self, raw, now):
        return json.loads(raw)["_t"]


def dep(c, epoch, slot, n, k="9"):
    c.clk.t = max(c.clk.t, at(epoch))
    return c.deposit(json.dumps({"_t": {"ok": True, "e": str(epoch), "H_e": slot, "N": n, "K": k}}).encode(), "10.0.0.1")


def new(path, t=None):
    clk = Clock(at(E) if t is None else t)
    c = bc.Centurion(str(path), verifier=FakeVerifier(), clock=clk, per_epoch_cap=100_000, ip_per_minute=1_000_000)
    c.clk = clk
    return c


@pytest.fixture
def cen(tmp_path):
    return new(tmp_path / "beacon.db")


def count(c, table, where="1=1", args=()):
    with sqlite3.connect(c.db_path) as db:
        return db.execute(f"SELECT count(*) FROM {table} WHERE {where}", args).fetchone()[0]


def epochs(c, table):
    with sqlite3.connect(c.db_path) as db:
        return sorted(r[0] for r in db.execute(f"SELECT DISTINCT epoch FROM {table}"))


# ---- off by default ----------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("raw", [None, "", "0"])
def test_unset_or_zero_is_off_with_no_refusal(raw):
    assert bc.parse_retention_interval(raw) == (0, None)


@pytest.mark.parametrize("raw,want", [("60", 60), ("3600", 3600), ("86400", 86400)])
def test_a_valid_interval_is_read(raw, want):
    assert bc.parse_retention_interval(raw) == (want, None)


@pytest.mark.parametrize("raw", ["59", "1", "-1", "1e3", " 60", "60 ", "0x40", "abc", "٦٠", "99999999999", "60.0"])
def test_anything_else_is_off_with_a_refusal(raw):
    interval, refusal = bc.parse_retention_interval(raw)
    assert interval == 0 and refusal


def test_nothing_is_deleted_unless_purge_is_called(tmp_path):
    c = new(tmp_path / "beacon.db")
    dep(c, E, "11", "1")
    c.clk.t = at(E + 50)
    new_again = bc.Centurion(c.db_path, verifier=FakeVerifier(), clock=c.clk, per_epoch_cap=100_000, ip_per_minute=1_000_000)
    assert count(new_again, "beacon_deposits") == 1            # starting up with old rows on disk deletes nothing


def test_the_retention_loop_only_runs_when_started():
    calls = []

    class Stop(Exception):
        pass

    class Cen:
        def purge_closed(self):
            calls.append(1)
            return {"last_purge_at": "x", "deposits_deleted": 0, "matches_deleted": 0, "scrubbed": True}

    sleeps = []

    def sleep(s):
        sleeps.append(s)
        if len(sleeps) == 3:
            raise Stop

    with pytest.raises(Stop):
        bc.retention_loop(Cen(), 120, sleep=sleep, jitter=lambda a, b: 7)
    assert calls == [1, 1] and sleeps == [7, 120, 120]


def test_the_retention_loop_survives_a_failed_purge(capsys):
    class Stop(Exception):
        pass

    class Cen:
        n = 0

        def purge_closed(self):
            Cen.n += 1
            raise RuntimeError("slot 12345 secret detail")

    seen = []

    def sleep(s):
        seen.append(s)
        if len(seen) == 3:
            raise Stop

    with pytest.raises(Stop):
        bc.retention_loop(Cen(), 120, sleep=sleep, jitter=lambda a, b: 0)
    assert Cen.n == 2
    assert "12345" not in capsys.readouterr().out                 # nothing about a row is printed


# ---- what goes and what stays ------------------------------------------------------------------------------------------------
def test_closed_epochs_go_and_the_open_one_stays(cen):
    for e in (E, E + 1, E + 2):
        dep(cen, e, f"{e}1", "1")
        dep(cen, e, f"{e}1", "2")                                 # a match in every epoch
    cen.clk.t = at(E + 2, 3 * 3600)
    out = cen.purge_closed()
    assert epochs(cen, "beacon_deposits") == [E + 2] and epochs(cen, "beacon_matches") == [E + 2]
    assert out["deposits_deleted"] == 4 and out["matches_deleted"] == 2


@pytest.mark.parametrize("seconds,expect", [(0, [E, E + 1]), (600, [E, E + 1]), (600 + 3599, [E, E + 1]), (600 + 3600, [E + 1])])
def test_the_margin_keeps_an_epoch_for_an_hour_past_its_grace(cen, seconds, expect):
    dep(cen, E, "11", "1")
    dep(cen, E + 1, "22", "1")
    cen.clk.t = (E + 1) * WEEK + seconds
    cen.purge_closed()
    assert epochs(cen, "beacon_deposits") == expect


def test_a_deposit_for_the_next_epoch_is_never_touched(cen):
    dep(cen, E, "11", "1")
    cen.clk.t = at(E + 1) - 100                                    # last 600 s of E: E+1 is open
    with sqlite3.connect(cen.db_path) as db:
        db.execute("INSERT INTO beacon_deposits (epoch, slot, n, k, accepted_at) VALUES (?, '33', '1', '9', 'x')", (E + 1,))
    cen.purge_closed()
    assert epochs(cen, "beacon_deposits") == [E, E + 1]


def test_totals_keep_only_counts(cen):
    dep(cen, E, "11", "1")
    dep(cen, E, "11", "2")
    dep(cen, E, "22", "3")
    assert cen._act("withdraw", "22", "3", "9", "t") == bc.WITHDRAWN
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("SELECT epoch, deposits, matches, withdrawn FROM beacon_epoch_totals").fetchall() == [(E, 3, 1, 1)]
        cols = [r[1] for r in db.execute("PRAGMA table_info(beacon_epoch_totals)")]
    assert cols == ["epoch", "deposits", "matches", "withdrawn"]  # no slot, nullifier, key or time


def test_totals_add_up_if_an_epoch_is_purged_twice(cen):
    dep(cen, E, "11", "1")
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    with sqlite3.connect(cen.db_path) as db:
        db.execute("INSERT INTO beacon_deposits (epoch, slot, n, k, accepted_at) VALUES (?, '22', '2', '9', 'x')", (E,))
    cen.purge_closed()
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("SELECT deposits FROM beacon_epoch_totals WHERE epoch = ?", (E,)).fetchone() == (2,)


def test_a_second_purge_changes_nothing(cen):
    dep(cen, E, "11", "1")
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    out = cen.purge_closed()
    assert out["deposits_deleted"] == 0 and out["matches_deleted"] == 0
    with sqlite3.connect(cen.db_path) as db:
        assert db.execute("SELECT deposits FROM beacon_epoch_totals").fetchall() == [(1,)]


def test_a_failed_purge_deletes_nothing_and_says_so(cen):
    dep(cen, E, "11", "1")
    dep(cen, E, "11", "2")
    with sqlite3.connect(cen.db_path) as db:
        db.execute("CREATE TRIGGER block_it BEFORE DELETE ON beacon_matches BEGIN SELECT RAISE(ABORT, 'no'); END")
    cen.clk.t = at(E + 3)
    with pytest.raises(sqlite3.Error):
        cen.purge_closed()
    assert count(cen, "beacon_deposits") == 2 and count(cen, "beacon_matches") == 1 and count(cen, "beacon_epoch_totals") == 0
    assert cen.retention_status()["scrubbed"] is False


def test_security_alarms_are_never_purged(cen):
    dep(cen, E, "11", "1")
    dep(cen, E, "11", "2")
    dep(cen, E, "11", "3")                                         # a third nullifier at a full slot
    assert count(cen, "beacon_security_alarms") == 1
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    assert count(cen, "beacon_security_alarms") == 1


# ---- the cap counter and the open epoch ---------------------------------------------------------------------------------------
def test_the_cap_counter_is_right_after_a_purge_and_a_restart(cen):
    dep(cen, E, "11", "1")
    dep(cen, E + 2, "22", "1")
    dep(cen, E + 2, "33", "1")
    cen.clk.t = at(E + 2, 3 * 3600)
    with sqlite3.connect(cen.db_path) as db:
        before = cen._open_count(db, cen.clk.t)
    cen.purge_closed()
    assert epochs(cen, "beacon_epoch_counts") == [E + 2]
    with sqlite3.connect(cen.db_path) as db:
        assert cen._open_count(db, cen.clk.t) == before == 2
    again = bc.Centurion(cen.db_path, verifier=FakeVerifier(), clock=cen.clk, per_epoch_cap=100_000, ip_per_minute=1_000_000)
    with sqlite3.connect(cen.db_path) as db:
        assert again._open_count(db, cen.clk.t) == 2
        assert db.execute("SELECT n FROM beacon_epoch_counts WHERE epoch = ?", (E + 2,)).fetchone() == (2,)


def test_the_open_epoch_behaves_the_same_after_a_purge(cen):
    dep(cen, E, "11", "1")
    cen.clk.t = at(E + 2, 3 * 3600)
    cen.purge_closed()
    assert dep(cen, E + 2, "55", "1") == bc.ACCEPTED
    assert dep(cen, E + 2, "55", "1") == bc.ALREADY                # the replay check holds
    assert dep(cen, E + 2, "55", "2") == bc.ACCEPTED              # completes the bond
    assert cen._act("poll", "55", "1", "9", "t") == bc.MATCH
    assert dep(cen, E + 2, "55", "3") == bc.ACCEPTED              # third nullifier: alarm, stored nowhere else
    assert count(cen, "beacon_security_alarms") == 1 and count(cen, "beacon_deposits", "slot = '55'") == 2


def auth_stub(tmp_path):
    p = tmp_path / "auth_ok.py"
    p.write_text("import sys\nsys.stdin.read()\nsys.stdout.write('{\"ok\":true}\\n')\n")
    return [sys.executable, str(p)]


@pytest.mark.parametrize("op", ["poll", "withdraw"])
def test_a_purged_row_looks_exactly_like_one_that_never_existed(tmp_path, op):
    clk = Clock(at(E))
    c = bc.Centurion(str(tmp_path / "beacon.db"), verifier=FakeVerifier(), clock=clk, per_epoch_cap=1000, ip_per_minute=100000, auth_cmd=auth_stub(tmp_path))
    c.clk = clk
    dep(c, E, "11", "1")
    dep(c, E, "11", "2")
    clk.t = at(E + 3)
    c.purge_closed()

    def ask(slot, n):
        nonce = json.loads(c.nonce(json.dumps({"op": op, "H_e": slot, "N": n}).encode(), "10.0.0.2"))["nonce"]
        return getattr(c, op)(json.dumps({"H_e": slot, "N": n, "pk": "a" * 64, "sig": "b" * 128, "nonce": nonce}).encode(), "10.0.0.2")

    assert ask("11", "1") == ask("99", "98") == bc.refused("auth")


# ---- the bytes, not only the rows --------------------------------------------------------------------------------------------
def on_disk(c):
    out = b""
    for p in (c.db_path, c.db_path + "-wal"):
        if os.path.exists(p):
            with open(p, "rb") as f:
                out += f.read()
    return out


def test_every_connection_zeroes_what_it_frees(cen):
    db = cen._db()
    try:
        assert db.execute("PRAGMA secure_delete").fetchone()[0] == 1
    finally:
        db.close()


def test_every_connection_asks_for_it_itself(cen, monkeypatch):
    """Some SQLite builds default secure_delete on and some don't, so the setting is pinned by what the code asks for, not by reading it back."""
    real, opened = sqlite3.connect, []

    class Spy:
        def __init__(self, conn):
            self.conn, self.sql = conn, []
            opened.append(self)

        def execute(self, sql, *a):
            self.sql.append(sql)
            return self.conn.execute(sql, *a)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    monkeypatch.setattr(bc.sqlite3, "connect", lambda *a, **k: Spy(real(*a, **k)))
    dep(cen, E, "11", "1")
    assert cen._act("withdraw", "11", "1", "9", "t") == bc.WITHDRAWN
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    assert len(opened) >= 4 and all("PRAGMA secure_delete=ON" in c.sql for c in opened)


def test_deleted_slots_and_nullifiers_are_gone_from_the_file(cen):
    slots = [f"7{i:039d}" for i in range(500)]              # enough to split pages
    nulls = [f"8{i:039d}" for i in range(500)]
    for s, n in zip(slots, nulls):
        dep(cen, E, s, n)
    assert cen._act("withdraw", slots[3], nulls[3], "9", "t") == bc.WITHDRAWN      # an UPDATE that rewrites a cell
    keep_s, keep_n = "6" * 40, "5" * 40
    dep(cen, E + 3, keep_s, keep_n)
    cen.clk.t = at(E + 3, 3 * 3600)
    out = cen.purge_closed()
    assert out["scrubbed"] is True
    blob = on_disk(cen)
    assert keep_n.encode() in blob                                 # the scan can see a row that is still there
    assert not [x for x in slots + nulls if x.encode() in blob]


def test_the_wal_is_empty_after_a_scrub(cen):
    dep(cen, E, "11", "1")
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    wal = cen.db_path + "-wal"
    assert not os.path.exists(wal) or os.path.getsize(wal) == 0     # SQLite removes it when the last connection closes


def test_the_wal_really_is_truncated_while_another_connection_is_open(cen):
    """With no other connection open, SQLite drops the WAL by itself on the last close, so that case can't show the truncate happened."""
    dep(cen, E, "11", "1")
    idle = sqlite3.connect(cen.db_path, isolation_level=None)
    try:
        idle.execute("SELECT count(*) FROM beacon_deposits").fetchone()
        cen.clk.t = at(E + 3)
        assert cen.purge_closed()["scrubbed"] is True
        assert os.path.getsize(cen.db_path + "-wal") == 0
    finally:
        idle.close()


@pytest.mark.parametrize("row,want", [((0, 0, 0), True), ((1, 0, 0), False), ((0, 3, 3), False), ((1, 3, 1), False)])
def test_scrubbed_needs_both_busy_and_log_clear(cen, monkeypatch, row, want):
    class Fake:
        def execute(self, sql, *a):
            return self

        def fetchone(self):
            return row

        def close(self):
            pass

    monkeypatch.setattr(cen, "_db", Fake)
    assert cen._scrub() is want


def test_a_reader_blocking_the_checkpoint_is_reported_then_retried(cen):
    dep(cen, E, "11", "1")
    dep(cen, E + 3, "22", "1")
    reader = sqlite3.connect(cen.db_path, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM beacon_deposits").fetchone()
    cen.clk.t = at(E + 3, 3 * 3600)
    assert cen.purge_closed()["scrubbed"] is False
    assert cen.retention_status()["scrubbed"] is False
    reader.execute("COMMIT")
    reader.close()
    out = cen.purge_closed()                                       # no rows left to delete, still scrubs
    assert out["deposits_deleted"] == 0 and out["scrubbed"] is True


# ---- what the operator sees ---------------------------------------------------------------------------------------------------
def test_status_before_any_purge(cen):
    assert cen.retention_status() == {"interval_s": 0, "last_purge_at": None, "deposits_deleted": 0, "matches_deleted": 0, "scrubbed": None,
                                      "totals": {"deposits": 0, "matches": 0, "withdrawn": 0}}


def test_status_after_a_purge_is_counts_only(cen):
    dep(cen, E, "1234567", "7654321")
    cen.clk.t = at(E + 3)
    cen.purge_closed()
    s = cen.retention_status()
    assert s["deposits_deleted"] == 1 and s["scrubbed"] is True and s["totals"]["deposits"] == 1 and s["last_purge_at"]
    assert "1234567" not in json.dumps(s) and "7654321" not in json.dumps(s)
