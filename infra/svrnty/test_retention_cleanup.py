"""Scheduled retention cleanup: OFF by default, same cutoffs as the admin routes, single-flight, dead-man stamp.
Run from infra/svrnty:  python3 -m pytest -q test_retention_cleanup.py

A feature that deletes data ships OFF: the task starts only when SATELLITE_CLEANUP_INTERVAL_S > 0."""
import asyncio, json, os, stat, tempfile
from datetime import datetime, timedelta, timezone

os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-cleanup-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
os.environ.setdefault("SATELLITE_ADMIN_KEY", "test-admin-key-0123456789abcdef")
os.environ.pop("SATELLITE_CLEANUP_INTERVAL_S", None)  # the default under test: unset

import pytest
import satellite  # noqa: E402
from fastapi.testclient import TestClient

satellite.init_db()
satellite.init_psi_tables()
TTL = satellite.UNDELIVERED_MSG_TTL_SECONDS
RET = satellite.RETENTION_DAYS * 86400
PSI = satellite.PSI_SESSION_TTL


def _seed(now, margin=1):
    """Rows on both sides of every cutoff (±margin s). Returns ids by name."""
    db = satellite.get_db()
    try:
        return _seed_rows(db, now, margin)
    finally:
        db.close()


def _seed_rows(db, now, m):
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("DELETE FROM messages")
    db.execute("DELETE FROM psi_sessions")
    iso = lambda s: (now - timedelta(seconds=s)).isoformat()
    ids = {}
    for name, created, retrieved, retrieved_at in [
        ("unacked_old", iso(TTL + m), 0, None), ("unacked_new", iso(TTL - m), 0, None),
        ("collected_old", iso(RET + 100), 1, iso(RET + m)), ("collected_new", iso(RET + 100), 1, iso(RET - m)),
    ]:
        cur = db.execute("INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at, retrieved, retrieved_at) "
                         "VALUES ('r', 's', 'blob', ?, ?, ?)", (created, retrieved, retrieved_at))
        ids[name] = cur.lastrowid
    for sid, created, status in [("psi_old", iso(PSI + m), "complete"), ("psi_new", iso(PSI - m), "complete"),
                                 ("psi_old_other_status", iso(PSI + m), "failed")]:
        db.execute("INSERT INTO psi_sessions (session_id, initiator, responder, initiator_blinded, status, created_at) "
                   "VALUES (?, 'a', ?, 'x', ?, ?)", (sid, "b-" + sid, status, created))
    db.commit()
    return ids


def _left():
    db = satellite.get_db()
    m = {r[0] for r in db.execute("SELECT id FROM messages")}
    p = {r[0] for r in db.execute("SELECT session_id FROM psi_sessions")}
    db.close()
    return m, p


@pytest.mark.parametrize("raw,want", [(None, 0), ("", 0), ("0", 0), ("-5", 0), ("abc", 0), (" 86400 ", 86400), ("3600", 3600), ("1", 3600), ("59", 3600)])
def test_interval_parse_defaults_off(raw, want):
    assert satellite._parse_cleanup_interval(raw) == want


def test_module_default_is_off():
    assert satellite.CLEANUP_INTERVAL_S == 0


def test_unset_env_starts_no_task_and_deletes_nothing(monkeypatch):
    ids = _seed(datetime.now(timezone.utc))
    started = []
    async def fake_loop(*a, **k):
        started.append(a)
    monkeypatch.setattr(satellite, "_retention_cleanup_loop", fake_loop)
    with TestClient(satellite.app):
        pass
    assert started == []
    m, p = _left()
    assert m == set(ids.values()) and p == {"psi_old", "psi_new", "psi_old_other_status"}


def test_enabled_env_starts_the_task(monkeypatch):
    started = []
    async def fake_loop(interval_s, first_delay_s):
        started.append((interval_s, first_delay_s))
    monkeypatch.setattr(satellite, "_retention_cleanup_loop", fake_loop)
    monkeypatch.setattr(satellite, "CLEANUP_INTERVAL_S", 3600)
    with TestClient(satellite.app):
        pass
    assert len(started) == 1 and started[0][0] == 3600 and 0 <= started[0][1] <= 600


def test_helpers_respect_cutoffs_exactly():
    now = datetime.now(timezone.utc)
    ids = _seed(now)
    db = satellite.get_db()
    assert satellite._purge_unacknowledged(db, now=now) == 1
    assert satellite._purge_retained(db, now=now) == (1, 1)
    db.commit(); db.close()
    m, p = _left()
    assert m == {ids["unacked_new"], ids["collected_new"]}
    assert p == {"psi_new", "psi_old_other_status"}


def test_scheduled_run_matches_the_routes_and_stamps():
    ids = _seed(datetime.now(timezone.utc), margin=60)  # real clock: ±60 s around each cutoff
    stamp = asyncio.run(satellite.run_retention_cleanup())
    assert stamp["ok"] is True and stamp["counts"] == {"unacknowledged": 1, "retained": 1, "psi_sessions": 1}
    m, _ = _left()
    assert ids["unacked_old"] not in m and ids["collected_old"] not in m
    path = satellite.DATA_DIR / satellite.CLEANUP_STAMP_NAME
    assert json.loads(path.read_text())["ok"] is True
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_failing_run_stamps_not_ok_and_does_not_raise(monkeypatch):
    def boom():
        raise sqlite3_error()
    class sqlite3_error(Exception):
        pass
    monkeypatch.setattr(satellite, "get_db", boom)
    stamp = asyncio.run(satellite.run_retention_cleanup())
    assert stamp["ok"] is False
    monkeypatch.undo()
    assert json.loads((satellite.DATA_DIR / satellite.CLEANUP_STAMP_NAME).read_text())["ok"] is False


def test_single_flight():
    async def go():
        await satellite._cleanup_lock.acquire()
        try:
            return await satellite.run_retention_cleanup()
        finally:
            satellite._cleanup_lock.release()
    assert asyncio.run(go()) == {"skipped": True}


def test_routes_still_require_the_key_and_use_the_helpers():
    ids = _seed(datetime.now(timezone.utc), margin=60)
    with TestClient(satellite.app) as c:
        assert c.post("/msg/cleanup").status_code == 403
        assert c.post("/admin/cleanup", headers={"X-Admin-Key": "wrong-key-0123456789abcdef"}).status_code == 403
        k = {"X-Admin-Key": os.environ["SATELLITE_ADMIN_KEY"]}
        assert c.post("/msg/cleanup", headers=k).json()["purged"] == 1
        r = c.post("/admin/cleanup", headers=k).json()
        assert r["deleted"] == 1 and r["psi_deleted"] == 1
    m, _ = _left()
    assert m == {ids["unacked_new"], ids["collected_new"]}


def test_stamp_write_refuses_a_planted_symlink_and_leaves_no_temp(tmp_path, monkeypatch):
    monkeypatch.setattr(satellite, "DATA_DIR", tmp_path)
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / (satellite.CLEANUP_STAMP_NAME + ".tmp")).symlink_to(victim)  # the old fixed temp name
    satellite._write_cleanup_stamp({"ts": "2026-11-02T00:00:00+00:00", "ok": True, "counts": {}})
    assert json.loads((tmp_path / satellite.CLEANUP_STAMP_NAME).read_text())["ok"] is True
    assert victim.read_text() == "keep"
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp") and not p.is_symlink()] == []


def test_stamp_carries_no_error_text(monkeypatch):
    class Boom(Exception):
        pass
    def boom():
        raise Boom("mailbox_fp=deadbeef secret detail")
    monkeypatch.setattr(satellite, "get_db", boom)
    stamp = asyncio.run(satellite.run_retention_cleanup())
    assert set(stamp) == {"ts", "ok", "counts"} and "deadbeef" not in json.dumps(stamp)


def test_live_writer_is_not_locked_out_during_a_big_purge():
    import threading
    now = datetime.now(timezone.utc)
    db = satellite.get_db()
    db.execute("PRAGMA foreign_keys=OFF")
    db.execute("DELETE FROM messages")
    old = (now - timedelta(seconds=TTL + 3600)).isoformat()
    db.executemany("INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES ('r','s',?,?)",
                   [("x" * 512, old) for _ in range(20000)])
    db.commit(); db.close()
    errors, written = [], []
    def writer():
        for i in range(200):
            try:
                w = satellite.get_db(); w.execute("PRAGMA foreign_keys=OFF")
                w.execute("INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES ('live','s','b',?)",
                          (datetime.now(timezone.utc).isoformat(),))
                w.commit(); w.close(); written.append(i)
            except Exception as e:
                errors.append(type(e).__name__)
    th = threading.Thread(target=writer)
    th.start()
    stamp = asyncio.run(satellite.run_retention_cleanup())
    th.join()
    assert errors == [] and len(written) == 200
    assert stamp["ok"] is True and stamp["counts"]["unacknowledged"] == 20000
    db = satellite.get_db()
    assert db.execute("SELECT count(*) FROM messages WHERE recipient='live'").fetchone()[0] == 200
    db.close()


@pytest.mark.parametrize("ttl,ret", [(0, 30), (-1, 30), (30, -1)])
def test_bad_cutoffs_refuse_to_start_and_delete_nothing(monkeypatch, ttl, ret):
    ids = _seed(datetime.now(timezone.utc), margin=60)
    started = []
    async def fake_loop(*a, **k):
        started.append(a)
    monkeypatch.setattr(satellite, "_retention_cleanup_loop", fake_loop)
    monkeypatch.setattr(satellite, "CLEANUP_INTERVAL_S", 86400)
    monkeypatch.setattr(satellite, "UNDELIVERED_MSG_TTL_DAYS", ttl)
    monkeypatch.setattr(satellite, "RETENTION_DAYS", ret)
    assert satellite._cleanup_start_refusal() is not None
    with TestClient(satellite.app):
        pass
    assert started == []
    m, _ = _left()
    assert m == set(ids.values())


def test_sane_cutoffs_allow_start():
    assert satellite._cleanup_start_refusal() is None
