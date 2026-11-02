"""/allowed add and remove are ordered by their signed times: a removal always applies, and an add that is not later than the last removal of
the same pair is refused (409), whatever order the requests arrive in.

Run (from infra/svrnty, with the packages pinned in the Dockerfile plus pytest and httpx installed):
    python -m pytest test_allowed_clock.py -q

Everything is the real handler code: the signatures are real Ed25519 over the real preimages, and the checks read the database directly.
"""
import base64
import hashlib
import os
import sqlite3
import tempfile
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-clock-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import satellite  # noqa: E402


class Ident:
    def __init__(self, name: str):
        self.sk = Ed25519PrivateKey.generate()
        self.fp = hashlib.sha256(name.encode()).hexdigest()
        self.pub_hex = self.sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def wire(self, preimage: str, unix: int) -> str:
        return f"{unix}:{base64.b64encode(self.sk.sign(preimage.encode())).decode()}"

    def auth(self) -> str:
        ts = int(time.time())
        return f"{ts}:{base64.b64encode(self.sk.sign(f'svrnty-psi-auth:{self.fp}:{ts}'.encode())).decode()}"


class World:
    def __init__(self, client: TestClient):
        self.client = client
        self.owner, self.s1, self.s2, self.other = Ident("owner"), Ident("s1"), Ident("s2"), Ident("other")
        self.now = int(time.time())

    def add(self, sender: Ident, unix: int, signer: Ident = None):
        signer = signer or self.owner
        return self.client.post(f"/allowed/{self.owner.fp}", json={
            "sender_fingerprint": sender.fp,
            "signature": signer.wire(f"svrnty-allowed-add:{self.owner.fp}:{sender.fp}:{unix}", unix)})

    def add_wire(self, sender: Ident, wire: str):
        return self.client.post(f"/allowed/{self.owner.fp}", json={"sender_fingerprint": sender.fp, "signature": wire})

    def signed_add(self, sender: Ident, unix: int) -> str:
        return self.owner.wire(f"svrnty-allowed-add:{self.owner.fp}:{sender.fp}:{unix}", unix)

    def remove(self, sender: Ident, unix: int, signer: Ident = None):
        signer = signer or self.owner
        return self.client.delete(f"/allowed/{self.owner.fp}/{sender.fp}", headers={
            "X-Signature": signer.wire(f"svrnty-allowed-remove:{self.owner.fp}:{sender.fp}:{unix}", unix)})

    def listed(self):
        r = self.client.get(f"/allowed/{self.owner.fp}", headers={"X-Signature": self.owner.auth()})
        assert r.status_code == 200, r.text
        return r.json()["allowed"]

    def rows(self, table: str, where: str = "1=1", args=()):
        db = sqlite3.connect(str(satellite.DB_PATH))
        try:
            return db.execute(f"SELECT * FROM {table} WHERE {where}", args).fetchall()
        finally:
            db.close()

    def clock(self, sender: Ident):
        r = self.rows("allowed_clock", "owner_fingerprint = ? AND sender_fingerprint = ?", (self.owner.fp, sender.fp))
        return r[0][2] if r else None

    def put_clock(self, sender: Ident, unix: int):
        db = sqlite3.connect(str(satellite.DB_PATH))
        db.execute("INSERT OR REPLACE INTO allowed_clock (owner_fingerprint, sender_fingerprint, last_remove_unix) VALUES (?,?,?)",
                   (self.owner.fp, sender.fp, unix))
        db.commit()
        db.close()


@pytest.fixture
def w(monkeypatch, tmp_path):
    monkeypatch.setattr(satellite, "DB_PATH", tmp_path / "satellite.db")
    monkeypatch.setattr(satellite, "RATE_LIMITS", {})
    satellite.init_db()
    world = World(TestClient(satellite.app))
    db = sqlite3.connect(str(satellite.DB_PATH))
    for i in (world.owner, world.s1, world.s2, world.other):
        db.execute("INSERT INTO identities (fingerprint, public_key, registered_at, sig_pubkey) VALUES (?,?,?,?)",
                   (i.fp, base64.b64encode(b"x" * 32).decode(), "2026-11-01T00:00:00+00:00", i.pub_hex))
    db.commit()
    db.close()
    return world


# ── baseline ─────────────────────────────────────────────────────────────────────────────────────────────────

def test_first_add_with_no_clock_row_works_and_remove_works(w):
    assert w.add(w.s1, w.now).status_code == 200
    assert w.listed() == [w.s1.fp]
    r = w.remove(w.s1, w.now + 1)
    assert r.status_code == 200 and r.json()["status"] == "removed"
    assert w.listed() == []


def test_removing_a_pair_that_is_not_allowed_is_still_404_with_the_same_body(w):
    r = w.remove(w.s1, w.now)
    assert r.status_code == 404
    assert r.json() == {"detail": "Sender not in allowed list"}


# ── the ordering rule ────────────────────────────────────────────────────────────────────────────────────────

def test_an_add_signed_before_a_removal_cannot_bring_the_row_back(w):
    add_wire = w.signed_add(w.s1, w.now)
    assert w.add_wire(w.s1, add_wire).status_code == 200
    assert w.remove(w.s1, w.now + 1).status_code == 200
    late = w.add_wire(w.s1, add_wire)  # the same add arrives again after the removal
    assert late.status_code == 409
    assert late.json() == {"status": "superseded", "sender_fingerprint": w.s1.fp}
    assert w.listed() == []
    assert w.rows("allowed_senders", "sender_fingerprint = ?", (w.s1.fp,)) == []


def test_a_removal_that_arrives_before_the_add_it_follows_still_wins(w):
    assert w.remove(w.s1, w.now + 1).status_code == 404  # no row yet
    assert w.clock(w.s1) == w.now + 1                      # but the removal is recorded
    late = w.add(w.s1, w.now)
    assert late.status_code == 409
    assert w.listed() == []


def test_a_later_add_after_a_removal_is_accepted(w):
    assert w.add(w.s1, w.now).status_code == 200
    assert w.remove(w.s1, w.now + 1).status_code == 200
    assert w.add(w.s1, w.now + 2).status_code == 200
    assert w.listed() == [w.s1.fp]


def test_a_tie_goes_to_the_removal_in_either_arrival_order(w):
    t = w.now
    assert w.remove(w.s1, t).status_code == 404
    assert w.add(w.s1, t).status_code == 409
    assert w.listed() == []
    assert w.add(w.s2, t).status_code == 200
    assert w.remove(w.s2, t).status_code == 200   # a removal is never refused for being old
    assert w.listed() == []


def test_the_clock_keeps_the_latest_removal_time_even_if_an_older_removal_arrives_later(w):
    assert w.remove(w.s1, w.now + 5).status_code == 404
    assert w.remove(w.s1, w.now + 1).status_code == 404
    assert w.clock(w.s1) == w.now + 5
    assert w.add(w.s1, w.now + 3).status_code == 409


def test_a_removal_from_a_slow_clock_is_not_lost(w):
    assert w.add(w.s1, w.now + 20).status_code == 200      # a device whose clock runs fast
    r = w.remove(w.s1, w.now - 20)                          # a device whose clock runs slow, later in real time
    assert r.status_code == 200
    assert w.listed() == []


def test_RESIDUAL_a_captured_add_from_a_fast_clock_can_return_after_a_slow_clock_removal(w):
    """Named, not fixed here: when the removal's signed time is EARLIER than an add's, a copy of that add still inside its 30 s
    window is not refused. The window is the only bound; the ordering rule cannot see which request was really first."""
    add_wire = w.signed_add(w.s1, w.now + 20)
    assert w.add_wire(w.s1, add_wire).status_code == 200
    assert w.remove(w.s1, w.now - 20).status_code == 200
    assert w.add_wire(w.s1, add_wire).status_code == 200


def test_an_add_inside_the_30s_window_is_refused_while_its_removal_row_is_live(w):
    assert w.remove(w.s1, w.now - 25).status_code == 404
    assert w.add(w.s1, w.now - 26).status_code == 409
    assert w.add(w.s1, w.now - 25).status_code == 409


def test_pairs_are_independent(w):
    assert w.remove(w.s1, w.now + 5).status_code == 404
    assert w.add(w.s2, w.now).status_code == 200
    assert w.listed() == [w.s2.fp]


# ── the unauthenticated cannot write the clock ───────────────────────────────────────────────────────────────

def test_a_removal_with_the_wrong_key_changes_neither_table(w):
    assert w.add(w.s1, w.now).status_code == 200
    r = w.remove(w.s1, w.now + 1, signer=w.other)
    assert r.status_code == 403
    assert w.clock(w.s1) is None
    assert w.listed() == [w.s1.fp]


def test_an_add_with_the_wrong_key_is_refused_before_any_clock_check(w):
    assert w.remove(w.s1, w.now + 5).status_code == 404
    assert w.add(w.s1, w.now + 9, signer=w.other).status_code == 403
    assert w.listed() == []


def test_adding_yourself_is_still_refused(w):
    r = w.client.post(f"/allowed/{w.owner.fp}", json={
        "sender_fingerprint": w.owner.fp,
        "signature": w.owner.wire(f"svrnty-allowed-add:{w.owner.fp}:{w.owner.fp}:{w.now}", w.now)})
    assert r.status_code == 400


# ── expiry: the table does not keep a record of who was removed ──────────────────────────────────────────────

def test_clock_rows_older_than_120s_are_gone_after_the_next_allowed_operation(w):
    w.put_clock(w.s1, int(time.time()) - 200)
    assert w.clock(w.s1) is not None
    assert w.add(w.s2, w.now).status_code == 200      # any allowed operation prunes
    assert w.clock(w.s1) is None


def test_the_prune_boundary_keeps_a_row_younger_than_120s_and_drops_one_older(w):
    w.put_clock(w.s1, int(time.time()) - 100)
    w.put_clock(w.s2, int(time.time()) - 140)
    assert w.add(w.other, w.now).status_code == 200
    assert w.clock(w.s1) is not None
    assert w.clock(w.s2) is None


def test_a_removal_prunes_too(w):
    w.put_clock(w.s2, int(time.time()) - 500)
    assert w.remove(w.s1, w.now).status_code == 404
    assert w.clock(w.s2) is None
    assert w.clock(w.s1) == w.now


def test_a_refused_add_still_commits_the_prune(w):
    assert w.remove(w.s1, w.now + 5).status_code == 404
    w.put_clock(w.s2, int(time.time()) - 500)          # planted AFTER the removal, so only the refused add can prune it
    assert w.add(w.s1, w.now).status_code == 409
    assert w.clock(w.s2) is None


def test_a_pruned_pair_can_be_added_again(w):
    w.put_clock(w.s1, int(time.time()) - 500)
    assert w.add(w.s1, w.now - 29).status_code == 200


# ── the readers see no change ────────────────────────────────────────────────────────────────────────────────

def test_a_removed_pair_is_in_no_allowed_list_and_the_clock_is_a_separate_table(w):
    assert w.add(w.s1, w.now).status_code == 200
    assert w.remove(w.s1, w.now + 1).status_code == 200
    assert w.listed() == []
    cols = [c[1] for c in sqlite3.connect(str(satellite.DB_PATH)).execute("PRAGMA table_info(allowed_senders)").fetchall()]
    assert cols == ["id", "owner_fingerprint", "sender_fingerprint", "added_at"]


# ── identity delete ──────────────────────────────────────────────────────────────────────────────────────────

def test_deleting_an_identity_drops_its_clock_rows_as_owner_and_as_sender(w):
    assert w.remove(w.s1, w.now).status_code == 404         # clock row (owner, s1)
    w.put_clock(w.other, int(time.time()))                  # a row where s1 is the owner is made below
    db = sqlite3.connect(str(satellite.DB_PATH))
    db.execute("INSERT INTO allowed_clock (owner_fingerprint, sender_fingerprint, last_remove_unix) VALUES (?,?,?)",
               (w.s1.fp, w.other.fp, int(time.time())))
    db.commit()
    db.close()
    r = w.client.request("DELETE", f"/identity/{w.s1.fp}", json={
        "fingerprint": w.s1.fp, "signature": w.s1.auth(), "confirm": "DELETE_MY_IDENTITY"})
    assert r.status_code == 200, r.text
    assert w.rows("allowed_clock", "owner_fingerprint = ? OR sender_fingerprint = ?", (w.s1.fp, w.s1.fp)) == []
    assert w.clock(w.other) is not None                     # an unrelated pair is kept


# ── one transaction: the order check and the write cannot be separated by another writer ─────────────────────

class _Rec(sqlite3.Connection):
    """Records every statement so a test can see WHEN the transaction began relative to the reads and writes of the two tables."""
    log: list = []

    def execute(self, sql, *args, **kwargs):
        _Rec.log.append(" ".join(sql.split()))
        return super().execute(sql, *args, **kwargs)


def _recording_get_db():
    db = sqlite3.connect(str(satellite.DB_PATH), factory=_Rec)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def _begin_precedes_every_table_statement(log):
    assert "BEGIN IMMEDIATE" in log, f"no BEGIN IMMEDIATE in {log}"
    begin = log.index("BEGIN IMMEDIATE")
    touching = [i for i, s in enumerate(log) if "allowed_clock" in s or "allowed_senders" in s]
    assert touching, "the handler touched neither table"
    assert all(i > begin for i in touching), f"a table statement ran before the transaction began: {log}"
    assert log.count("BEGIN IMMEDIATE") == 1


def test_add_checks_and_writes_inside_one_immediate_transaction(w, monkeypatch):
    monkeypatch.setattr(satellite, "get_db", _recording_get_db)
    _Rec.log = []
    assert w.add(w.s1, w.now).status_code == 200
    _begin_precedes_every_table_statement(_Rec.log)


def test_a_refused_add_also_checks_inside_the_transaction(w, monkeypatch):
    assert w.remove(w.s1, w.now + 5).status_code == 404
    monkeypatch.setattr(satellite, "get_db", _recording_get_db)
    _Rec.log = []
    assert w.add(w.s1, w.now).status_code == 409
    _begin_precedes_every_table_statement(_Rec.log)


def test_remove_records_and_deletes_inside_one_immediate_transaction(w, monkeypatch):
    assert w.add(w.s1, w.now).status_code == 200
    monkeypatch.setattr(satellite, "get_db", _recording_get_db)
    _Rec.log = []
    assert w.remove(w.s1, w.now + 1).status_code == 200
    _begin_precedes_every_table_statement(_Rec.log)
