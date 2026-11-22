"""PSI initiate: non-completing pairs and the per-pair cooldown.

Two guarantees of /trust/psi/initiate that had no coverage:

1. A pair that cannot complete a PSI — one side blocked the other, or they are
   not both in each other's allowed senders — is answered exactly like a pair
   that can: same status, same top-level response shape. The request leaves no
   usable session behind; the only trace is a sinkhole slot nothing reads.

2. A per-pair cooldown bounds initiations to one recent session in status
   'complete' or 'responded' in either direction, and it is evaluated before
   the completion check — so it answers the same refusal for completing and
   non-completing pairs alike.

Run (from infra/svrnty, with the packages pinned in the Dockerfile plus pytest
and httpx installed):
    python -m pytest test_psi_initiate_sinkhole_cooldown.py -q

Same harness as test_psi_session_parity.py: the sealed-envelope layer is not
under test — _open_psi_sealed is the identity function and _seal_psi_to a stub —
while auth, session storage, the allowed-senders/block reads, and the status
codes are the real code. Time is aged by writing created_at directly; nothing
sleeps.
"""
import base64
import hashlib
import os
import re
import sqlite3
import tempfile
import time
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-psi-sc-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import satellite  # noqa: E402


class Ident:
    """A registered identity with a bound Ed25519 auth key (what verify_request_signature checks)."""

    def __init__(self, name: str):
        self.sk = Ed25519PrivateKey.generate()
        self.fp = hashlib.sha256(name.encode()).hexdigest()
        self.pub_hex = self.sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()

    def sig(self) -> str:
        ts = int(time.time())
        raw = self.sk.sign(f"svrnty-psi-auth:{self.fp}:{ts}".encode())
        return f"{ts}:{base64.b64encode(raw).decode()}"


def response_pub() -> dict:
    x, k = os.urandom(32), os.urandom(1568)
    return {
        "x25519_pub_b64": base64.b64encode(x).decode(),
        "mlkem1024_pub_b64": base64.b64encode(k).decode(),
        "mailbox_fp": hashlib.sha256(x + k).hexdigest(),
    }


COOLDOWN_SECONDS = 86400


def _iso_age(seconds_ago: float) -> str:
    return datetime.fromtimestamp(
        datetime.now(timezone.utc).timestamp() - seconds_ago, timezone.utc
    ).isoformat()


class World:
    def __init__(self, client: TestClient):
        self.client = client
        self.a, self.b, self.c = Ident("a"), Ident("b"), Ident("c")

    def initiate(self, who: Ident, to: Ident):
        return self.client.post("/trust/psi/initiate", json={
            "initiator_fingerprint": who.fp, "responder_fingerprint": to.fp,
            "blinded_set": ["QUJD"], "signature": who.sig(), "response_pub": response_pub()})

    def db(self):
        return sqlite3.connect(str(satellite.DB_PATH))

    def allow(self, owner: Ident, sender: Ident):
        with self.db() as db:
            db.execute(
                "INSERT OR IGNORE INTO allowed_senders (owner_fingerprint, sender_fingerprint, added_at) VALUES (?,?,?)",
                (owner.fp, sender.fp, satellite.now_iso()))
            db.commit()

    def unallow(self, owner: Ident, sender: Ident):
        with self.db() as db:
            db.execute(
                "DELETE FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
                (owner.fp, sender.fp))
            db.commit()

    def block(self, blocker: Ident, blocked: Ident):
        with self.db() as db:
            db.execute(
                "INSERT OR IGNORE INTO blocks (blocker, blocked, created_at) VALUES (?,?,?)",
                (blocker.fp, blocked.fp, satellite.now_iso()))
            db.commit()

    def session_count(self, who: Ident, to: Ident) -> int:
        with self.db() as db:
            return db.execute(
                "SELECT COUNT(*) FROM psi_sessions WHERE (initiator = ? AND responder = ?) OR (initiator = ? AND responder = ?)",
                (who.fp, to.fp, to.fp, who.fp)).fetchone()[0]

    def psi_notice_count(self, responder: Ident) -> int:
        """Rows the genuine path writes to tell the responder a request is waiting; a sinkholed pair must write none."""
        with self.db() as db:
            return db.execute(
                "SELECT COUNT(*) FROM messages WHERE recipient = ? AND sender_fingerprint = 'satellite:psi'",
                (responder.fp,)).fetchone()[0]

    def sinkhole_count(self) -> int:
        with self.db() as db:
            return db.execute("SELECT COUNT(*) FROM psi_sinkhole").fetchone()[0]

    def seed_session(self, who: Ident, to: Ident, status: str, seconds_ago: float):
        with self.db() as db:
            db.execute(
                "INSERT INTO psi_sessions (session_id, initiator, responder, initiator_blinded, initiator_response_pub, status, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (f"sess-{who.fp[:6]}-{to.fp[:6]}-{status}", who.fp, to.fp, "[]", None,
                 status, _iso_age(seconds_ago)))
            db.commit()


@pytest.fixture
def w(monkeypatch, tmp_path):
    monkeypatch.setattr(satellite, "DB_PATH", tmp_path / "satellite.db")
    monkeypatch.setattr(satellite, "RATE_LIMITS", {})  # /trust/psi/initiate is rate-limited; tests make more calls
    monkeypatch.setattr(satellite, "_open_psi_sealed", lambda body: dict(body))
    monkeypatch.setattr(satellite, "_seal_psi_to", lambda result, pub: {"sealed_for_test": True})
    satellite.init_db()
    satellite.init_psi_tables()
    satellite.init_block_table()
    world = World(TestClient(satellite.app))
    db = world.db()
    for i in (world.a, world.b, world.c):
        db.execute("INSERT INTO identities (fingerprint, public_key, registered_at, sig_pubkey) VALUES (?,?,?,?)",
                   (i.fp, base64.b64encode(b"x" * 32).decode(), "2026-11-01T00:00:00+00:00", i.pub_hex))
    db.commit()
    db.close()
    # A and B are mutual: either direction of the pair can complete a PSI.
    world.allow(world.a, world.b)
    world.allow(world.b, world.a)
    return world


def _shape(r):
    """The observable answer shape: status code, body status, top-level key set, value types."""
    j = r.json()
    return (r.status_code, j.get("status"), frozenset(j.keys()), frozenset(type(v) for v in j.values()),
            j.get("message"), bool(re.fullmatch(r"[0-9a-f]{32}", str(j.get("session_id")))))


# ── non-completing pairs ────────────────────────────────────────────────────────────────────────

def test_p1a_noncompleting_initiate_creates_no_session_and_writes_one_sinkhole_slot(w, monkeypatch):
    """A pair that cannot complete leaves no usable session; the only trace is one dead slot."""
    monkeypatch.setattr("secrets.randbelow", lambda n: 0)  # pin the ring writes to one slot so the count is exact
    before_sessions = w.session_count(w.b, w.c)
    before_sink = w.sinkhole_count()
    r = w.initiate(w.b, w.c)  # C is nobody's contact — the pair can never complete
    assert r.status_code == 200
    assert w.session_count(w.b, w.c) == before_sessions, "a non-completing initiate must leave no session row"
    assert w.sinkhole_count() - before_sink == 1, "exactly one new sinkhole slot records the write"


def test_p1b_noncompleting_initiate_answers_with_the_genuine_shape(w):
    """Every non-completing reason answers like a mutual pair whose responder is simply away."""
    d, e, f = Ident("d"), Ident("e"), Ident("f")
    db = w.db()
    for i in (d, e, f):
        db.execute("INSERT INTO identities (fingerprint, public_key, registered_at, sig_pubkey) VALUES (?,?,?,?)",
                   (i.fp, base64.b64encode(b"x" * 32).decode(), "2026-11-01T00:00:00+00:00", i.pub_hex))
    db.commit()
    db.close()

    genuine = _shape(w.initiate(w.b, w.a))
    assert genuine[0] == 200
    # positive control: the genuine path DOES write a session row and a notice, so the zeros below mean something
    assert w.session_count(w.b, w.a) == 1 and w.psi_notice_count(w.a) == 1

    # (i) the responder blocked the initiator — the pair is otherwise fully mutual
    w.allow(w.b, d)
    w.allow(d, w.b)
    w.block(d, w.b)
    blocked = _shape(w.initiate(w.b, d))

    # (ii) the responder removed the initiator from its allowed senders
    w.allow(w.b, e)
    w.allow(e, w.b)
    w.unallow(e, w.b)
    removed = _shape(w.initiate(w.b, e))

    # (iii) the responder never added the initiator
    w.allow(w.b, f)
    never_added = _shape(w.initiate(w.b, f))

    for name, got in (("blocked", blocked), ("removed", removed), ("never-added", never_added)):
        assert got == genuine, f"{name} pair answered differently (status, keys, types, message text, session_id format): {got} vs {genuine}"
    # ...and none of them left anything the responder could act on: no session row, no notice
    for name, other in (("blocked", d), ("removed", e), ("never-added", f)):
        assert w.session_count(w.b, other) == 0, f"{name}: a non-completing initiate must leave no session row"
        assert w.psi_notice_count(other) == 0, f"{name}: a non-completing initiate must not notify the responder"


# ── per-pair cooldown ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", ["responded", "complete"])
def test_p2a_recent_completed_session_refuses_a_new_initiate_in_either_direction(w, status):
    """One session in a completing status inside the window refuses the next initiate, both ways."""
    w.seed_session(w.a, w.b, status, COOLDOWN_SECONDS - 1)
    assert w.initiate(w.b, w.a).status_code == 429
    assert w.initiate(w.a, w.b).status_code == 429


def test_p2b_session_older_than_the_window_does_not_refuse(w):
    """Past the cooldown window a new initiate is accepted again."""
    w.seed_session(w.a, w.b, "responded", COOLDOWN_SECONDS + 1)
    r = w.initiate(w.b, w.a)
    assert r.status_code == 200
    assert r.json()["status"] == "pending"


def test_p2c_cooldown_refuses_even_when_the_pair_can_no_longer_complete(w):
    """The refusal is evaluated before the completion check: a severed pair with a recent
    completing session gets the same 429 a mutual pair would."""
    w.seed_session(w.a, w.b, "responded", COOLDOWN_SECONDS - 1)
    w.unallow(w.a, w.b)  # the pair is non-completing now: A no longer allows B
    assert w.initiate(w.b, w.a).status_code == 429


def test_p2d_pending_session_does_not_trigger_the_cooldown(w):
    """Only completing statuses count: a still-open session does not refuse the next initiate."""
    w.seed_session(w.a, w.b, "pending", COOLDOWN_SECONDS - 1)
    r = w.initiate(w.b, w.a)
    assert r.status_code == 200
    assert r.json()["status"] == "pending"
