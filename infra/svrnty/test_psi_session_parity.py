"""PSI session endpoints: a session id the caller cannot use is answered exactly like one that does not exist.

/trust/psi/initiate returns the same 200-pending shape whether or not it created a session row. These tests compare the
responses of the session endpoints (cancel, /blinded, /respond, /result) for an id that names no session against the id
of a genuine pending session, for the same caller, and check that cancel deletes only the caller's own sessions.

Run (from infra/svrnty, with the packages pinned in the Dockerfile plus pytest and httpx installed):
    python -m pytest test_psi_session_parity.py -q

The sealed envelope layer is not under test here: _open_psi_sealed is replaced by the identity function so a test can send
the inner fields directly, and _seal_psi_to (ML-KEM, needs liboqs) by a stub so a successful reply can be returned without it.
Everything else (auth, the session lookup, the status codes, the writes) is the real code.
"""
import base64
import hashlib
import os
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

# The module reads its data directory at import time.
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-psi-test-")
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


class World:
    def __init__(self, client: TestClient):
        self.client = client
        self.a, self.b, self.c = Ident("a"), Ident("b"), Ident("c")

    # -- the endpoints, as a caller (a modified client can send any of these) --------------------------------
    def initiate(self, who: Ident, to: Ident):
        return self.client.post("/trust/psi/initiate", json={
            "initiator_fingerprint": who.fp, "responder_fingerprint": to.fp,
            "blinded_set": ["QUJD"], "signature": who.sig(), "response_pub": response_pub()})

    def cancel(self, who: Ident, sid: str):
        return self.client.request("DELETE", f"/trust/psi/session/{sid}",
                                   params={"fingerprint": who.fp}, headers={"X-Signature": who.sig()})

    def blinded(self, who: Ident, sid: str):
        return self.client.post(f"/trust/psi/session/{sid}/blinded", json={
            "responder_fingerprint": who.fp, "signature": who.sig(), "response_pub": response_pub()})

    def respond(self, who: Ident, sid: str):
        return self.client.post(f"/trust/psi/session/{sid}/respond", json={
            "responder_fingerprint": who.fp, "responder_blinded_set": ["QQ=="],
            "reblinded_initiator_set": ["QQ=="], "signature": who.sig()})

    def result(self, who: Ident, sid: str):
        return self.client.get(f"/trust/psi/session/{sid}/result",
                               params={"fingerprint": who.fp}, headers={"X-Signature": who.sig()})

    # -- the two kinds of session id B can hold ---------------------------------------------------------------
    def genuine(self) -> str:
        """B starts a request to A, who is mutual with B: a real pending session."""
        r = self.initiate(self.b, self.a)
        assert r.status_code == 200, r.text
        return r.json()["session_id"]

    def unmade(self) -> str:
        """B starts a request to C, who is not mutual with B: the id comes back but no session row is made."""
        r = self.initiate(self.b, self.c)
        assert r.status_code == 200, r.text
        return r.json()["session_id"]

    def session_rows(self, sid: str) -> int:
        db = sqlite3.connect(str(satellite.DB_PATH))
        try:
            return db.execute("SELECT COUNT(*) FROM psi_sessions WHERE session_id = ?", (sid,)).fetchone()[0]
        finally:
            db.close()


@pytest.fixture
def w(monkeypatch, tmp_path):
    monkeypatch.setattr(satellite, "DB_PATH", tmp_path / "satellite.db")
    monkeypatch.setattr(satellite, "RATE_LIMITS", {})  # /trust/psi/initiate is 3 per minute per IP; the tests make more
    monkeypatch.setattr(satellite, "_open_psi_sealed", lambda body: dict(body))
    monkeypatch.setattr(satellite, "_seal_psi_to", lambda result, pub: {"sealed_for_test": True})
    satellite.init_db()
    satellite.init_psi_tables()
    satellite.init_block_table()
    world = World(TestClient(satellite.app))
    db = sqlite3.connect(str(satellite.DB_PATH))
    for i in (world.a, world.b, world.c):
        db.execute("INSERT INTO identities (fingerprint, public_key, registered_at, sig_pubkey) VALUES (?,?,?,?)",
                   (i.fp, base64.b64encode(b"x" * 32).decode(), "2026-11-01T00:00:00+00:00", i.pub_hex))
    now = "2026-11-01T00:00:00+00:00"
    for owner, sender in ((world.a, world.b), (world.b, world.a)):  # A and B are mutual; C is nobody's contact
        db.execute("INSERT INTO allowed_senders (owner_fingerprint, sender_fingerprint, added_at) VALUES (?,?,?)",
                   (owner.fp, sender.fp, now))
    db.commit()
    db.close()
    return world


def same(r, *sids):
    """Status and body with the session ids masked, so two responses can be compared for equality."""
    body = r.text
    for s in sids:
        body = body.replace(s, "<sid>")
    return r.status_code, body


# ── baseline: the setup itself is right ──────────────────────────────────────────────────────────────────────

def test_initiate_answers_alike_whether_or_not_a_session_row_was_made(w):
    g, u = w.genuine(), w.unmade()
    assert w.session_rows(g) == 1, "the genuine request made a session row"
    assert w.session_rows(u) == 0, "the other request made none"
    assert len(g) == len(u)


# ── cancel ───────────────────────────────────────────────────────────────────────────────────────────────────

def test_cancel_of_an_unknown_session_looks_like_a_real_cancel(w):
    u = w.unmade()
    got = same(w.cancel(w.b, u), u)
    g = w.genuine()
    want = same(w.cancel(w.b, g), g)
    assert got == want
    assert got[0] == 200


def test_cancel_by_someone_who_is_not_a_party_looks_the_same_and_deletes_nothing(w):
    g = w.genuine()
    r = w.cancel(w.c, g)  # C is not a party to B's session with A
    assert same(r, g)[0] == 200 and "cancelled" in r.text
    assert w.session_rows(g) == 1, "a non-party must not delete the session"


def test_cancel_by_a_party_deletes(w):
    g = w.genuine()
    assert w.cancel(w.b, g).status_code == 200
    assert w.session_rows(g) == 0
    g2 = w.genuine()
    assert w.cancel(w.a, g2).status_code == 200  # the responder is a party too
    assert w.session_rows(g2) == 0


def test_cancel_write_profile_is_the_same_whether_or_not_the_session_exists(w, monkeypatch):
    """Timing parity, made deterministic: the same kinds of write statements and the same single commit."""
    log: list[str] = []
    real = satellite.get_db

    def traced():
        db = real()
        db.set_trace_callback(lambda stmt: log.append(stmt))
        return db

    monkeypatch.setattr(satellite, "get_db", traced)

    def profile(sid, who):
        log.clear()
        w.cancel(who, sid)
        return [s.split()[0].upper() for s in log if s.split()[0].upper() in {"INSERT", "DELETE", "UPDATE", "COMMIT"}]

    u, g = w.unmade(), w.genuine()
    unknown = profile(u, w.b)
    real_cancel = profile(g, w.b)
    assert unknown == real_cancel, (unknown, real_cancel)
    assert unknown.count("COMMIT") == 1


# ── the other endpoints that take a session id from the caller ───────────────────────────────────────────────

def test_blinded_on_an_unknown_session_looks_like_on_ones_own_pending_session(w):
    u, g = w.unmade(), w.genuine()
    assert same(w.blinded(w.b, u), u) == same(w.blinded(w.b, g), g)


def test_respond_on_an_unknown_session_looks_like_on_ones_own_pending_session(w):
    u, g = w.unmade(), w.genuine()
    assert same(w.respond(w.b, u), u) == same(w.respond(w.b, g), g)


def test_result_on_an_unknown_session_looks_like_on_ones_own_pending_session(w):
    u, g = w.unmade(), w.genuine()
    assert same(w.result(w.b, u), u) == same(w.result(w.b, g), g)


def test_the_designated_responder_still_gets_through(w):
    """The fix must not close the door on the real responder: A can fetch B's blinded set and respond."""
    g = w.genuine()
    assert w.blinded(w.a, g).status_code == 200
    assert w.respond(w.a, g).status_code == 200
