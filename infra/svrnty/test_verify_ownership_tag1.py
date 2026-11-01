"""verify_ownership (gated-A tag#1) behaviour pins. Run: REG_FILE=<path to registration.py> python3 -m pytest -q <this>
(REG_FILE must end in .py: spec_from_file_location returns None for any other suffix.)
Synthetic keys only. Each case states the property; the positive control comes first so a verifier that
always returns False cannot pass."""
import base64
import importlib.util
import os
import sqlite3
import sys
import tempfile
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

os.environ["REGISTRATION_DATA"] = tempfile.mkdtemp(prefix="reg-tag1-")
os.environ.pop("GATED_A_ACCEPT_LEGACY_BARE", None)
_spec = importlib.util.spec_from_file_location("registration_under_test", os.environ["REG_FILE"])
reg = importlib.util.module_from_spec(_spec)
sys.modules["registration_under_test"] = reg
_spec.loader.exec_module(reg)


def _ident(fp):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return fp, sk, pk.hex()


A = _ident("a" * 64)
B = _ident("b" * 64)


@pytest.fixture
def db():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE verified_identities (fingerprint TEXT PRIMARY KEY, public_key TEXT)")
    for fp, _, pkhex in (A, B):
        c.execute("INSERT INTO verified_identities VALUES (?,?)", (fp, pkhex))
    yield c
    c.close()


def _tag1(ident, ts, fp=None, preimage=None):
    fp_signed = fp or ident[0]
    msg = preimage if preimage is not None else f"svrnty-own:{fp_signed}:{ts}".encode()
    return f"{ts}:{base64.b64encode(ident[1].sign(msg)).decode()}"


def _legacy(ident, minute):
    return base64.b64encode(ident[1].sign(f"{ident[0]}:{minute}".encode())).decode()


def test_tag1_fresh_proof_accepted(db):
    assert reg.verify_ownership(A[0], _tag1(A, int(time.time())), db) is True


def test_tag1_outside_window_rejected_both_sides(db):
    now = int(time.time())
    assert reg.verify_ownership(A[0], _tag1(A, now - reg.GATED_A_TS_WINDOW - 2), db) is False
    assert reg.verify_ownership(A[0], _tag1(A, now + reg.GATED_A_TS_WINDOW + 2), db) is False


def test_cross_context_signatures_rejected(db):
    """Domain separation: a signature over another tag's preimage, sent in the tag#1 wire, never verifies."""
    now = int(time.time())
    for other in (f"svrnty-psi-auth:{A[0]}:{now}".encode(), f"svrnty-bind:{A[0]}:{now}".encode(),
                  f"{A[0]}:{now}".encode()):
        assert reg.verify_ownership(A[0], _tag1(A, now, preimage=other), db) is False


def test_proof_for_another_identity_rejected(db):
    now = int(time.time())
    assert reg.verify_ownership(B[0], _tag1(A, now, fp=B[0]), db) is False      # A's key, B's fp
    assert reg.verify_ownership(B[0], _tag1(A, now), db) is False               # A's proof replayed for B


def test_legacy_bare_rejected_by_default(db, monkeypatch):
    monkeypatch.setattr(reg, "GATED_A_ACCEPT_LEGACY_BARE", False)
    assert reg.verify_ownership(A[0], _legacy(A, int(time.time()) // 60), db) is False


def test_legacy_bare_only_inside_the_migration_window(db, monkeypatch):
    monkeypatch.setattr(reg, "GATED_A_ACCEPT_LEGACY_BARE", True)
    assert reg.verify_ownership(A[0], _legacy(A, int(time.time()) // 60), db) is True
    assert reg.verify_ownership(A[0], _legacy(A, int(time.time()) // 60 - 5), db) is False   # stale minute


def test_default_is_secure_at_import():
    assert reg.GATED_A_ACCEPT_LEGACY_BARE is False


def test_malformed_and_unknown_never_raise(db):
    for sig in ("", "abc:xyz", "123:", ":::", "12345:%%%notb64", "x" * 5000):
        assert reg.verify_ownership(A[0], sig, db) is False
    assert reg.verify_ownership("c" * 64, _tag1(A, int(time.time()), fp="c" * 64), db) is False
