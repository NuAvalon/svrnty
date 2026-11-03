"""The legacy bare proof is accepted ONLY for identities that have not bound a sig_pubkey.
Run from infra/svrnty:  python3 -m pytest -q test_legacy_bare_unbound_only.py

verify_request_signature() takes tag#3 (Ed25519 by the bound sig_pubkey over "svrnty-psi-auth:{fp}:{unix}"). During the
migration window (GATED_A_ACCEPT_LEGACY_BARE=1) it also takes the legacy bare proof signed by the IDENTITY key, in two
wire forms: "{unix}:{b64sig}" over "{fp}:{unix}", and a bare base64 sig over "{fp}:{minute}". A bare proof is replayable
across satellites, so once an identity has bound a sig_pubkey the bare forms must never authenticate it.
"""
import base64, os, sqlite3, tempfile, time
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-legacy-bare-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import pytest
import satellite  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FP = "a" * 64


def raw_pub(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()   # identity key, auth (sig) key


def make_db(identity_sk, sig_sk=None, sig_pubkey_value=None):
    """sig_sk binds that key; sig_pubkey_value overrides the stored column (e.g. '' or None) for the unbound cases."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE revocations (fingerprint TEXT, revoked_at TEXT, reason TEXT)")
    db.execute("CREATE TABLE identities (fingerprint TEXT, public_key TEXT, sig_pubkey TEXT)")
    stored = raw_pub(sig_sk).hex() if sig_sk is not None else sig_pubkey_value
    db.execute("INSERT INTO identities VALUES (?, ?, ?)",
               (FP, base64.b64encode(raw_pub(identity_sk)).decode(), stored))
    return db


def bare_seconds(identity_sk):
    ts = int(time.time())
    return f"{ts}:{base64.b64encode(identity_sk.sign(f'{FP}:{ts}'.encode())).decode()}"


def bare_minute(identity_sk):
    return base64.b64encode(identity_sk.sign(f"{FP}:{int(time.time()) // 60}".encode())).decode()


def tag3(sig_sk):
    ts = int(time.time())
    return f"{ts}:{base64.b64encode(sig_sk.sign(f'svrnty-psi-auth:{FP}:{ts}'.encode())).decode()}"


@pytest.fixture
def flag(monkeypatch):
    def set_(on):
        monkeypatch.setattr(satellite, "GATED_A_ACCEPT_LEGACY_BARE", on)
    return set_


# NEG 1: a BOUND identity is never authenticated by a valid bare proof (both wire forms), even with the flag on.
@pytest.mark.parametrize("form", [bare_seconds, bare_minute], ids=["seconds", "minute"])
def test_bound_identity_rejects_valid_bare_proof(keys, flag, form):
    idk, sigk = keys
    flag(True)
    assert satellite.verify_request_signature(FP, form(idk), make_db(idk, sig_sk=sigk)) is False


# NEG 2: an UN-BOUND identity still authenticates with the bare proof while the flag is on (no lockout), NULL or ''.
@pytest.mark.parametrize("unbound", [None, ""], ids=["null", "empty"])
@pytest.mark.parametrize("form", [bare_seconds, bare_minute], ids=["seconds", "minute"])
def test_unbound_identity_accepts_bare_proof_with_flag(keys, flag, form, unbound):
    idk, _ = keys
    flag(True)
    assert satellite.verify_request_signature(FP, form(idk), make_db(idk, sig_pubkey_value=unbound)) is True


# NEG 3: a BOUND identity authenticates with tag#3 (flag on and off).
@pytest.mark.parametrize("on", [True, False], ids=["flag-on", "flag-off"])
def test_bound_identity_accepts_tag3(keys, flag, on):
    idk, sigk = keys
    flag(on)
    assert satellite.verify_request_signature(FP, tag3(sigk), make_db(idk, sig_sk=sigk)) is True


# NEG 4: flag OFF -> the bare proof is rejected for everyone, bound or not.
@pytest.mark.parametrize("bound", [True, False], ids=["bound", "unbound"])
@pytest.mark.parametrize("form", [bare_seconds, bare_minute], ids=["seconds", "minute"])
def test_flag_off_rejects_bare_proof(keys, flag, form, bound):
    idk, sigk = keys
    flag(False)
    db = make_db(idk, sig_sk=sigk) if bound else make_db(idk, sig_pubkey_value=None)
    assert satellite.verify_request_signature(FP, form(idk), db) is False


# Control: the bare proof signed by the WRONG key is rejected for an unbound identity with the flag on.
def test_unbound_wrong_key_bare_rejected(keys, flag):
    idk, other = keys
    flag(True)
    assert satellite.verify_request_signature(FP, bare_seconds(other), make_db(idk, sig_pubkey_value=None)) is False
