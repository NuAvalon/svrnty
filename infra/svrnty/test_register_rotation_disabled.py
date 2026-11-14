"""/register no longer changes an existing identity's keys.
Run from infra/svrnty:  python3 -m pytest -q test_register_rotation_disabled.py

R1: a key change for an existing identity is refused even with a valid request signature, and the stored key is
unchanged. R2/R3: the identical re-announce (409) and a revoked identity (403) behave as before."""
import base64, hashlib, os, tempfile, time
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-rotation-off-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import pytest
import satellite  # noqa: E402
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def raw_pub(sk):
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture()
def env():
    satellite.init_db()
    satellite._rate_limiter._hits.clear()
    client = TestClient(satellite.app)
    owner = Ed25519PrivateKey.generate()          # the identity key
    auth = Ed25519PrivateKey.generate()            # its bound per-request auth key (sig_pubkey)
    pk_b64 = base64.b64encode(raw_pub(owner)).decode()
    fp = hashlib.sha256(raw_pub(owner)).hexdigest()   # legacy single-key fingerprint format
    r = client.post("/register", json={"fingerprint": fp, "public_key": pk_b64, "display_name": "owner"})
    assert r.status_code in (200, 201), r.text
    db = satellite.get_db()
    try:
        db.execute("UPDATE identities SET sig_pubkey = ? WHERE fingerprint = ?", (raw_pub(auth).hex(), fp))
        db.commit()
    finally:
        db.close()
    return client, fp, pk_b64, auth


def valid_auth_sig(auth, fp):
    ts = int(time.time())
    sig = auth.sign(f"svrnty-psi-auth:{fp}:{ts}".encode())
    return f"{ts}:{base64.b64encode(sig).decode()}"


def stored_key(fp):
    db = satellite.get_db()
    try:
        return db.execute("SELECT public_key FROM identities WHERE fingerprint = ?", (fp,)).fetchone()["public_key"]
    finally:
        db.close()


def test_R1_key_change_refused_even_with_a_valid_signature(env):
    client, fp, pk_b64, auth = env
    sig = valid_auth_sig(auth, fp)
    # the sig really is valid for this identity: the generic verifier accepts it
    db = satellite.get_db()
    try:
        assert satellite.verify_request_signature(fp, sig, db)
    finally:
        db.close()
    other_key = base64.b64encode(raw_pub(Ed25519PrivateKey.generate())).decode()
    r = client.post("/register", json={"fingerprint": fp, "public_key": other_key, "display_name": "x", "signature": sig})
    assert r.status_code == 403, r.text
    assert "disabled" in r.json()["detail"]
    assert stored_key(fp) == pk_b64                 # nothing was rebound


def test_R2_identical_reannounce_still_409(env):
    client, fp, pk_b64, _ = env
    r = client.post("/register", json={"fingerprint": fp, "public_key": pk_b64, "display_name": "owner"})
    assert r.status_code == 409, r.text
    assert stored_key(fp) == pk_b64


def test_R3_revoked_identity_still_403_before_anything(env):
    client, fp, pk_b64, auth = env
    db = satellite.get_db()
    try:
        db.execute("INSERT INTO revocations (fingerprint, revoked_at, reason, signed_by, signature) VALUES (?, ?, ?, ?, ?)", (fp, satellite.now_iso(), "test", fp, "test"))
        db.commit()
    finally:
        db.close()
    r = client.post("/register", json={"fingerprint": fp, "public_key": pk_b64, "display_name": "owner"})
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"]
