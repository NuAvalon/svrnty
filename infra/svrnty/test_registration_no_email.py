"""Registration sends no email: the legacy email /register is retired.
Run from infra/svrnty:  python3 -m pytest -q test_registration_no_email.py

POST /register used to send a 6-digit code via Resend to ANY address it was given, limited only
to 1 per minute per address. No live client used it. These tests pin that the route is gone,
that nothing in the service can reach Resend even when a key is still present in an operator's
env, and that the open mint still works."""
import os, tempfile
os.environ["REGISTRATION_DATA"] = tempfile.mkdtemp(prefix="registration-noemail-test-")
os.environ["RESEND_API_KEY"] = "re_test_should_never_be_used"   # a key in env must change nothing
os.environ["DEV_MODE"] = "1"

import pathlib
import urllib.request
import pytest
import registration  # noqa: E402
from fastapi.testclient import TestClient

HERE = pathlib.Path(__file__).parent
SPELLINGS = ["/register", "/register/", "/REGISTER", "/register?x=1"]


@pytest.fixture(scope="module")
def client():
    with TestClient(registration.app) as c:
        yield c


@pytest.fixture
def no_network(monkeypatch):
    calls = []
    def boom(*a, **k):
        calls.append(a)
        raise AssertionError("registration made an outbound HTTP call")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    return calls


@pytest.mark.parametrize("path", SPELLINGS)
def test_email_register_is_gone(client, no_network, path):
    r = client.post(path, json={"email": "someone@example.com"})
    assert r.status_code in (404, 405), f"{path} -> {r.status_code}"
    assert no_network == [], "a /register request reached the network"


def test_nothing_writes_pending_verifications(client, no_network):
    client.post("/register", json={"email": "someone@example.com"})
    db = registration.get_db()
    try:
        n = db.execute("SELECT COUNT(*) FROM pending_verifications").fetchone()[0]
    finally:
        db.close()
    assert n == 0
    assert no_network == []


def test_health_does_not_report_email(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert "email_configured" not in r.json()


def test_source_has_no_email_sender():
    src = (HERE / "registration.py").read_text()
    for needle in ("api.resend.com", "RESEND_API_KEY", "RESEND_FROM", "send_otp_email",
                   '@app.post("/register")', "_dev_mode", "dev_otp"):
        assert needle not in src, f"registration.py still contains {needle!r}"


def test_no_register_route_registered():
    paths = {getattr(r, "path", None) for r in registration.app.routes}
    assert "/register" not in paths
    assert "/verify" in paths, "the open mint route must stay"
