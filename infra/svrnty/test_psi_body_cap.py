"""PSI request-body cap pins. Run from infra/svrnty:  python3 -m pytest -q test_psi_body_cap.py
A refused request must be answered from the HEADERS ONLY: the ASGI `receive` (the body) is never
called and the PSI envelope opener never runs."""
import asyncio, os, tempfile
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-bodycap-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import pytest
import satellite  # noqa: E402
from fastapi.testclient import TestClient

CAP = satellite.PSI_MAX_BODY_BYTES
H = lambda **kv: [(k.replace("_", "-").encode(), str(v).encode()) for k, v in kv.items()]


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    satellite._rate_limiter._hits.clear()
    opened = []
    real = satellite._open_psi_sealed
    monkeypatch.setattr(satellite, "_open_psi_sealed", lambda body: (opened.append(1), real(body))[1])
    yield opened


def asgi_call(method, path, headers):
    """Drive the real app directly; return (status, receive_calls)."""
    calls, sent = [], []
    async def receive():
        calls.append(1)
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(msg):
        sent.append(msg)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": headers, "client": ("127.0.0.1", 1), "server": ("t", 80)}
    asyncio.run(satellite.app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    return status, len(calls)


def test_unit_matrix():
    ok, bad = satellite.psi_body_allowed, lambda m, h: not satellite.psi_body_allowed(m, h)
    assert ok("POST", H(content_length=CAP)) and ok("POST", H(content_length=0))
    assert bad("POST", H(content_length=CAP + 1))
    assert bad("POST", []) and bad("POST", H(transfer_encoding="chunked"))
    assert bad("POST", H(content_length=10, transfer_encoding="chunked"))
    assert bad("POST", [(b"content-length", b"10"), (b"content-length", b"10")])
    for junk in ("-1", "1e3", "0x10", "", "+5", "1 0"):
        assert bad("POST", [(b"content-length", junk.encode())]), junk
    assert ok("POST", [(b"content-length", b" 10 ")])   # optional whitespace around the value is legal HTTP
    assert ok("GET", []) and ok("DELETE", []) and bad("GET", H(content_length=CAP + 1))


@pytest.mark.parametrize("path", ["/trust/psi/initiate", "/trust/psi/session/abc/blinded", "/trust/psi/session/abc/respond"])
def test_one_byte_over_is_refused_before_the_body_is_read(path, clean):
    status, reads = asgi_call("POST", path, H(content_length=CAP + 1, content_type="application/json"))
    assert status == 413 and reads == 0 and clean == []


@pytest.mark.parametrize("headers", [H(transfer_encoding="chunked"), H(content_type="application/json"),
                                     H(content_length=10, transfer_encoding="chunked")])
def test_chunked_or_lengthless_post_is_refused_unread(headers, clean):
    status, reads = asgi_call("POST", "/trust/psi/initiate", headers)
    assert status == 413 and reads == 0 and clean == []


def test_at_the_cap_reaches_the_route(clean):
    c = TestClient(satellite.app, raise_server_exceptions=False)
    r = c.post("/trust/psi/initiate", content=b"{" + b" " * (CAP - 2) + b"}", headers={"content-type": "application/json"})
    assert r.status_code != 413 and clean == [1]          # passed the cap, the opener ran


def test_bodyless_methods_pass_and_other_routes_are_untouched():
    c = TestClient(satellite.app, raise_server_exceptions=False)
    assert c.get("/trust/psi/pending/abcdefgh").status_code != 413
    assert c.delete("/trust/psi/session/abc?fingerprint=abcdefgh").status_code != 413
    assert c.post("/register", content=b"x" * (CAP + 1), headers={"content-type": "application/json"}).status_code != 413
