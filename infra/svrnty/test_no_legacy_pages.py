"""The satellite serves no HTML pages: the legacy dashboard ("/") and chat page ("/chat") are gone.
Run from infra/svrnty:  python3 -m pytest -q test_no_legacy_pages.py

The chat page stored private keys in localStorage on whatever origin served it, and every proxy door
that reached the satellite re-exposed it. These tests pin the removal at the source, for every
spelling a proxy might pass through, and check that no route anywhere answers with HTML."""
import os, tempfile
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-nolegacy-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
os.environ.setdefault("SATELLITE_ADMIN_KEY", "test-admin-key-0123456789abcdef")

import pathlib
import pytest
import satellite  # noqa: E402
from fastapi.testclient import TestClient

HERE = pathlib.Path(__file__).parent

LEGACY_PATHS = [
    "/", "/chat", "/chat/", "/chat.html", "/dashboard", "/dashboard.html",
    "/index.html", "/Chat", "/CHAT", "/%63hat", "//chat", "/./chat", "/chat?x=1",
]


@pytest.fixture(scope="module")
def client():
    with TestClient(satellite.app) as c:
        yield c


@pytest.mark.parametrize("path", LEGACY_PATHS)
def test_legacy_page_is_gone(client, path):
    r = client.get(path, follow_redirects=True)
    assert r.status_code == 404, f"{path} -> {r.status_code}"
    assert "text/html" not in r.headers.get("content-type", ""), f"{path} served HTML"
    assert "svrnty_keys" not in r.text and "<html" not in r.text.lower()


def test_api_still_answers(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


def test_no_route_returns_html():
    # No route is declared with an HTML response class (the removed two were the only ones).
    for route in satellite.app.routes:
        rc = getattr(route, "response_class", None)
        name = getattr(rc, "__name__", "") if rc is not None else ""
        assert "HTML" not in name, f"{getattr(route, 'path', route)} declares {name}"


def test_page_files_are_not_shipped():
    assert not (HERE / "chat.html").exists()
    assert not (HERE / "dashboard.html").exists()
    dockerfile = (HERE / "Dockerfile").read_text()
    copy_lines = [l for l in dockerfile.splitlines() if l.strip().startswith("COPY") and "--from=" not in l]
    assert copy_lines, "no COPY line found"
    for line in copy_lines:
        assert ".html" not in line, f"Dockerfile still copies HTML: {line}"


def test_source_has_no_page_reader():
    src = (HERE / "satellite.py").read_text()
    for needle in ('"dashboard.html"', '"chat.html"', "'dashboard.html'", "'chat.html'", "HTMLResponse"):
        assert needle not in src, f"satellite.py still references {needle}"
