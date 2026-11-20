"""The registration service ships no in-browser signup page.
Run from infra/svrnty:  python3 -m pytest -q test_no_legacy_signup_page.py

The old page generated identity keys in the browser with code fetched from a CDN, on an older key suite than the app.
These tests pin that it is gone from the service's "/" route, from the registration image and from the self-host kit."""
import os, pathlib, re, tempfile
os.environ["REGISTRATION_DATA"] = tempfile.mkdtemp(prefix="registration-nosignup-test-")
os.environ["DEV_MODE"] = "1"
import pytest
import registration  # noqa: E402
from fastapi.testclient import TestClient

HERE = pathlib.Path(__file__).parent
KEYGEN_OR_CDN = re.compile(r"keygen|ml_kem|ml_dsa|cdn\.jsdelivr|<script", re.I)


@pytest.fixture(scope="module")
def client():
    with TestClient(registration.app) as c:
        yield c


def test_S1_root_serves_a_plain_notice_with_no_script_or_keygen(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "svrnty app" in r.text
    assert not KEYGEN_OR_CDN.search(r.text)


def test_S2_the_page_file_is_gone():
    assert not (HERE / "landing.html").exists()


def test_S3_the_registration_image_does_not_copy_it():
    df = (HERE / "Dockerfile.registration").read_text()
    assert "landing.html" not in df
    assert "COPY registration.py ." in df          # the image still builds the service


def test_S4_the_self_host_kit_does_not_bundle_it():
    src = (HERE / "satellite.py").read_text()
    i = src.index("with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:")
    block = src[i:src.index("\n\n", src.index("zf.writestr('about.html'", i))]
    assert "landing.html" not in block
    assert "zf.writestr('profile.html'" in block    # the kit still carries the pages the image COPYs
