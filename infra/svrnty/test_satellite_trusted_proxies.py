"""Trusted-proxy / client-IP pins for the satellite rate limiter.
Run from a dir holding satellite.py + its modules:  python3 -m pytest -q test_satellite_trusted_proxies.py
Unit tests drive client_ip_for() with a patched resolver; integration tests go through the real
RateLimitMiddleware with /register (3 per window per client)."""
import os, socket, tempfile
os.environ["SATELLITE_DATA"] = tempfile.mkdtemp(prefix="satellite-xff-test-")
os.environ.setdefault("SATELLITE_MODE", "full")
import pytest
import satellite  # noqa: E402
from fastapi.testclient import TestClient

EDGE, APP, OTHER = "172.18.0.2", "172.18.0.4", "172.18.0.9"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("SATELLITE_TRUSTED_PROXIES", raising=False)
    monkeypatch.delenv("SATELLITE_TRUSTED_PROXY_NAMES", raising=False)
    satellite._proxy_name_cache.update(at=float("-inf"), ips=frozenset())
    satellite._rate_limiter._hits.clear()
    yield


def fake_dns(table):
    def gai(name, *a, **k):
        if name not in table:
            raise socket.gaierror("no such name")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[name]]
    return gai


def test_default_trusts_only_localhost():
    assert satellite.trusted_proxies(now=0) == {"127.0.0.1", "::1"}
    assert satellite.client_ip_for(EDGE, "203.0.113.7", now=0) == EDGE           # untrusted edge: peer IP (pre-fix)
    assert satellite.client_ip_for("127.0.0.1", "203.0.113.7", now=0) == "203.0.113.7"


def test_old_default_bridge_is_no_longer_trusted():
    assert satellite.client_ip_for("172.17.0.1", "203.0.113.7", now=0) == "172.17.0.1"


def test_exact_ip_env_and_cidr_ignored(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXIES", f"{EDGE}, 172.18.0.0/16, junk")
    assert satellite.trusted_proxies(now=0) == {"127.0.0.1", "::1", EDGE}
    assert satellite.client_ip_for(EDGE, "203.0.113.7", now=0) == "203.0.113.7"
    assert satellite.client_ip_for(OTHER, "203.0.113.7", now=0) == OTHER         # NEG: same /16, not trusted


def test_names_resolve_to_exact_addresses(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy,svrnty")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE], "svrnty": [APP]}))
    assert satellite.trusted_proxies(now=0) == {"127.0.0.1", "::1", EDGE, APP}
    assert satellite.client_ip_for(APP, "198.51.100.5", now=0) == "198.51.100.5"
    assert satellite.client_ip_for(OTHER, "198.51.100.5", now=0) == OTHER        # NEG: spoof from untrusted peer


def test_name_with_several_addresses_trusts_none(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy,svrnty")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE, OTHER], "svrnty": [APP]}))
    assert satellite.trusted_proxies(now=0) == {"127.0.0.1", "::1", APP}
    assert satellite.client_ip_for(EDGE, "203.0.113.7", now=0) == EDGE
    assert satellite.client_ip_for(OTHER, "203.0.113.7", now=0) == OTHER


def test_startup_logs_trusted_set(monkeypatch, capsys):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}))
    monkeypatch.setenv("SATELLITE_ADMIN_KEY", "test-admin-key-0123456789")
    monkeypatch.setattr(satellite, "SATELLITE_MODE", "registry")   # skip the liboqs check; the log line is mode-independent
    with TestClient(satellite.app):
        pass
    out = capsys.readouterr().out
    assert "[satellite] Trusted proxies:" in out and EDGE in out and "names=['caddy']" in out


def test_resolver_failure_trusts_nothing(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({}))
    assert satellite.trusted_proxies(now=0) == {"127.0.0.1", "::1"}
    assert satellite.client_ip_for(EDGE, "203.0.113.7", now=0) == EDGE


def test_cache_ttl_and_re_resolution(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}))
    assert EDGE in satellite.trusted_proxies(now=100)
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [OTHER]}))      # edge container recreated
    assert EDGE in satellite.trusted_proxies(now=100 + satellite._PROXY_NAME_TTL - 1)  # still cached
    got = satellite.trusted_proxies(now=100 + satellite._PROXY_NAME_TTL + 1)
    assert OTHER in got and EDGE not in got                                      # old address no longer trusted


def test_rightmost_entry_and_injected_left(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXIES", EDGE)
    assert satellite.client_ip_for(EDGE, "6.6.6.6, 203.0.113.7", now=0) == "203.0.113.7"
    assert satellite.client_ip_for(EDGE, "203.0.113.7, not-an-ip", now=0) == EDGE   # garbage -> peer, never the string


# ---- integration through the real middleware ----
def _post_register(client, xff=None):
    h = {"x-forwarded-for": xff} if xff else {}
    return client.post("/register", json={}, headers=h).status_code


def _limit():
    return next(v for k, v in satellite.RATE_LIMITS.items() if k == "/register")


def test_two_clients_via_trusted_edge_get_separate_buckets(monkeypatch):
    monkeypatch.setattr(satellite, "trusted_proxies", lambda now=None: frozenset({"testclient"}))
    c = TestClient(satellite.app)
    n = _limit()
    codes_a = [_post_register(c, "203.0.113.1") for _ in range(n + 1)]
    assert codes_a[-1] == 429 and 429 not in codes_a[:-1]
    assert _post_register(c, "203.0.113.2") != 429                                # B unaffected by A


def test_untrusted_peer_cannot_rotate_xff_to_dodge_limit(monkeypatch):
    monkeypatch.setattr(satellite, "trusted_proxies", lambda now=None: frozenset())
    c = TestClient(satellite.app)
    n = _limit()
    codes = [_post_register(c, f"203.0.113.{i}") for i in range(n + 1)]
    assert codes[-1] == 429                                                        # spoofed XFF ignored
