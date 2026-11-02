"""Trusted-proxy / client-IP pins for the satellite rate limiter.
Run from infra/svrnty:  python3 -m pytest -q test_satellite_trusted_proxies.py
Unit tests drive refresh_proxy_names()/client_ip_for() with a patched resolver; integration tests go
through the real RateLimitMiddleware with /register (3 per window per client)."""
import asyncio, os, socket, tempfile, threading, time
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
    monkeypatch.setattr(satellite, "_STATIC_TRUSTED_PROXIES", satellite._parse_static_trusted_proxies())
    satellite._proxy_name_cache.update(at=float("-inf"), ips=frozenset())
    satellite._rate_limiter._hits.clear()
    yield


def static(monkeypatch, value):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXIES", value)
    monkeypatch.setattr(satellite, "_STATIC_TRUSTED_PROXIES", satellite._parse_static_trusted_proxies())


def fake_dns(table, delay=0.0):
    def gai(name, *a, **k):
        if delay:
            time.sleep(delay)
        if name not in table:
            raise socket.gaierror("no such name")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[name]]
    return gai


def refresh(now=0.0):
    return asyncio.run(satellite.refresh_proxy_names(now=now))


def test_default_trusts_only_localhost():
    refresh()
    assert satellite.trusted_proxies() == {"127.0.0.1", "::1"}
    assert satellite.client_ip_for(EDGE, "203.0.113.7") == EDGE                 # untrusted edge: peer IP (pre-fix)
    assert satellite.client_ip_for("127.0.0.1", "203.0.113.7") == "203.0.113.7"


def test_old_default_bridge_is_no_longer_trusted():
    assert satellite.client_ip_for("172.17.0.1", "203.0.113.7") == "172.17.0.1"


def test_exact_ip_env_and_cidr_ignored(monkeypatch):
    static(monkeypatch, f"{EDGE}, 172.18.0.0/16, junk")
    assert satellite.trusted_proxies() == {"127.0.0.1", "::1", EDGE}
    assert satellite.client_ip_for(EDGE, "203.0.113.7") == "203.0.113.7"
    assert satellite.client_ip_for(OTHER, "203.0.113.7") == OTHER                # NEG: same /16, not trusted


def test_static_set_is_read_at_import_not_per_request(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXIES", EDGE)                        # env changed, no re-parse
    assert EDGE not in satellite.trusted_proxies()


def test_names_resolve_to_exact_addresses(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy,svrnty")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE], "svrnty": [APP]}))
    refresh()
    assert satellite.trusted_proxies() == {"127.0.0.1", "::1", EDGE, APP}
    assert satellite.client_ip_for(APP, "198.51.100.5") == "198.51.100.5"
    assert satellite.client_ip_for(OTHER, "198.51.100.5") == OTHER               # NEG: spoof from untrusted peer


def test_name_with_several_addresses_trusts_none(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy,svrnty")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE, OTHER], "svrnty": [APP]}))
    refresh()
    assert satellite.trusted_proxies() == {"127.0.0.1", "::1", APP}
    assert satellite.client_ip_for(EDGE, "203.0.113.7") == EDGE


def test_resolver_failure_trusts_nothing(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({}))
    refresh()
    assert satellite.trusted_proxies() == {"127.0.0.1", "::1"}


def test_resolver_timeout_trusts_nothing(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(satellite, "_PROXY_RESOLVE_TIMEOUT", 0.1)
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}, delay=0.5))
    async def timed():  # measured INSIDE the loop: asyncio.run() itself waits for the stray thread at shutdown
        t0 = time.monotonic(); await satellite.refresh_proxy_names(now=0.0); return time.monotonic() - t0
    dt = asyncio.run(timed())
    assert EDGE not in satellite.trusted_proxies() and dt < 0.4                  # gave up at the timeout


def test_resolution_does_not_block_the_event_loop(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}, delay=0.3))
    ticks, done = [], []
    async def main():
        async def ticker():
            for _ in range(10):
                ticks.append(time.monotonic()); await asyncio.sleep(0.02)
        async def resolve():
            await satellite.refresh_proxy_names(now=0.0); done.append(time.monotonic())
        await asyncio.gather(resolve(), ticker())
    asyncio.run(main())
    assert sum(t < done[0] for t in ticks) >= 5                                  # the loop kept ticking WHILE resolving
    assert EDGE in satellite.trusted_proxies()


def test_cache_ttl_and_re_resolution(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}))
    refresh(100)
    assert EDGE in satellite.trusted_proxies()
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [OTHER]}))      # edge container recreated
    refresh(100 + satellite._PROXY_NAME_TTL - 1)
    assert EDGE in satellite.trusted_proxies()                                    # still cached
    refresh(100 + satellite._PROXY_NAME_TTL + 1)
    got = satellite.trusted_proxies()
    assert OTHER in got and EDGE not in got


def test_refresh_claims_the_cache_before_resolving(monkeypatch):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    calls = []
    def gai(name, *a, **k):
        calls.append(name); time.sleep(0.1); return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (EDGE, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    async def main():
        await asyncio.gather(*(satellite.refresh_proxy_names(now=0.0) for _ in range(5)))
    asyncio.run(main())
    assert calls == ["caddy"]                                                     # one resolve, not five


def test_ipv4_mapped_peer_and_client_are_normalised(monkeypatch):
    static(monkeypatch, EDGE)
    assert satellite.client_ip_for("::ffff:" + EDGE, "203.0.113.7") == "203.0.113.7"
    assert satellite.client_ip_for(EDGE, "::ffff:203.0.113.7") == "203.0.113.7"


def test_rightmost_entry_and_injected_left(monkeypatch):
    static(monkeypatch, EDGE)
    assert satellite.client_ip_for(EDGE, "6.6.6.6, 203.0.113.7") == "203.0.113.7"
    assert satellite.client_ip_for(EDGE, "203.0.113.7, not-an-ip") == EDGE        # garbage -> peer, never the string


def test_startup_logs_trusted_set(monkeypatch, capsys):
    monkeypatch.setenv("SATELLITE_TRUSTED_PROXY_NAMES", "caddy")
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns({"caddy": [EDGE]}))
    monkeypatch.setenv("SATELLITE_ADMIN_KEY", "test-admin-key-0123456789")
    monkeypatch.setattr(satellite, "SATELLITE_MODE", "registry")   # skip the liboqs check; the log line is mode-independent
    with TestClient(satellite.app):
        pass
    out = capsys.readouterr().out
    assert "[satellite] Trusted proxies:" in out and EDGE in out and "names=['caddy']" in out


# ---- integration through the real middleware ----
def _post_register(client, xff=None):
    h = {"x-forwarded-for": xff} if xff else {}
    return client.post("/register", json={}, headers=h).status_code


def test_every_request_refreshes_the_trusted_names(monkeypatch):
    calls = []
    async def fake_refresh(now=None):
        calls.append(1); return frozenset()
    monkeypatch.setattr(satellite, "refresh_proxy_names", fake_refresh)
    c = TestClient(satellite.app)
    c.get("/health"); c.post("/register", json={})
    assert len(calls) >= 2                                                         # the middleware calls it per request


def test_two_clients_via_trusted_edge_get_separate_buckets(monkeypatch):
    monkeypatch.setattr(satellite, "trusted_proxies", lambda: frozenset({"testclient"}))
    c = TestClient(satellite.app)
    n = satellite.RATE_LIMITS["/register"]
    codes_a = [_post_register(c, "203.0.113.1") for _ in range(n + 1)]
    assert codes_a[-1] == 429 and 429 not in codes_a[:-1]
    assert _post_register(c, "203.0.113.2") != 429                                # B unaffected by A


def test_untrusted_peer_cannot_rotate_xff_to_dodge_limit(monkeypatch):
    monkeypatch.setattr(satellite, "trusted_proxies", lambda: frozenset())
    c = TestClient(satellite.app)
    n = satellite.RATE_LIMITS["/register"]
    codes = [_post_register(c, f"203.0.113.{i}") for i in range(n + 1)]
    assert codes[-1] == 429                                                        # spoofed XFF ignored
