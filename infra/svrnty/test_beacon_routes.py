"""#588 piece G: the satellite's routes around the centurion. Run from infra/svrnty:  python3 -m pytest -q test_beacon_routes.py
DARK first: unless BEACON_CENTURION is exactly "1" AND every precondition holds, nothing is registered, nothing is imported from
the beacon modules, no file is created, and the satellite keeps serving. Responses are the centurion's fixed bytes, always 200."""
import asyncio, hashlib, json, os, shutil, subprocess, sys, tempfile, threading, time

os.environ.setdefault("SATELLITE_DATA", tempfile.mkdtemp(prefix="satellite-beaconroutes-test-"))
os.environ.setdefault("SATELLITE_MODE", "full")
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import beacon_centurion as bc
import beacon_routes as br

HERE = os.path.dirname(os.path.abspath(__file__))
OPS = ("deposit", "nonce", "poll", "withdraw")
P = br.ROUTE_PREFIX


class Stub:
    """Stands in for the Centurion wherever only the routing is under test."""
    def __init__(self, sha="", out=bc.ACCEPTED):
        self.vkey_sha, self.out, self.calls, self.exc, self.alarms = sha, out, [], None, 0
        self.retention = {"interval_s": 0, "last_purge_at": None, "deposits_deleted": 0, "matches_deleted": 0, "scrubbed": None,
                          "totals": {"deposits": 0, "matches": 0, "withdrawn": 0}}

    def handle(self, op, raw, ip):
        self.calls.append((op, raw, ip))
        if self.exc:
            raise self.exc
        return self.out

    def alarm_count(self):
        if self.exc:
            raise self.exc
        return self.alarms

    def retention_status(self):
        if self.exc:
            raise self.exc
        return dict(self.retention, interval_s=getattr(self, "retention_interval", 0))


@pytest.fixture
def world(tmp_path, monkeypatch):
    vkey = tmp_path / "vkey.json"
    vkey.write_bytes(b'{"throwaway":1}')
    sha = hashlib.sha256(vkey.read_bytes()).hexdigest()
    monkeypatch.setenv("BEACON_CENTURION", "1")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("BEACON_VKEY_PATH", str(vkey))
    monkeypatch.setenv("BEACON_REHEARSAL_VKEY_SHA256", sha)
    monkeypatch.setenv("SATELLITE_ADMIN_KEY", "k" * 32)
    monkeypatch.setattr(br, "FINAL_VKEY_SHA256", "")
    monkeypatch.setattr(br, "_verifiers_load", lambda *a, **k: True)
    return {"vkey": vkey, "sha": sha, "tmp": tmp_path, "stub": Stub(sha)}


def do_mount(world, mode="full", app=None, client_ip=lambda r: "1.2.3.4", stub=True):
    app = app or FastAPI()
    make = (lambda db, vkey, node: world["stub"]) if stub else None
    m = br.mount(app, world["tmp"], mode, client_ip, **({"make_centurion": make} if make else {}))
    return app, m


def beacon_paths(app):
    return sorted(r.path for r in app.routes if "beacon" in r.path)


def assert_dark(app, m, capsys, reason):
    assert m is None
    assert beacon_paths(app) == []
    assert [x for x in app.user_middleware if x.cls.__name__ == "BeaconBodyCap"] == []
    assert TestClient(app).post(f"{P}/deposit", content=b"{}").status_code == 404
    assert f"[beacon] NOT mounted: {reason}" in capsys.readouterr().out


# ---- the dark switch and every precondition -------------------------------------------------------------------------
@pytest.mark.parametrize("flag", [None, "", "0", "true", "TRUE", "1 ", " 1", "11", "yes"])
def test_only_the_exact_value_1_mounts(world, monkeypatch, capsys, flag):
    if flag is None:
        monkeypatch.delenv("BEACON_CENTURION")
    else:
        monkeypatch.setenv("BEACON_CENTURION", flag)
    app, m = do_mount(world)
    assert m is None and beacon_paths(app) == [] and not list(world["tmp"].glob("*.db"))
    assert "[beacon]" not in capsys.readouterr().out          # off is silent: nothing to report


def test_exact_1_with_every_precondition_mounts_exactly_four_post_routes(world):
    app, m = do_mount(world)
    assert m is not None and m.vkey_kind == "rehearsal"
    assert beacon_paths(app) == sorted([f"{P}/{op}" for op in OPS] + ["/admin/beacon/health"])
    for r in app.routes:
        if r.path.startswith(P):
            assert r.methods == {"POST"}


def test_registry_mode_stays_dark(world, capsys):
    app, m = do_mount(world, mode="registry")
    assert_dark(app, m, capsys, "mode")


@pytest.mark.parametrize("n", ["2", "4", "", "0", "abc"])
def test_more_than_one_worker_stays_dark(world, monkeypatch, capsys, n):
    """Nonce key + used set live in ONE process: a second worker would accept a nonce the first has used."""
    monkeypatch.setenv("WEB_CONCURRENCY", n)
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "workers")


def test_one_worker_explicitly_is_fine(world, monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    assert do_mount(world)[1] is not None


def test_verifier_that_cannot_load_stays_dark(world, monkeypatch, capsys):
    monkeypatch.setattr(br, "_verifiers_load", lambda *a, **k: False)
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "verifier")


def test_no_vkey_path_stays_dark(world, monkeypatch, capsys):
    monkeypatch.delenv("BEACON_VKEY_PATH")
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-path")


def test_unreadable_vkey_stays_dark(world, monkeypatch, capsys):
    monkeypatch.setenv("BEACON_VKEY_PATH", str(world["tmp"] / "absent.json"))
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-unreadable")


def test_a_vkey_nobody_pinned_stays_dark(world, monkeypatch, capsys):
    monkeypatch.delenv("BEACON_REHEARSAL_VKEY_SHA256")
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-not-pinned")


@pytest.mark.parametrize("pin", ["0" * 64, "", "abc", "A" * 64])
def test_a_rehearsal_pin_that_does_not_match_stays_dark(world, monkeypatch, capsys, pin):
    monkeypatch.setenv("BEACON_REHEARSAL_VKEY_SHA256", pin)
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-not-pinned")


@pytest.mark.parametrize("spell", [str.upper, lambda x: "é" * 64, lambda x: x + "\n"])
def test_a_rehearsal_pin_must_be_spelled_exactly_and_a_strange_one_never_raises(world, monkeypatch, capsys, spell):
    monkeypatch.setenv("BEACON_REHEARSAL_VKEY_SHA256", spell(world["sha"]))
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-not-pinned")


def test_the_final_pin_is_accepted_and_needs_no_env_pin(world, monkeypatch):
    monkeypatch.setattr(br, "FINAL_VKEY_SHA256", world["sha"])
    monkeypatch.delenv("BEACON_REHEARSAL_VKEY_SHA256")
    assert do_mount(world)[1].vkey_kind == "final"


def test_once_a_final_pin_exists_a_rehearsal_vkey_is_refused(world, monkeypatch, capsys):
    """After the ceremony an env var can no longer bring a key with known toxic waste back."""
    monkeypatch.setattr(br, "FINAL_VKEY_SHA256", "f" * 64)
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-not-pinned")


def test_the_vkey_the_centurion_read_must_be_the_one_checked(world, capsys):
    """Swap between the pin check and the centurion's own read: its sha differs, so nothing mounts."""
    world["stub"].vkey_sha = "e" * 64
    app, m = do_mount(world)
    assert_dark(app, m, capsys, "vkey-changed")


def test_a_centurion_that_raises_stays_dark_and_never_propagates(world, capsys):
    app = FastAPI()
    def boom(db, vkey, node):
        raise OSError("disk says no: /secret/path")
    m = br.mount(app, world["tmp"], "full", lambda r: "x", make_centurion=boom)
    out = capsys.readouterr().out
    assert m is None and beacon_paths(app) == [] and "[beacon] NOT mounted: centurion" in out and "/secret/path" not in out


# ---- the routes -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("op", OPS)
@pytest.mark.parametrize("out", [bc.ACCEPTED, bc.ALREADY, bc.MATCH, bc.NONE, bc.WITHDRAWN, bc.refused("rate"), bc.refused("auth"),
                                 b'{"nonce":"' + b"a" * 64 + b'"}'])
def test_every_answer_is_the_fixed_bytes_with_200_and_json(world, op, out):
    world["stub"].out = out
    app, _ = do_mount(world)
    raw = b'{"opaque": "bytes \xc3\xa9  kept"}'
    r = TestClient(app).post(f"{P}/{op}", content=raw)
    assert r.status_code == 200 and r.content == out
    assert r.headers["content-type"] == "application/json" and r.headers["cache-control"] == "no-store"
    assert world["stub"].calls == [(op, raw, "1.2.3.4")]


def test_the_body_reaches_the_centurion_byte_for_byte_even_if_not_json(world):
    app, _ = do_mount(world)
    TestClient(app).post(f"{P}/deposit", content=b"\xff\x00not json")
    assert world["stub"].calls[0][1] == b"\xff\x00not json"


def test_get_is_not_a_route(world):
    app, _ = do_mount(world)
    assert TestClient(app).get(f"{P}/poll").status_code == 405
    assert world["stub"].calls == []


def test_an_unknown_op_is_not_a_route(world):
    app, _ = do_mount(world)
    assert TestClient(app).post(f"{P}/purge", content=b"{}").status_code == 404
    assert world["stub"].calls == []


def test_the_client_ip_callable_decides_the_ip_never_a_raw_header(world):
    app, _ = do_mount(world, client_ip=lambda request: "from-the-callable")
    TestClient(app).post(f"{P}/nonce", content=b"{}", headers={"X-Forwarded-For": "6.6.6.6"})
    assert world["stub"].calls[0][2] == "from-the-callable"


def test_any_exception_is_the_fixed_internal_refusal_with_no_detail(world):
    world["stub"].exc = RuntimeError("/data/beacon.db trace detail")
    app, _ = do_mount(world)
    r = TestClient(app, raise_server_exceptions=False).post(f"{P}/deposit", content=b"{}")
    assert r.status_code == 200 and r.content == bc.refused("internal")


def test_client_ip_failure_is_the_fixed_internal_refusal(world):
    def bad(request):
        raise ValueError("nope")
    app, _ = do_mount(world, client_ip=bad)
    r = TestClient(app, raise_server_exceptions=False).post(f"{P}/deposit", content=b"{}")
    assert r.status_code == 200 and r.content == bc.refused("internal") and world["stub"].calls == []


def test_nothing_about_a_request_is_printed(world, capsys):
    app, _ = do_mount(world)
    capsys.readouterr()
    TestClient(app).post(f"{P}/deposit", content=b'{"N":"7777777"}', headers={"X-Forwarded-For": "5.5.5.5"})
    cap = capsys.readouterr()
    assert cap.out == "" and cap.err == ""


# ---- a slow verifier must not stall the satellite ----------------------------------------------------------------------
def test_a_blocked_centurion_call_does_not_block_the_event_loop(world):
    """handle() can sit in a node subprocess for 10 s. Run on the event loop, one hostile deposit would stall every route."""
    entered, release, order = threading.Event(), threading.Event(), []

    class Slow(Stub):
        def handle(self, op, raw, ip):
            entered.set()
            release.wait(timeout=5)
            order.append("deposit-done")
            return bc.ACCEPTED

    world["stub"] = Slow(world["sha"])
    app, _ = do_mount(world)

    @app.get("/ping")
    async def ping():
        order.append("ping")
        return {"ok": True}

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            dep = asyncio.create_task(c.post(f"{P}/deposit", content=b"{}"))
            for _ in range(200):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set()
            r = await c.get("/ping")
            assert r.status_code == 200
            release.set()
            assert (await dep).content == bc.ACCEPTED

    asyncio.run(go())
    assert order == ["ping", "deposit-done"]


# ---- the body cap, answered from the headers alone ----------------------------------------------------------------------
CAP = bc.MAX_BODY_BYTES
H = lambda *kv: [(k.encode(), str(v).encode()) for k, v in kv]


def test_body_allowed_matrix():
    ok, bad = br.body_allowed, lambda h: not br.body_allowed(h)
    assert ok(H(("content-length", CAP))) and ok(H(("content-length", 0))) and ok(H(("Content-Length", 5)))
    assert bad(H(("content-length", CAP + 1)))
    assert bad([])
    assert bad(H(("transfer-encoding", "chunked")))
    assert bad(H(("content-length", 5), ("transfer-encoding", "chunked")))
    assert bad(H(("content-length", 5), ("content-length", 5)))
    for junk in ("", "-1", "+5", " 5x", "0x10", "1e3", "٣", "9" * 5000):
        assert bad([(b"content-length", junk.encode())]), junk


def asgi_call(app, method, path, headers):
    calls, sent = [], []
    async def receive():
        calls.append(1)
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(msg):
        sent.append(msg)
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
             "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": headers,
             "client": ("127.0.0.1", 1), "server": ("t", 80)}
    asyncio.run(app(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body, len(calls)


@pytest.mark.parametrize("headers", [H(("content-length", CAP + 1)), H(("transfer-encoding", "chunked")), [],
                                     H(("content-length", 3), ("content-length", 3))])
def test_an_oversized_or_unlengthed_body_is_refused_without_reading_it(world, headers):
    app, _ = do_mount(world)
    status, body, reads = asgi_call(app, "POST", f"{P}/deposit", headers)
    assert (status, body, reads) == (200, bc.refused("wire"), 0)
    assert world["stub"].calls == []


def test_a_body_of_exactly_the_cap_reaches_the_centurion(world):
    app, _ = do_mount(world)
    r = TestClient(app).post(f"{P}/deposit", content=b"x" * CAP)
    assert r.content == bc.ACCEPTED and len(world["stub"].calls[0][1]) == CAP


def test_the_cap_goes_in_before_any_route(world):
    """A failure partway through mount() must never leave a route registered without its cap."""
    order = []

    class Recorder:
        def add_middleware(self, cls):
            order.append(("cap", cls.__name__))

        def add_api_route(self, path, fn, **kw):
            order.append(("route", path))

    assert br.mount(Recorder(), world["tmp"], "full", lambda r: "x", make_centurion=lambda db, vkey, node: world["stub"]) is not None
    assert order[0] == ("cap", "BeaconBodyCap") and len(order) == 6


def test_the_cap_is_outermost_and_only_on_beacon_paths(world):
    app, _ = do_mount(world)
    assert app.user_middleware[0].cls.__name__ == "BeaconBodyCap"

    @app.post("/other")
    async def other():
        return {"ok": True}
    status, body, _ = asgi_call(app, "POST", "/other", [])
    assert (status, body) == (200, b'{"ok":true}')


# ---- the operator's health view ------------------------------------------------------------------------------------------
HK = {"X-Admin-Key": "k" * 32}


@pytest.mark.parametrize("hdr", [{}, {"X-Admin-Key": "wrong"}, {"X-Admin-Key": "é".encode()}])
def test_health_needs_the_admin_key(world, hdr):
    app, _ = do_mount(world)
    assert TestClient(app, raise_server_exceptions=False).get("/admin/beacon/health", headers=hdr).status_code == 403


def test_health_with_no_admin_key_configured_refuses_everyone(world, monkeypatch):
    app, _ = do_mount(world)
    monkeypatch.delenv("SATELLITE_ADMIN_KEY")
    assert TestClient(app).get("/admin/beacon/health", headers={"X-Admin-Key": ""}).status_code == 403


def test_health_ok_is_counts_only(world):
    app, _ = do_mount(world)
    j = TestClient(app).get("/admin/beacon/health", headers=HK).json()
    assert set(j) == {"status", "vkey", "alarms", "db_bytes", "disk_free_bytes", "retention"}
    assert j["retention"]["interval_s"] == 0 and j["retention"]["last_purge_at"] is None
    assert j["status"] == "ok" and j["alarms"] == 0 and j["vkey"] == "rehearsal"
    assert isinstance(j["disk_free_bytes"], int)


def test_health_reports_alarm(world):
    world["stub"].alarms = 3
    app, _ = do_mount(world)
    j = TestClient(app).get("/admin/beacon/health", headers=HK).json()
    assert j["status"] == "ALARM" and j["alarms"] == 3


def test_health_warns_on_low_disk_and_alarm_outranks_it(world, monkeypatch):
    monkeypatch.setattr(br, "LOW_DISK_BYTES", 2 ** 62)
    app, _ = do_mount(world)
    c = TestClient(app)
    assert c.get("/admin/beacon/health", headers=HK).json()["status"] == "WARN"
    world["stub"].alarms = 1
    assert c.get("/admin/beacon/health", headers=HK).json()["status"] == "ALARM"


def test_health_warns_when_the_last_purge_did_not_scrub(world):
    world["stub"].retention["scrubbed"] = False
    app, _ = do_mount(world)
    j = TestClient(app).get("/admin/beacon/health", headers=HK).json()
    assert j["status"] == "WARN" and j["retention"]["scrubbed"] is False
    world["stub"].alarms = 1
    assert TestClient(app).get("/admin/beacon/health", headers=HK).json()["status"] == "ALARM"


def beacon_threads():
    return [t for t in threading.enumerate() if t.name == "beacon-retention"]


def test_retention_off_when_unset_starts_no_thread(world, monkeypatch, capsys):
    monkeypatch.delenv(bc.RETENTION_ENV, raising=False)
    before = len(beacon_threads())
    _, m = do_mount(world)
    assert m is not None and len(beacon_threads()) == before
    assert world["stub"].retention_interval == 0
    assert "retention OFF" in capsys.readouterr().out


@pytest.mark.parametrize("raw", ["0", "59", "banana"])
def test_retention_stays_off_for_zero_or_a_bad_value(world, monkeypatch, raw):
    monkeypatch.setenv(bc.RETENTION_ENV, raw)
    before = len(beacon_threads())
    do_mount(world)
    assert len(beacon_threads()) == before and world["stub"].retention_interval == 0


def test_retention_starts_one_daemon_thread_when_set(world, monkeypatch, capsys):
    monkeypatch.setenv(bc.RETENTION_ENV, "86400")
    started = []
    monkeypatch.setattr(bc, "retention_loop", lambda *a, **k: started.append(a))
    do_mount(world)
    deadline = time.time() + 5
    while not started and time.time() < deadline:
        time.sleep(0.01)
    assert started == [(world["stub"], 86400)] and world["stub"].retention_interval == 86400
    assert "retention: ON every 86400s" in capsys.readouterr().out


def test_the_retention_thread_cannot_hold_the_process_open(world, monkeypatch):
    monkeypatch.setenv(bc.RETENTION_ENV, "86400")
    release = threading.Event()
    monkeypatch.setattr(bc, "retention_loop", lambda *a, **k: release.wait(5))
    do_mount(world)
    try:
        assert [t.daemon for t in beacon_threads()] == [True]
    finally:
        release.set()


def test_retention_needs_every_mount_precondition(world, monkeypatch):
    monkeypatch.setenv(bc.RETENTION_ENV, "86400")
    started = []
    monkeypatch.setattr(bc, "retention_loop", lambda *a, **k: started.append(a))
    monkeypatch.setenv("WEB_CONCURRENCY", "2")                  # a refused mount must not start the purge
    _, m = do_mount(world)
    assert m is None and started == []


def test_health_that_cannot_see_does_not_say_ok(world):
    world["stub"].exc = RuntimeError("locked")
    app, _ = do_mount(world)
    j = TestClient(app, raise_server_exceptions=False).get("/admin/beacon/health", headers=HK).json()
    assert j["status"] == "UNREADABLE" and set(j) == {"status", "vkey"}


# ---- the real Centurion behind the routes ----------------------------------------------------------------------------------
def real(world, **kw):
    def make(db, vkey, node):
        return bc.Centurion(db, verifier=kw.get("verifier"), vkey_path=vkey, node=node, ip_per_minute=kw.get("limit", 30))
    app = FastAPI()
    m = br.mount(app, world["tmp"], "full", lambda r: "1.2.3.4", make_centurion=make)
    return app, m


def test_the_store_goes_in_its_own_file_in_the_data_dir_only_when_on(world):
    real(world)
    assert (world["tmp"] / "beacon.db").exists()


def test_the_real_centurion_rate_refusal_is_a_200_refusal_not_a_429(world):
    app, _ = real(world, limit=2)
    c = TestClient(app)
    good = json.dumps({"op": "poll", "H_e": "1", "N": "2"}).encode()
    answers = [c.post(f"{P}/nonce", content=good) for _ in range(3)]
    assert [r.status_code for r in answers] == [200, 200, 200]
    assert answers[2].content == bc.refused("rate") and b"nonce" in answers[1].content


def test_child_processes_do_not_inherit_the_satellites_secrets(world, monkeypatch, tmp_path):
    """verify.mjs/auth.mjs run third-party npm code on hostile input: they get PATH and nothing else."""
    monkeypatch.setenv("SATELLITE_ADMIN_KEY", "must-not-leak-" + "s" * 20)
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/evil.js")
    probe = tmp_path / "probe.py"
    probe.write_text("import os,json,sys\nsys.stdin.buffer.read()\n"
                     "ok = 'SATELLITE_ADMIN_KEY' not in os.environ and 'NODE_OPTIONS' not in os.environ\n"
                     "print(json.dumps({'ok':True,'e':'1','H_e':'2','N':'3','K':'4'} if ok else {'ok':False,'reason':'proof'}))\n")
    c = bc.Centurion(str(tmp_path / "x.db"), verify_cmd=[sys.executable, str(probe)], clock=lambda: 604800.0 * 2)
    assert c.deposit(b"{}", "1.1.1.1") == bc.ACCEPTED
    a = tmp_path / "authprobe.py"
    a.write_text("import os,sys\nsys.stdin.buffer.read()\n"
                 "sys.stdout.write('{\"ok\":true}\\n' if 'SATELLITE_ADMIN_KEY' not in os.environ else 'x')\n")
    c2 = bc.Centurion(str(tmp_path / "y.db"), auth_cmd=[sys.executable, str(a)])
    assert c2._authenticate({"x": 1}) is True


def test_the_third_nullifier_alarm_is_loud_in_the_log_and_names_no_value(tmp_path, capsys):
    def v(raw, now):
        return {"ok": True, "e": "1", "H_e": "424242", "N": str(1000 + v.i), "K": "9"}
    v.i = 0
    c = bc.Centurion(str(tmp_path / "a.db"), verifier=v, clock=lambda: 604800.0)
    for i in range(3):
        v.i = i
        assert c.deposit(b"{}", "1.1.1.1") == bc.ACCEPTED
    out = capsys.readouterr().out
    assert c.alarm_count() == 1 and "[beacon] SECURITY ALARM" in out
    assert "424242" not in out and "1002" not in out


# ---- the startup smoke check ----------------------------------------------------------------------------------------------
NODE = os.environ.get("BEACON_NODE") or shutil.which("node")
HAVE_DEPS = NODE and os.path.exists(os.path.join(HERE, "beacon-verifier", "node_modules", "snarkjs", "package.json"))


@pytest.mark.skipif(not HAVE_DEPS, reason="needs npm ci in beacon-verifier")
def test_smoke_passes_with_the_real_verifiers(tmp_path):
    v = tmp_path / "v.json"
    v.write_text("{}")
    assert br._verifiers_load(NODE, str(v), hashlib.sha256(v.read_bytes()).hexdigest()) is True


def test_smoke_fails_when_node_is_missing(tmp_path):
    v = tmp_path / "v.json"
    v.write_text("{}")
    assert br._verifiers_load(str(tmp_path / "no-node"), str(v), "0" * 64) is False


@pytest.mark.skipif(not HAVE_DEPS, reason="needs npm ci in beacon-verifier")
def test_smoke_fails_when_the_shared_wire_module_is_not_where_verify_imports_it(tmp_path):
    """The image builds from infra/svrnty, so ../../../src/... is exactly what a naive COPY would lose."""
    d = tmp_path / "beacon-verifier"
    d.mkdir()
    for f in ("verify.mjs", "auth.mjs", "package.json"):
        shutil.copy(os.path.join(HERE, "beacon-verifier", f), d)
    os.symlink(os.path.join(HERE, "beacon-verifier", "node_modules"), d / "node_modules")
    v = tmp_path / "v.json"
    v.write_text("{}")
    assert br._verifiers_load(NODE, str(v), hashlib.sha256(v.read_bytes()).hexdigest(),
                              verify_js=str(d / "verify.mjs"), auth_js=str(d / "auth.mjs")) is False


def test_smoke_fails_on_a_verifier_that_accepts_garbage(tmp_path):
    """The smoke's stdin is not a deposit: anything but the wire refusal means the thing on disk isn't the verifier."""
    bad = tmp_path / "bad.mjs"
    bad.write_text("process.stdout.write('{\"ok\":true,\"e\":\"1\",\"H_e\":\"2\",\"N\":\"3\",\"K\":\"4\"}\\n');process.exit(0)")
    v = tmp_path / "v.json"
    v.write_text("{}")
    if NODE:
        assert br._verifiers_load(NODE, str(v), "0" * 64, verify_js=str(bad), auth_js=str(bad)) is False


@pytest.mark.skipif(not NODE, reason="needs node")
def test_smoke_needs_exit_1_and_needs_both_verifiers(tmp_path):
    v = tmp_path / "v.json"
    v.write_text("{}")
    good, zero, other = tmp_path / "good.mjs", tmp_path / "zero.mjs", tmp_path / "other.mjs"
    line = "process.stdout.write('{\"ok\":false,\"reason\":\"wire\"}\\n',()=>process.exit(%d))"
    good.write_text(line % 1)
    zero.write_text(line % 0)
    other.write_text("process.exit(1)")
    load = lambda a, b: br._verifiers_load(NODE, str(v), "0" * 64, verify_js=str(a), auth_js=str(b))
    assert load(good, good) is True
    assert load(zero, good) is False and load(good, zero) is False
    assert load(good, other) is False and load(other, good) is False


# ---- the real satellite, in a clean process each time ----------------------------------------------------------------------
def run_sat(script, flag, tmp, extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ("BEACON_CENTURION", "WEB_CONCURRENCY")}
    env.update({"SATELLITE_DATA": str(tmp), "SATELLITE_MODE": "full", "SATELLITE_ADMIN_KEY": "k" * 32, **(extra or {})})
    if flag is not None:
        env["BEACON_CENTURION"] = flag
    p = subprocess.run([sys.executable, "-c", script], cwd=HERE, env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr[-2000:]
    return p.stdout


OFF = """
import sys, json
from fastapi.testclient import TestClient
import satellite
c = TestClient(satellite.app)
a = c.post('/trust/beacon/deposit', content=b'{}'); b = c.post('/trust/nosuchroute/x', content=b'{}')
print('RESULT' + json.dumps({'mods': sorted(m for m in sys.modules if 'beacon' in m), 'same': (a.status_code, a.content) == (b.status_code, b.content),
  'status': a.status_code, 'paths': [r.path for r in satellite.app.routes if 'beacon' in r.path],
  'none': satellite.beacon_mount is None, 'mw': [m.cls.__name__ for m in satellite.app.user_middleware]}))
"""


@pytest.mark.parametrize("flag", [None, "0", "1 "])
def test_flag_off_the_real_satellite_is_untouched(tmp_path, flag):
    out = run_sat(OFF, flag, tmp_path)
    r = json.loads(out.split("RESULT", 1)[1])
    assert r["mods"] == [] and r["paths"] == [] and r["none"] is True and r["same"] is True and r["status"] == 404
    assert "BeaconBodyCap" not in r["mw"]
    assert not list(tmp_path.glob("beacon*")) and "[beacon]" not in out


ON = """
import sys, json, os
import beacon_routes
beacon_routes._verifiers_load = lambda *a, **k: True
from fastapi.testclient import TestClient
import satellite
assert satellite.beacon_mount is not None
peer = os.environ['PEER']
c = TestClient(satellite.app, client=(peer, 4242))
body = json.dumps({'op': 'poll', 'H_e': '1', 'N': '2'}).encode()
rotating = [c.post('/trust/beacon/nonce', content=body, headers={'X-Forwarded-For': f'7.7.{i}.1'}).content for i in range(31)]
rate = b'{"status":"refused","reason":"rate"}'
print('RESULT' + json.dumps({'rotating_limited': rate in rotating, 'n_ok': sum(b'nonce' in r for r in rotating),
   'routes': sorted(r.path for r in satellite.app.routes if 'beacon' in r.path),
   'outer': satellite.app.user_middleware[0].cls.__name__}))
"""


def on_env(tmp, peer, trusted=""):
    v = tmp / "vkey.json"
    v.write_bytes(b'{"a":1}')
    return {"BEACON_VKEY_PATH": str(v), "BEACON_REHEARSAL_VKEY_SHA256": hashlib.sha256(v.read_bytes()).hexdigest(),
            "PEER": peer, "SATELLITE_TRUSTED_PROXIES": trusted}


def test_flag_on_forged_forwarded_for_from_an_untrusted_peer_cannot_escape_the_limit(tmp_path):
    r = json.loads(run_sat(ON, "1", tmp_path, on_env(tmp_path, "9.9.9.9")).split("RESULT", 1)[1])
    assert r["rotating_limited"] is True and r["n_ok"] == 30
    assert r["outer"] == "BeaconBodyCap" and f"{P}/deposit" in r["routes"]


def test_flag_on_the_trusted_edge_gives_each_client_its_own_bucket(tmp_path):
    r = json.loads(run_sat(ON, "1", tmp_path, on_env(tmp_path, "9.9.9.9", trusted="9.9.9.9")).split("RESULT", 1)[1])
    assert r["rotating_limited"] is False and r["n_ok"] == 31


BROKEN = """
import builtins
real = builtins.__import__
def imp(name, *a, **k):
    if name == 'beacon_routes':
        raise ImportError('not in this image')
    return real(name, *a, **k)
builtins.__import__ = imp
from fastapi.testclient import TestClient
import satellite
satellite.init_db()
print('RESULT', satellite.beacon_mount is None, TestClient(satellite.app).get('/health').status_code)
"""


RAISING = """
import beacon_routes
def boom(*a, **k):
    raise RuntimeError('secret-path-detail')
beacon_routes.mount = boom
from fastapi.testclient import TestClient
import satellite
satellite.init_db()
print('RESULT', satellite.beacon_mount is None, TestClient(satellite.app).get('/health').status_code)
"""


def test_flag_on_a_mount_that_raises_leaves_the_satellite_serving_and_names_no_detail(tmp_path):
    out = run_sat(RAISING, "1", tmp_path)
    assert "RESULT True 200" in out and "[beacon] NOT mounted: mount" in out and "secret-path-detail" not in out


def test_no_rate_limit_prefix_covers_the_beacon_routes(tmp_path):
    """The 200-only claim in the module docstring leans on this: the generic limiter never answers on these paths."""
    import satellite
    assert not [p for p in satellite.RATE_LIMITS if br.ROUTE_PREFIX.startswith(p) or p.startswith(br.ROUTE_PREFIX)]


def test_flag_on_with_the_module_missing_from_the_image_the_satellite_still_serves(tmp_path):
    out = run_sat(BROKEN, "1", tmp_path)
    assert "RESULT True 200" in out and "[beacon] NOT mounted: import" in out


def test_a_real_mount_takes_its_cap_from_the_disk(world, monkeypatch):
    seen = {}
    def fake(db, **k):
        seen.update(k, db=db)
        return world["stub"]
    monkeypatch.setattr(bc, "default_epoch_cap", lambda db: 7)
    monkeypatch.setattr(bc, "Centurion", fake)
    do_mount(world, stub=False)
    assert seen["per_epoch_cap"] == 7
