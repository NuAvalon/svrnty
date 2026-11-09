"""#588 mutual-trust beacon: the satellite's routes around the centurion. DARK.

satellite.py imports this module only when BEACON_CENTURION is exactly "1", and mount() then registers routes only if every
precondition holds. Any failed precondition: nothing is registered, one "[beacon] NOT mounted: <code>" line is printed, and the
satellite keeps serving everything else. A beacon problem must never take messaging down.

The routes live under /trust/beacon because the edge already sends /api/trust/* (prefix stripped) straight to the real satellite
on prod and dev, with the client address in X-Forwarded-For. The browser's base URL is /api/trust. The app's /api/satellite/*
proxies are no use here: on prod they default to the registration service, which has no satellite routes.

Every answer from these routes is the centurion's fixed bytes with status 200, including refusals, so the status line carries
nothing. Layers outside them can still answer on their own (the edge, or the generic rate limiter if a RATE_LIMITS prefix ever
covers this path; none does today), and the client treats 429 and 503 as busy. The handler runs off the event loop because it can sit in a node subprocess for its whole timeout; on the loop, one hostile deposit would
stall every route on this satellite. Nothing about a request is logged. The operator view is /admin/beacon/health, counts only.

THE VKEY. Only a vkey whose sha256 is pinned here can verify deposits. FINAL_VKEY_SHA256 is set by a reviewed commit after the
ceremony (plan H7), and from then on it is the only key accepted. Until then a test deployment may name a rehearsal key's hash in
BEACON_REHEARSAL_VKEY_SHA256. A rehearsal key's toxic waste is known, so anyone can forge proofs against it: that env var must
never be set on prod. A deployment needs BEACON_VKEY_PATH either way; a vkey nobody pinned means no routes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable, NamedTuple, Optional

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import beacon_centurion as bc

ROUTE_PREFIX = "/trust/beacon"
HEALTH_PATH = "/admin/beacon/health"
OPS = ("deposit", "nonce", "poll", "withdraw")
FINAL_VKEY_SHA256 = ""            # empty until the ceremony's final vkey is pinned by a reviewed commit (plan H7)
LOW_DISK_BYTES = 1024 ** 3
SMOKE_TIMEOUT_S = 30
_HEX64 = re.compile(r"[0-9a-f]{64}")
_WIRE_REFUSAL = b'{"ok":false,"reason":"wire"}\n'
_MAX_LENGTH_DIGITS = 6            # far above the cap; int() of a huge digit string is itself an error path


class Mounted(NamedTuple):
    centurion: object
    vkey_kind: str


def _reply(out: bytes) -> Response:
    return Response(content=out, status_code=200, media_type="application/json", headers={"Cache-Control": "no-store"})


def body_allowed(headers: list[tuple[bytes, bytes]]) -> bool:
    """Decided from the headers alone: exactly one plain decimal Content-Length within the cap, and no Transfer-Encoding."""
    lengths = [v for k, v in headers if k.lower() == b"content-length"]
    if len(lengths) != 1 or any(k.lower() == b"transfer-encoding" for k, _ in headers):
        return False
    raw = lengths[0].strip()
    return raw.isdigit() and len(raw) <= _MAX_LENGTH_DIGITS and int(raw) <= bc.MAX_BODY_BYTES


class BeaconBodyCap:
    """Pure ASGI, so a refusal never touches `receive`: an oversized body is not read at all."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] == "POST" and scope["path"].startswith(ROUTE_PREFIX + "/") \
                and not body_allowed(scope.get("headers", [])):
            await _reply(bc.refused("wire"))(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _smoke(cmd: list[str], want: bytes, stdin: bytes) -> bool:
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, timeout=SMOKE_TIMEOUT_S, env=bc.child_env())
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 1 and p.stdout == want


def _verifiers_load(node: str, vkey_path: str, sha: str, *, verify_js: str = str(bc.VERIFY_JS), auth_js: str = str(bc.AUTH_JS)) -> bool:
    """Run both real verifiers once on input that isn't a deposit. Only the exact wire refusal counts: that proves node, the npm
    tree and the shared wire module all load, which a file-exists check can't. A missing import prints nothing and fails here."""
    return (_smoke([node, verify_js, "--vkey", vkey_path, "--vkey-sha256", sha, "--now", "0"], _WIRE_REFUSAL, b"{}")
            and _smoke([node, auth_js], _WIRE_REFUSAL, b"{}"))


def _vkey_kind(sha: str) -> Optional[str]:
    if FINAL_VKEY_SHA256:
        return "final" if hmac.compare_digest(sha, FINAL_VKEY_SHA256) else None
    pin = os.environ.get("BEACON_REHEARSAL_VKEY_SHA256", "")
    return "rehearsal" if _HEX64.fullmatch(pin) and hmac.compare_digest(sha, pin) else None


def _refuse(code: str) -> None:
    print(f"[beacon] NOT mounted: {code}", flush=True)


def mount(app, data_dir, mode: str, client_ip: Callable[[Request], str], *, make_centurion=None) -> Optional[Mounted]:
    """Register the routes if and only if everything holds. Never raises."""
    if not bc.enabled():
        return None
    if mode != "full":
        return _refuse("mode")
    # This reads the environment only: a `--workers` flag on the uvicorn command line would not show here. The shipped CMD has none.
    if os.environ.get("WEB_CONCURRENCY", "1") != "1":   # the nonce key and used set live in ONE process (see Centurion.__init__)
        return _refuse("workers")
    vkey_path = os.environ.get("BEACON_VKEY_PATH", "")
    if not vkey_path:
        return _refuse("vkey-path")
    try:
        sha = hashlib.sha256(Path(vkey_path).read_bytes()).hexdigest()
    except OSError:
        return _refuse("vkey-unreadable")
    kind = _vkey_kind(sha)
    if kind is None:
        return _refuse("vkey-not-pinned")
    node = os.environ.get("BEACON_NODE") or shutil.which("node") or "node"
    if not _verifiers_load(node, vkey_path, sha):
        return _refuse("verifier")
    make = make_centurion or (lambda db, vkey, n: bc.Centurion(db, vkey_path=vkey, node=n, per_epoch_cap=bc.default_epoch_cap(db)))
    db_path = str(Path(data_dir) / "beacon.db")
    try:
        centurion = make(db_path, vkey_path, node)
    except Exception:
        return _refuse("centurion")
    if centurion.vkey_sha != sha:                       # the centurion's own read is the one it will enforce
        return _refuse("vkey-changed")
    # Before the routes, so a failure partway can never leave a route without its cap. Added last of all the middleware = outermost:
    # it refuses before the rate limiter or any read.
    app.add_middleware(BeaconBodyCap)
    for op in OPS:
        app.add_api_route(f"{ROUTE_PREFIX}/{op}", _endpoint(centurion, op, client_ip), methods=["POST"], include_in_schema=False)
    app.add_api_route(HEALTH_PATH, _health(centurion, kind, db_path), methods=["GET"], include_in_schema=False)
    print(f"[beacon] mounted: vkey={kind}", flush=True)
    return Mounted(centurion, kind)


def _endpoint(centurion, op: str, client_ip):
    async def endpoint(request: Request) -> Response:
        try:
            raw = await request.body()
            return _reply(await run_in_threadpool(centurion.handle, op, raw, client_ip(request)))
        except Exception:
            return _reply(bc.refused("internal"))
    return endpoint


def _health(centurion, kind: str, db_path: str):
    def read() -> dict:
        alarms = centurion.alarm_count()
        free = shutil.disk_usage(Path(db_path).parent).free
        size = sum(os.path.getsize(p) for p in (db_path, db_path + "-wal") if os.path.exists(p))
        status = "ALARM" if alarms > 0 else ("WARN" if free < LOW_DISK_BYTES else "ok")
        return {"status": status, "vkey": kind, "alarms": alarms, "db_bytes": size, "disk_free_bytes": free}

    async def health(request: Request) -> JSONResponse:
        expected = os.environ.get("SATELLITE_ADMIN_KEY", "").encode()
        given = request.headers.get("x-admin-key", "").encode()
        if not expected or not hmac.compare_digest(given, expected):
            return JSONResponse(status_code=403, content={"detail": "Unauthorized"})
        try:
            return JSONResponse(await run_in_threadpool(read), headers={"Cache-Control": "no-store"})
        except Exception:                               # a check that can't see must not read as a pass
            return JSONResponse({"status": "UNREADABLE", "vkey": kind}, headers={"Cache-Control": "no-store"})
    return health
