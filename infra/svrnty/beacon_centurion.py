"""#588 mutual-trust beacon: the centurion's deposit path + store. DARK: nothing registers unless BEACON_CENTURION=1.

One deposit = one verifier subprocess (beacon-verifier/verify.mjs: the pinned snarkjs + the ONE shared wire parser). This module
never parses a proof or a public signal itself; it stores exactly the canonical (e, H_e, N, K) the verifier printed.

Order of cost: body byte cap -> per-IP rate limit -> open-epoch cap (all BEFORE spawning) -> verifier (own session, killpg +
reap on timeout) -> ONE transaction (caps re-checked, deposit, match) committed before any response.

Responses are fixed byte strings: ACCEPTED / ALREADY (your own N) / refused(<reason code>). A deposit never learns anything about
another nullifier: the deposit that completes a bond gets ACCEPTED like any other, and the poll delivers the match (release on
match: released_at = formed_at). A third distinct N at a matched slot can't come from a valid proof by either pair member, so it
is answered ACCEPTED, stores nothing in the beacon tables, and writes a security-alarm row with the raw body as evidence (no
client path reads that table; it is not counted against any cap).
No deletion anywhere. Caps count OPEN epochs only (cur, plus cur-1 / cur+1 inside the grace window), so closed epochs can't block
new deposits; disk growth is the remaining bound (health check).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from pathlib import Path

FLAG_ENV = "BEACON_CENTURION"
EPOCH_SECONDS = 604800          # must equal verify.mjs EPOCH_SECONDS (weekly; one named constant)
GRACE_SECONDS = 600
MAX_BODY_BYTES = 16 * 1024
VERIFY_JS = Path(__file__).resolve().parent / "beacon-verifier" / "verify.mjs"

_CANON = re.compile(r"^(0|[1-9][0-9]{0,76})$")
ACCEPTED = b'{"status":"accepted"}'
ALREADY = b'{"status":"already"}'
_REASONS = {"wire", "epoch", "point:pi_a:identity", "point:pi_a:off-curve", "point:pi_c:identity", "point:pi_c:off-curve",
            "point:pi_b:identity", "point:pi_b:off-curve", "point:pi_b:not-in-subgroup", "vkey", "proof", "usage",
            "internal", "timeout", "rate", "full"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS beacon_deposits (
    epoch INTEGER NOT NULL, slot TEXT NOT NULL, n TEXT NOT NULL, k TEXT NOT NULL, accepted_at TEXT NOT NULL,
    PRIMARY KEY (slot, n));
CREATE INDEX IF NOT EXISTS beacon_deposits_epoch ON beacon_deposits (epoch);
CREATE TABLE IF NOT EXISTS beacon_matches (
    epoch INTEGER NOT NULL, slot TEXT PRIMARY KEY, n1 TEXT NOT NULL, n2 TEXT NOT NULL, formed_at TEXT NOT NULL,
    released_at TEXT, polled_n1 INTEGER NOT NULL DEFAULT 0, polled_n2 INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS beacon_security_alarms (
    at TEXT NOT NULL, epoch INTEGER, slot TEXT, n TEXT, raw TEXT NOT NULL);
"""


def enabled() -> bool:
    """Only the exact value "1" turns the centurion on."""
    return os.environ.get(FLAG_ENV) == "1"


def refused(reason: str) -> bytes:
    return json.dumps({"status": "refused", "reason": reason if reason in _REASONS else "internal"},
                      separators=(",", ":")).encode()


def _now_iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def open_epochs(now: float) -> list[int]:
    cur = int(now // EPOCH_SECONDS)
    start = cur * EPOCH_SECONDS
    out = [cur]
    if now < start + GRACE_SECONDS:
        out.append(cur - 1)
    if now > start + EPOCH_SECONDS - GRACE_SECONDS:
        out.append(cur + 1)
    return out


def parse_verifier_output(code: int, out: bytes) -> dict:
    """FAIL CLOSED: accept ONLY exit 0 with exactly one newline-terminated JSON line holding exactly {ok: true, e, H_e, N, K},
    each a canonical decimal. Empty output, two lines, extra keys, non-canonical numbers: refused ("internal")."""
    bad = {"ok": False, "reason": "internal"}
    try:
        text = out.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return bad
    if not text.endswith("\n") or text.count("\n") != 1:
        return bad
    try:
        res = json.loads(text)
    except ValueError:
        return bad
    if not isinstance(res, dict):
        return bad
    if code == 1 and set(res) == {"ok", "reason"} and res["ok"] is False and isinstance(res["reason"], str):
        return {"ok": False, "reason": res["reason"]}
    if code != 0 or set(res) != {"ok", "e", "H_e", "N", "K"} or res["ok"] is not True:
        return bad
    if not all(isinstance(res[k], str) and _CANON.match(res[k]) for k in ("e", "H_e", "N", "K")):
        return bad
    return res


def _insert_match(db: sqlite3.Connection, epoch: int, slot: str, n_a: str, n_b: str, at: str) -> None:
    n1, n2 = sorted((n_a, n_b), key=int)
    db.execute("INSERT INTO beacon_matches (epoch, slot, n1, n2, formed_at, released_at) VALUES (?, ?, ?, ?, ?, ?)",
               (epoch, slot, n1, n2, at, at))


class Centurion:
    def __init__(self, db_path: str, *, vkey_path: str | None = None, node: str = "node", verify_cmd: list[str] | None = None,
                 verifier=None, clock=time.time, timeout_s: float = 10.0, per_epoch_cap: int = 100_000,
                 ip_per_minute: int = 30):
        self.db_path, self.clock, self.timeout_s = db_path, clock, timeout_s
        self.per_epoch_cap, self.ip_per_minute = per_epoch_cap, ip_per_minute
        self.verifier = verifier                      # test seam: callable(raw: bytes, now: int) -> dict
        self.vkey_path = vkey_path
        # The vkey is pinned ONCE, here; verify.mjs re-hashes the file every run and refuses if it changed since.
        self.vkey_sha = hashlib.sha256(Path(vkey_path).read_bytes()).hexdigest() if vkey_path else None
        self.verify_cmd = verify_cmd or [node, str(VERIFY_JS)]
        self._ip_hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        with closing(self._db()) as db:
            db.executescript(SCHEMA)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _rate_ok(self, ip: str, now: float) -> bool:
        with self._lock:
            hits = [t for t in self._ip_hits.get(ip, []) if now - t < 60]
            if len(hits) >= self.ip_per_minute:
                self._ip_hits[ip] = hits
                return False
            hits.append(now)
            self._ip_hits[ip] = hits
            return True

    def _open_count(self, db: sqlite3.Connection, now: float) -> int:
        eps = open_epochs(now)
        return db.execute(f"SELECT count(*) FROM beacon_deposits WHERE epoch IN ({','.join('?' * len(eps))})", eps).fetchone()[0]

    def _verify(self, raw: bytes, now: float) -> dict:
        if self.verifier is not None:
            return self.verifier(raw, int(now))
        cmd = list(self.verify_cmd)
        if self.vkey_path:
            cmd += ["--vkey", self.vkey_path, "--vkey-sha256", self.vkey_sha, "--now", str(int(now))]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True)     # its own process group: killpg reaches every descendant
        try:
            out, _ = proc.communicate(input=raw, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()                              # reap
            return {"ok": False, "reason": "timeout"}
        return parse_verifier_output(proc.returncode, out)

    def deposit(self, raw: bytes, ip: str) -> bytes:
        now = self.clock()
        if len(raw) > MAX_BODY_BYTES:
            return refused("wire")
        if not self._rate_ok(ip, now):
            return refused("rate")
        with closing(self._db()) as db:
            if self._open_count(db, now) >= self.per_epoch_cap:
                return refused("full")
        res = self._verify(raw, now)
        if res.get("ok") is not True:
            return refused(str(res.get("reason", "internal")))
        epoch, slot, n, k = int(res["e"]), res["H_e"], res["N"], res["K"]
        at = _now_iso(now)
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            if self._open_count(db, now) >= self.per_epoch_cap:          # re-checked inside the transaction (no race)
                db.execute("ROLLBACK")
                return refused("full")
            if db.execute("SELECT 1 FROM beacon_deposits WHERE slot = ? AND n = ?", (slot, n)).fetchone():
                db.execute("ROLLBACK")
                return ALREADY
            if db.execute("SELECT 1 FROM beacon_matches WHERE slot = ?", (slot,)).fetchone():
                db.execute("INSERT INTO beacon_security_alarms (at, epoch, slot, n, raw) VALUES (?, ?, ?, ?, ?)",
                           (at, epoch, slot, n, raw.decode("utf-8", "replace")))
                db.execute("COMMIT")
                return ACCEPTED
            db.execute("INSERT INTO beacon_deposits (epoch, slot, n, k, accepted_at) VALUES (?, ?, ?, ?, ?)",
                       (epoch, slot, n, k, at))
            others = [r[0] for r in db.execute("SELECT n FROM beacon_deposits WHERE slot = ? AND n != ?", (slot, n))]
            if len(others) == 1:
                _insert_match(db, epoch, slot, others[0], n, at)
            db.execute("COMMIT")
            return ACCEPTED
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()
