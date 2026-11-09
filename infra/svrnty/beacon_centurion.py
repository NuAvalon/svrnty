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
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from pathlib import Path

FLAG_ENV = "BEACON_CENTURION"
EPOCH_SECONDS = 604800          # copy of beacon-wire.mjs's (the one definition); pinned equal by a test
GRACE_SECONDS = 600
MAX_BODY_BYTES = 16 * 1024
VERIFY_JS = Path(__file__).resolve().parent / "beacon-verifier" / "verify.mjs"
AUTH_JS = Path(__file__).resolve().parent / "beacon-verifier" / "auth.mjs"
MAX_AUTH_BYTES = 1024
_NONCE_TAG = b"svrnty:588:nonce:v1"
_HEX = {"pk": re.compile(r"^[0-9a-f]{64}$"), "sig": re.compile(r"^[0-9a-f]{128}$"), "nonce": re.compile(r"^[0-9a-f]{64}$")}

_CANON = re.compile(r"^(0|[1-9][0-9]{0,76})$")
ACCEPTED = b'{"status":"accepted"}'
ALREADY = b'{"status":"already"}'
MATCH = b'{"status":"match"}'
NONE = b'{"status":"none"}'
WITHDRAWN = b'{"status":"withdrawn"}'
NONCE_TTL_SECONDS = 60
_REASONS = {"wire", "epoch", "point:pi_a:identity", "point:pi_a:off-curve", "point:pi_c:identity", "point:pi_c:off-curve",
            "point:pi_b:identity", "point:pi_b:off-curve", "point:pi_b:not-in-subgroup", "vkey", "proof", "usage",
            "internal", "timeout", "rate", "full", "auth"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS beacon_deposits (
    epoch INTEGER NOT NULL, slot TEXT NOT NULL, n TEXT NOT NULL, k TEXT NOT NULL, accepted_at TEXT NOT NULL,
    withdrawn_at TEXT, PRIMARY KEY (slot, n));
CREATE INDEX IF NOT EXISTS beacon_deposits_epoch ON beacon_deposits (epoch);
CREATE TABLE IF NOT EXISTS beacon_matches (
    epoch INTEGER NOT NULL, slot TEXT PRIMARY KEY, n1 TEXT NOT NULL, n2 TEXT NOT NULL, formed_at TEXT NOT NULL,
    released_at TEXT, polled_n1 INTEGER NOT NULL DEFAULT 0, polled_n2 INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS beacon_security_alarms (
    at TEXT NOT NULL, epoch INTEGER, slot TEXT, n TEXT, raw TEXT NOT NULL);
"""


def child_env() -> dict[str, str]:
    """verify.mjs and auth.mjs run third-party npm code on hostile input. They get PATH and nothing else: no admin key, no
    NODE_OPTIONS from the parent."""
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}


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


def parse_auth_output(code: int, out: bytes) -> bool:
    """FAIL CLOSED: authenticated ONLY on exit 0 with exactly the bytes {"ok":true} and one newline. Anything else = refused."""
    return code == 0 and out == b'{"ok":true}\n'


def _field(v) -> int | None:
    """A canonical decimal that fits 32 bytes (auth.mjs re-checks < r), or None."""
    if not isinstance(v, str) or not _CANON.match(v):
        return None
    x = int(v)
    return x if x < 2 ** 256 else None


def _strict_obj(raw: bytes, keys: set[str]) -> dict | None:
    if len(raw) > MAX_AUTH_BYTES:
        return None
    try:
        o = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, ValueError):
        return None
    return o if isinstance(o, dict) and set(o) == keys else None


def _insert_match(db: sqlite3.Connection, epoch: int, slot: str, n_a: str, n_b: str, at: str) -> None:
    n1, n2 = sorted((n_a, n_b), key=int)
    db.execute("INSERT INTO beacon_matches (epoch, slot, n1, n2, formed_at, released_at) VALUES (?, ?, ?, ?, ?, ?)",
               (epoch, slot, n1, n2, at, at))


class Centurion:
    def __init__(self, db_path: str, *, vkey_path: str | None = None, node: str = "node", verify_cmd: list[str] | None = None,
                 verifier=None, clock=time.time, timeout_s: float = 10.0, per_epoch_cap: int = 100_000,
                 ip_per_minute: int = 30, auth_cmd: list[str] | None = None, max_inflight: int | None = None,
                 max_ip_keys: int = 100_000):
        self.db_path, self.clock, self.timeout_s = db_path, clock, timeout_s
        self.per_epoch_cap, self.ip_per_minute = per_epoch_cap, ip_per_minute
        self.verifier = verifier                      # test seam: callable(raw: bytes, now: int) -> dict
        self.vkey_path = vkey_path
        # The vkey is pinned ONCE, here; verify.mjs re-hashes the file every run and refuses if it changed since.
        self.vkey_sha = hashlib.sha256(Path(vkey_path).read_bytes()).hexdigest() if vkey_path else None
        self.verify_cmd = verify_cmd or [node, str(VERIFY_JS)]
        self.auth_cmd = auth_cmd or [node, str(AUTH_JS)]
        # Nonces are MACed, not stored at issue: an unauthenticated endpoint must not write a row per call. The key and the
        # used set live in THIS process's memory only: a nonce is void after the TTL and a restart voids the key, so the set
        # only covers the last TTL seconds and no replay survives a crash (key and set die together). ONE PROCESS: several
        # satellite workers would each need the same key and one shared used set.
        self._nonce_key = os.urandom(32)
        self._used_nonces: dict[str, float] = {}
        self._nonce_lock = threading.Lock()
        self._ip_hits: dict[str, list[float]] = {}
        self.max_ip_keys = max_ip_keys
        # ONE bound on node processes in flight, shared by the verifier and the authenticator; over it = refused("rate")
        # before anything is spawned (per-IP limits alone allow an unbounded number across many IPs).
        self._inflight = threading.BoundedSemaphore(max_inflight or os.cpu_count() or 2)
        self._lock = threading.Lock()
        with closing(self._db()) as db:
            db.executescript(SCHEMA)

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    @staticmethod
    def _ip_key(ip: str) -> str:
        """IPv4 as is; IPv6 by its /64 (one host usually holds a whole /64); IPv4-mapped IPv6 = the IPv4. Unparseable -> one
        shared bucket. The caller must pass the TRUSTED client address (satellite.client_ip_for), never a raw header."""
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            return "unparseable"
        if a.version == 6:
            if a.ipv4_mapped is not None:
                return str(a.ipv4_mapped)
            return str(ipaddress.ip_network(f"{a}/64", strict=False))
        return str(a)

    def _rate_ok(self, ip: str, now: float) -> bool:
        key = self._ip_key(ip)
        with self._lock:
            if key not in self._ip_hits and len(self._ip_hits) >= self.max_ip_keys:
                for k in [k for k, v in self._ip_hits.items() if not v or now - v[-1] >= 60]:
                    del self._ip_hits[k]                    # in-memory rate state only; no stored data is touched
                if len(self._ip_hits) >= self.max_ip_keys:
                    return False                           # every key active: fail closed, evict no one
            hits = [t for t in self._ip_hits.get(key, []) if now - t < 60]
            if len(hits) >= self.ip_per_minute:
                self._ip_hits[key] = hits
                return False
            hits.append(now)
            self._ip_hits[key] = hits
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
                                start_new_session=True, env=child_env())     # its own process group: killpg reaches every descendant
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
        if not self._inflight.acquire(blocking=False):
            return refused("rate")
        try:
            res = self._verify(raw, now)
        finally:
            self._inflight.release()
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
            # Two rows at a slot (a match, or one side withdrawn) is all two honest owners can ever make: a third N is an alarm.
            if db.execute("SELECT count(*) FROM beacon_deposits WHERE slot = ?", (slot,)).fetchone()[0] >= 2:
                db.execute("INSERT INTO beacon_security_alarms (at, epoch, slot, n, raw) VALUES (?, ?, ?, ?, ?)",
                           (at, epoch, slot, n, raw.decode("utf-8", "replace")))
                db.execute("COMMIT")
                print("[beacon] SECURITY ALARM: a third nullifier at a full slot; see beacon_security_alarms", flush=True)
                return ACCEPTED
            db.execute("INSERT INTO beacon_deposits (epoch, slot, n, k, accepted_at) VALUES (?, ?, ?, ?, ?)",
                       (epoch, slot, n, k, at))
            others = [r[0] for r in db.execute(
                "SELECT n FROM beacon_deposits WHERE slot = ? AND n != ? AND withdrawn_at IS NULL", (slot, n))]
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

    # ---- poll / withdraw (authenticated under K) and their nonces ----
    def _nonce_mac(self, op: str, slot: int, n: int, head: bytes) -> bytes:
        msg = _NONCE_TAG + op.encode() + b"|" + slot.to_bytes(32, "big") + n.to_bytes(32, "big") + head
        return hmac.new(self._nonce_key, msg, hashlib.sha256).digest()[:16]

    def nonce(self, raw: bytes, ip: str) -> bytes:
        """{op, H_e, N} -> {"nonce": 64 hex} = issued-at (8 B) || random (8 B) || MAC over (op, H_e, N, those 16 B) (16 B).
        Issued for ANY well-formed (H_e, N): whether a deposit exists is never answered here."""
        o = _strict_obj(raw, {"op", "H_e", "N"})
        if o is None or o["op"] not in ("poll", "withdraw"):
            return refused("wire")
        slot, n = _field(o["H_e"]), _field(o["N"])
        if slot is None or n is None:
            return refused("wire")
        now = self.clock()
        if not self._rate_ok(ip, now):
            return refused("rate")
        head = int(now).to_bytes(8, "big") + os.urandom(8)
        return json.dumps({"nonce": (head + self._nonce_mac(o["op"], slot, n, head)).hex()}, separators=(",", ":")).encode()

    def _nonce_ok(self, op: str, slot: int, n: int, nonce: bytes, now: float) -> bool:
        head, mac = nonce[:16], nonce[16:]
        issued = int.from_bytes(nonce[:8], "big")
        fresh = 0 <= int(now) - issued <= NONCE_TTL_SECONDS
        return hmac.compare_digest(mac, self._nonce_mac(op, slot, n, head)) and fresh

    def _authenticate(self, req: dict) -> bool:
        """One auth.mjs subprocess (own session; killpg + reap on timeout), fail closed on anything but the exact accept line."""
        proc = subprocess.Popen(self.auth_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                start_new_session=True, env=child_env())
        try:
            out, _ = proc.communicate(input=json.dumps(req, separators=(",", ":")).encode(), timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            return False
        return parse_auth_output(proc.returncode, out)

    def _authenticated_call(self, op: str, raw: bytes, ip: str) -> bytes:
        o = _strict_obj(raw, {"H_e", "N", "pk", "sig", "nonce"})
        if o is None or not all(isinstance(o[k], str) and _HEX[k].match(o[k]) for k in _HEX):
            return refused("wire")
        slot_i, n_i = _field(o["H_e"]), _field(o["N"])
        if slot_i is None or n_i is None:
            return refused("wire")
        slot, n, now = o["H_e"], o["N"], self.clock()
        if not self._rate_ok(ip, now):
            return refused("rate")
        # The nonce check needs no stored state about (H_e, N), so refusing a bad or used nonce before spawning tells nothing
        # about whether a deposit exists.
        if not self._nonce_ok(op, slot_i, n_i, bytes.fromhex(o["nonce"]), now):
            return refused("auth")
        with self._nonce_lock:
            if o["nonce"] in self._used_nonces:
                return refused("auth")
        with closing(self._db()) as db:
            row = db.execute("SELECT k FROM beacon_deposits WHERE slot = ? AND n = ?", (slot, n)).fetchone()
        # No deposit -> a random K that no key hashes to: the authenticator still runs in full (no fast path, no N-exists oracle).
        k = row[0] if row else str(secrets.randbelow(10 ** 76))
        if not self._inflight.acquire(blocking=False):
            return refused("rate")
        try:
            ok = self._authenticate({"op": op, "H_e": slot, "N": n, "K": k, "pk": o["pk"], "sig": o["sig"], "nonce": o["nonce"]})
        finally:
            self._inflight.release()
        if not ok:
            return refused("auth")
        at = _now_iso(now)
        # Check, act, mark: all under ONE lock, so two requests carrying one nonce act once. Marked only after COMMIT.
        with self._nonce_lock:
            for old in [x for x, t in self._used_nonces.items() if now - t > NONCE_TTL_SECONDS]:
                del self._used_nonces[old]
            if o["nonce"] in self._used_nonces:
                return refused("auth")
            out = self._act(op, slot, n, k, at)
            if out is not None:
                self._used_nonces[o["nonce"]] = now
            return out if out is not None else refused("auth")

    def _act(self, op: str, slot: str, n: str, k: str, at: str) -> bytes | None:
        """The action, in one transaction. None = the deposit is gone or its K changed since the check (refused)."""
        db = self._db()
        try:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute("SELECT k, withdrawn_at FROM beacon_deposits WHERE slot = ? AND n = ?", (slot, n)).fetchone()
            if cur is None or cur[0] != k:
                db.execute("ROLLBACK")
                return None
            m = db.execute("SELECT n1, n2 FROM beacon_matches WHERE slot = ?", (slot,)).fetchone()
            matched = m is not None and n in m
            if op == "poll":
                if matched:
                    db.execute(f"UPDATE beacon_matches SET {'polled_n1' if n == m[0] else 'polled_n2'} = 1 WHERE slot = ?",
                               (slot,))
                out = MATCH if matched else NONE
            else:     # withdraw: inert after a match; otherwise mark (never delete); idempotent
                if not matched and cur[1] is None:
                    db.execute("UPDATE beacon_deposits SET withdrawn_at = ? WHERE slot = ? AND n = ?", (at, slot, n))
                out = MATCH if matched else WITHDRAWN
            db.execute("COMMIT")
            return out
        except BaseException:
            if db.in_transaction:
                db.execute("ROLLBACK")
            raise
        finally:
            db.close()

    def poll(self, raw: bytes, ip: str) -> bytes:
        """{H_e, N, pk, sig, nonce} signed under the deposit's K -> MATCH / NONE (or refused). A poll before the completing
        deposit is byte-identical to no match, whatever else is stored (13b, 12)."""
        return self._authenticated_call("poll", raw, ip)

    def withdraw(self, raw: bytes, ip: str) -> bytes:
        """Same auth as poll. Lone deposit -> marked withdrawn (kept, can no longer match) -> WITHDRAWN; matched -> inert, MATCH."""
        return self._authenticated_call("withdraw", raw, ip)

    # ---- for the route and the health check ----
    def alarm_count(self) -> int:
        """Rows in beacon_security_alarms. The health check reports > 0 as ALARM, counts only, never the raw rows."""
        with closing(self._db()) as db:
            return db.execute("SELECT count(*) FROM beacon_security_alarms").fetchone()[0]

    def handle(self, op: str, raw: bytes, ip: str) -> bytes:
        """The ONE entry point a route calls. Any internal exception -> the fixed refused("internal") bytes: never a
        traceback, never a 500 with a body. `ip` = satellite.client_ip_for(peer, X-Forwarded-For), never the raw header."""
        fn = {"deposit": self.deposit, "nonce": self.nonce, "poll": self.poll, "withdraw": self.withdraw}.get(op)
        if fn is None:
            return refused("usage")
        try:
            return fn(raw, ip)
        except Exception:
            return refused("internal")
