"""
Satellite — Lightweight relay for the Planet/Satellite trust network.

Always-online message queue. Holds public keys only, never private keys.
Accepts encrypted blobs while the planet (laptop) is offline.
Stateless relay — nothing to steal.

Phase 2: Dumb Relay — trust logic lives on the phone/planet.
Satellite = identity storage + message relay + bouncer list (allowed_senders).

Part of the svrnty + Cairn ecosystem.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from collections import defaultdict

from fastapi import Depends, FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Onion blind-router (K0 outer-peel / K1 route). mailbox_envelope only needs `cryptography` at import
# time (ML-KEM decap via liboqs is lazy-imported inside the peel path — the Dockerfile must install it
# for full mode). satellite_keys manages the satellite's own routing keypair.
from mailbox_envelope import MAILBOX_ENV_ALG, peel_onion, open_mailbox_envelope, seal_mailbox_envelope
from satellite_keys import ensure_satellite_keypair, load_satellite_keypair, verify_mlkem_available

# ── Config ────────────────────────────────────────────────

DATA_DIR = Path(os.environ.get("SATELLITE_DATA", "/data"))
DB_PATH = DATA_DIR / "satellite.db"
MAX_MESSAGE_SIZE = 64 * 1024  # 64KB per encrypted blob
MAX_QUEUE_PER_IDENTITY = 1000
MAX_BLOBS_PER_RENDEZVOUS = 64  # Track C: cap blobs per rendezvous tag R (ring-buffer, evict oldest). Only the two peers who share S_pair can derive R, so this bounds re-deposit churn / self-DoS without ever dropping the newest beacon.
# Track C: TTL is the PRIMARY bound on cumulative table growth for the unauthed rendezvous
# relay (size/per-R/rate-limit bound the shape, not the total). Sized to the
# client's {current, current-1} WEEKLY-epoch poll window (~2wk) NOT minutes: the relay is blind
# to a beacon's (sealed) epoch, so it GCs by deposit wall-clock, and a shorter TTL would delete
# a real beacon before an async / just-migrated peer polls it (breaks §46 rehydrate). Tunable.
RENDEZVOUS_TTL_SECONDS = int(os.environ.get("SATELLITE_RENDEZVOUS_TTL", str(15 * 86400)))
RETENTION_DAYS = int(os.environ.get("SATELLITE_RETENTION_DAYS", "30"))
# Undelivered-mailbox expiry: SINGLE source of truth for how long an UNRETRIEVED
# message survives before GC — consumed by /msg status (~L2242) and /msg/cleanup
# DELETE (~L2274), previously two independent hardcoded timedelta(days=30) literals
# that could silently desync. The onion-deposit TTL (below) clamps itself >= this so
# a route/reversal deposit never GCs before the mailbox it guards.
UNDELIVERED_MSG_TTL_DAYS = int(os.environ.get("SATELLITE_MSG_TTL_DAYS", "30"))
UNDELIVERED_MSG_TTL_SECONDS = UNDELIVERED_MSG_TTL_DAYS * 86400
PORT = int(os.environ.get("PORT", "8100"))
SATELLITE_MODE = os.environ.get("SATELLITE_MODE", "registry")  # "registry" (T1) or "full" (T2)

# Onion blind-router (K0 outer-peel / K1 route). The satellite holds its OWN routing keypair
# (satellite_keys.py) to PEEL the OUTER shell; it can never read the device-sealed inner. Secret
# file (mode 0600) in the data volume — NOT in git. See satellite_keys.py threat-model note.
SATELLITE_KEY_PATH = Path(os.environ.get("SATELLITE_KEY_PATH", str(DATA_DIR / "satellite_mailbox_key.json")))
MAX_ONION_PER_ROUTE = 64  # per-route ring cap (evict oldest past cap; never drop the newest) — mirrors rendezvous
# TTL is the PRIMARY storage bound for the (unauthed-by-capability) route buckets: the relay is
# blind to the sealed inner and to the K1 window, so it GCs by deposit wall-clock. Sized to the
# recipient's route_id rotation/poll window with slack for an async/just-migrated peer. Tunable.
# Clamped >= UNDELIVERED_MSG_TTL_SECONDS BY CONSTRUCTION: an onion route/reversal
# deposit for an offline peer must never GC before that peer's undelivered mailbox
# expires (else the message outlives its route = undeliverable-but-not-expired, and a
# go-private reversal is silently lost). The env var can only RAISE the floor, never
# lower it below the mailbox expiry; default is the mailbox expiry itself (was 7d —
# that 7<30 default WAS the silent-reversal-loss band).
ONION_TTL_SECONDS = max(
    int(os.environ.get("SATELLITE_ONION_TTL", str(UNDELIVERED_MSG_TTL_SECONDS))),
    UNDELIVERED_MSG_TTL_SECONDS,
)
# Fail LOUD at import/boot if a future refactor ever removes the max() clamp — never
# silently reopen the band. raise (not assert): asserts strip under `python -O`.
# UNREACHABLE while the clamp above stands — intentional regression tripwire, do NOT
# "clean up the dead branch".
if ONION_TTL_SECONDS < UNDELIVERED_MSG_TTL_SECONDS:
    raise RuntimeError(
        f"INVARIANT VIOLATION: onion TTL {ONION_TTL_SECONDS}s < undelivered-mailbox "
        f"expiry {UNDELIVERED_MSG_TTL_SECONDS}s — route/reversal deposits would GC "
        f"before the mailbox they guard (silent reversal loss). Refusing to start."
    )


# ── Database ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS identities (
            fingerprint TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            signing_pk TEXT,
            encryption_pk TEXT,
            x25519_pk TEXT,
            mldsa65_pk TEXT,
            mlkem768_pk TEXT,
            pq_kem_pk TEXT,
            pq_sig_pk TEXT,
            crypto_version TEXT DEFAULT 'classical',
            key_version INTEGER DEFAULT 1,
            display_name TEXT,
            name TEXT,
            identity_type TEXT NOT NULL DEFAULT 'human',
            satellite_url TEXT,
            safeword TEXT,
            registered_at TEXT NOT NULL,
            last_seen TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL REFERENCES identities(fingerprint),
            sender_fingerprint TEXT,
            encrypted_blob TEXT NOT NULL,
            created_at TEXT NOT NULL,
            retrieved INTEGER DEFAULT 0,
            retrieved_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_messages_recipient
            ON messages(recipient, retrieved, created_at);

        -- Mailbox registry (spec §4.1 owner_sig pin). Stores ONLY the
        -- mailbox pubkeys + owner-proof epoch — NO durable user content (I-E / §4.1:
        -- never PSI/blinders/allow-block/graph). The book rehydrates the mailbox (§2);
        -- this row is a cache the book can rebuild. mailbox_fp = SHA256(x25519||mlkem1024).
        CREATE TABLE IF NOT EXISTS mailboxes (
            mailbox_fp TEXT PRIMARY KEY,
            x25519_pk TEXT NOT NULL,          -- 32B, lowercase hex
            mlkem1024_pk TEXT NOT NULL,       -- 1568B, lowercase hex
            owner_identity_fp TEXT NOT NULL,  -- register-time ownership ONLY, never routing (§4.5)
            epoch INTEGER NOT NULL DEFAULT 0, -- per-owner monotonic anti-replay
            registered_at TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_mailboxes_owner
            ON mailboxes(owner_identity_fp, epoch);

        -- Sovereign trust-rendezvous (Track C, Charter §8.5). Blind relay of Ed25519-signed +
        -- PQ-hybrid-sealed trust beacons keyed by an opaque rendezvous tag R. R = HKDF over the
        -- two peers' X25519 DH secret + sorted DIDs + epoch (client-derived; the relay CANNOT
        -- compute R — no privkeys — nor open the sealed blob). Both peers collide at the symmetric
        -- R (multiple blobs per tag); the recipient's wrong-recipient->null envelope open is the
        -- client-side filter. NO identity/sender/graph stored — the relay stays blind (§8.5).
        CREATE TABLE IF NOT EXISTS rendezvous (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            r_tag TEXT NOT NULL,        -- base64 of the 32B rendezvous tag R (opaque to the relay)
            blob TEXT NOT NULL,         -- opaque signed+sealed beacon envelope (relay cannot open)
            blob_hash TEXT NOT NULL,    -- sha256(blob) hex — idempotent exact re-deposit dedup
            deposited_at TEXT NOT NULL,
            UNIQUE(r_tag, blob_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_rendezvous_rtag
            ON rendezvous(r_tag, id);

        CREATE INDEX IF NOT EXISTS idx_rendezvous_deposited
            ON rendezvous(deposited_at);

        -- Onion blind-router route buckets (K0/K1). A peeled OUTER shell yields {route_id, inner};
        -- the still-device-sealed `inner` is deposited here keyed ONLY by the K1-blinded rotating
        -- route_id (16B, 32-hex). The relay stays blind: NO recipient identity, NO sender, NO stable
        -- mailbox_fp is stored (K0-1 strip is enforced on the peel output). inner is opaque — the
        -- satellite cannot open it (sealed to the recipient DEVICE, not the satellite).
        CREATE TABLE IF NOT EXISTS route_buckets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            route_id TEXT NOT NULL,     -- K1 blinded rotating route_id (32-hex; opaque routing tag)
            inner_json TEXT NOT NULL,   -- opaque device-sealed StrippedInner (relay cannot open)
            inner_hash TEXT NOT NULL,   -- sha256(inner_json) hex — idempotent exact re-deposit dedup
            deposited_at TEXT NOT NULL,
            UNIQUE(route_id, inner_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_route_buckets_route
            ON route_buckets(route_id, id);

        CREATE INDEX IF NOT EXISTS idx_route_buckets_deposited
            ON route_buckets(deposited_at);

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            fingerprint TEXT,
            details TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_log(timestamp);

        CREATE TABLE IF NOT EXISTS allowed_senders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_fingerprint TEXT NOT NULL REFERENCES identities(fingerprint),
            sender_fingerprint TEXT NOT NULL,
            added_at TEXT NOT NULL,
            UNIQUE(owner_fingerprint, sender_fingerprint)
        );

        CREATE INDEX IF NOT EXISTS idx_allowed_owner
            ON allowed_senders(owner_fingerprint);

        CREATE TABLE IF NOT EXISTS candles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            candle_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(fingerprint, version)
        );

        CREATE INDEX IF NOT EXISTS idx_candles_fingerprint
            ON candles(fingerprint, version DESC);

        CREATE TABLE IF NOT EXISTS revocations (
            fingerprint TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            successor TEXT,
            reason TEXT NOT NULL DEFAULT 'voluntary',
            signed_by TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS rotation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_fingerprint TEXT NOT NULL,
            new_fingerprint TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT 'voluntary',
            announcement TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );
        CREATE INDEX IF NOT EXISTS idx_rotation_old ON rotation_log(old_fingerprint);
        CREATE INDEX IF NOT EXISTS idx_rotation_new ON rotation_log(new_fingerprint);

        -- Single-use bind-nonce ledger (replay floor for /bind, satellite-direct).
        -- A /bind request carries a client-fresh nonce; the (fingerprint, nonce) pair
        -- is recorded here ONLY after the binding_sig verifies, so a forged/invalid
        -- request can never grow it (no DoS amplification). A replay of the same
        -- bind-tuple reuses (fp, nonce) -> PK collision -> rejected. PK scope is
        -- per-fingerprint because binding_sig is identity-key-bound: a nonce can only
        -- be consumed by a request already proven to own that identity, so cross-fp
        -- nonce burning is impossible. epoch is stored for future epoch-scoped GC
        -- (safe to prune a fp's nonces below its current epoch ONCE rotation bumps
        -- epoch; today identities.epoch is pinned 0 so a captured tuple stays valid
        -- indefinitely -> rows MUST be retained -> growth is one row per legit bind).
        CREATE TABLE IF NOT EXISTS bind_nonces (
            fingerprint TEXT NOT NULL,
            nonce TEXT NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 0,
            consumed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            PRIMARY KEY (fingerprint, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_bind_nonces_fp_epoch ON bind_nonces(fingerprint, epoch);
    """)

    # Migration: trust_commitments → allowed_senders (idempotent)
    try:
        db.execute("PRAGMA foreign_keys = OFF")  # disable during migration
        db.execute("SELECT 1 FROM trust_commitments LIMIT 1")
        # Table exists — migrate matched commitments
        matched = db.execute("""
            SELECT DISTINCT t1.committer_fingerprint AS owner,
                            t2.committer_fingerprint AS sender
            FROM trust_commitments t1
            JOIN trust_commitments t2 ON t1.commitment_hash = t2.commitment_hash
            WHERE t1.status = 'matched'
              AND t2.status = 'matched'
              AND t1.committer_fingerprint != t2.committer_fingerprint
        """).fetchall()
        now = datetime.now(timezone.utc).isoformat()
        known_fps = {r[0] for r in db.execute("SELECT fingerprint FROM identities").fetchall()}
        for row in matched:
            if row["owner"] in known_fps and row["sender"] in known_fps:
                db.execute(
                    "INSERT OR IGNORE INTO allowed_senders (owner_fingerprint, sender_fingerprint, added_at) VALUES (?, ?, ?)",
                    (row["owner"], row["sender"], now)
                )
        if matched:
            db.execute(
                "INSERT INTO audit_log (event, details, timestamp) VALUES (?, ?, ?)",
                ("migration_trust_to_allowed", f"migrated {len(matched)} matched pairs", now)
            )
        db.execute("DROP TABLE IF EXISTS trust_commitments")
        db.commit()
        db.execute("PRAGMA foreign_keys = ON")  # re-enable after migration
    except sqlite3.OperationalError:
        db.execute("PRAGMA foreign_keys = ON")  # re-enable even on skip
        pass  # trust_commitments doesn't exist — fresh install or already migrated

    # Migration: add PQ columns to identities (idempotent)
    # gated-A: sig_pubkey = bound per-request AUTH key (raw ed25519 as lowercase HEX —
    # uniform with registration for this NEW column; the legacy identity public_key
    # keeps its base64 encoding). epoch = clause-2 key-transition generation.
    for col, coltype in [("pq_kem_pk", "TEXT"), ("pq_sig_pk", "TEXT"), ("crypto_version", "TEXT DEFAULT 'classical'"),
                         ("sig_pubkey", "TEXT"), ("epoch", "INTEGER DEFAULT 0")]:
        try:
            db.execute(f"ALTER TABLE identities ADD COLUMN {col} {coltype}")
            db.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    db.close()


# ── Models ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    fingerprint: str = Field(..., min_length=8, max_length=128)
    public_key: str = Field(..., min_length=32)  # Ed25519 signing public key
    encryption_pk: Optional[str] = Field(None, min_length=32)  # X25519/XWing encryption public key
    pq_kem_pk: Optional[str] = None  # ML-KEM-1024 public key (post-quantum key encapsulation)
    pq_sig_pk: Optional[str] = None  # ML-DSA-87 public key (post-quantum signatures)
    crypto_version: Optional[str] = Field("classical", pattern=r'^(classical|hybrid-v1)$')
    display_name: Optional[str] = None
    identity_type: str = Field("human", pattern=r'^(human|agent|hybrid)$')
    satellite_url: Optional[str] = None  # Where to reach this identity's satellite
    safeword: Optional[str] = None  # Anti-phishing safeword (stored encrypted for two-layer vault)
    signature: Optional[str] = Field(None, description="Required for key rotation — Ed25519 sig from EXISTING key")


class SendMessageRequest(BaseModel):
    recipient: str = Field(..., min_length=8, max_length=128)
    sender_fingerprint: str = Field(..., min_length=8, max_length=128)
    encrypted_blob: str = Field(..., max_length=MAX_MESSAGE_SIZE)
    signature: str = Field(..., description="Ed25519 sig proving sender owns the key: Sign(sk, sender_fingerprint:timestamp_minute)")


class HeartbeatRequest(BaseModel):
    fingerprint: str = Field(..., min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 signature proving key ownership")


class AllowedSenderRequest(BaseModel):
    """Add or remove a sender from the allowed list."""
    sender_fingerprint: str = Field(..., min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 sig by the bound sig key over raw UTF-8 'svrnty-allowed-add:{owner}:{sender}:{unix}' (ADD) / 'svrnty-allowed-remove:{owner}:{sender}:{unix}' (REMOVE), no wrap; wire '{unix}:{b64sig}', +/-30s")


class RevokeRequest(BaseModel):
    """Revoke a key. Must be signed by the key being revoked."""
    fingerprint: str = Field(..., min_length=8, max_length=128)
    reason: str = Field("voluntary", pattern=r'^(voluntary|compromised)$')
    successor: Optional[str] = Field(None, min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 sig proving ownership of the key being revoked")


# ── App ───────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    admin_key = os.environ.get("SATELLITE_ADMIN_KEY", "")
    if not admin_key or len(admin_key) < 20:
        raise RuntimeError("SATELLITE_ADMIN_KEY must be set (20+ chars) before starting satellite")
    init_db()
    mode_label = "REGISTRY (contacts only)" if SATELLITE_MODE == "registry" else "FULL (contacts + messaging)"
    print(f"[satellite] Mode: {mode_label} | SATELLITE_MODE={SATELLITE_MODE}")

    # Onion blind-router: fail-fast if liboqs ML-KEM-1024 is missing/broken (else every /onion would
    # silently 400 at runtime), then mint the satellite's own routing keypair on first start (idempotent).
    if SATELLITE_MODE == "full":
        verify_mlkem_available()
        ensure_satellite_keypair(SATELLITE_KEY_PATH)
        _, _, _sat_fp = load_satellite_keypair(SATELLITE_KEY_PATH)
        print(f"[satellite] Blind-router keypair ready | mailbox_fp={_sat_fp[:16]}…")

    # F-SAT-6: Schedule periodic rate limiter cleanup to prevent memory growth
    import asyncio

    async def _rate_limiter_cleanup_loop():
        while True:
            await asyncio.sleep(300)  # every 5 minutes
            _rate_limiter.cleanup()

    cleanup_task = asyncio.create_task(_rate_limiter_cleanup_loop())
    yield
    cleanup_task.cancel()

app = FastAPI(
    title="Satellite Relay",
    description="Always-online message relay for the Planet/Satellite trust network. Public keys only — never holds private keys.",
    version="0.2.0",
    lifespan=lifespan,
)

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://svrnty.is").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key", "X-Signature", "X-Fingerprint"],
)


# ── Rate Limiting ─────────────────────────────────────────

# Per-IP sliding window. Limits per 60s window.
RATE_LIMITS = {
    "/register": 3,          # 3 registrations per minute per IP
    "/send": 30,             # 30 messages per minute per IP
    "/mailbox": 10,          # 10 mailbox register/lookup per minute per IP — caps §4.1 register storage-bloat DoS (one identity -> unlimited rows).
    "/trust/psi/initiate": 3,  # 3 PSI initiations/min/IP — REAL route (@app.post at /trust/psi/initiate). "/psi/initiate" was a DEAD key: startswith() never matched "/trust/psi/initiate", so the whole /trust/psi/* family was UNTHROTTLED (fail-open). Fixed 2026-09-13.
    "/verify-email": 5,      # 5 verification attempts per minute per IP
    # Track C sovereign trust-rendezvous. deposit (write) is stricter than poll (which is
    # burst-y on a full-book refresh / migration rehydrate). Keys are the REAL route prefixes
    # (deposit before the general prefix so it wins the startswith match) — like the
    # "/trust/psi/initiate" key above (the dead "/psi/initiate" it replaced never matched).
    "/trust/rendezvous/deposit": 60,
    "/trust/rendezvous": 180,
    # Onion blind-router (K0/K1). deposit (peel+route) is stricter than poll (burst-y on a
    # route-window rehydrate). Keys are the REAL route prefixes (startswith match).
    "/onion": 60,             # POST outer-onion deposits per min per IP
    "/route": 180,            # GET route_id polls per min per IP
    "/satellite/key": 30,     # GET satellite routing pubkey (clients cache it)
}
RATE_WINDOW = 60  # seconds


class RateLimiter:
    """In-memory sliding window rate limiter. No external dependencies."""

    def __init__(self):
        # {ip: {path: [timestamps]}}
        self._hits: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

    def check(self, ip: str, path: str) -> tuple[bool, int]:
        """Check if request is allowed. Returns (allowed, remaining)."""
        # Find matching rate limit (prefix match for parameterized routes)
        limit = None
        for prefix, lim in RATE_LIMITS.items():
            if path.startswith(prefix):
                limit = lim
                break
        if limit is None:
            return True, -1  # No rate limit for this path

        now = time.time()
        cutoff = now - RATE_WINDOW
        hits = self._hits[ip][path]

        # Prune old entries
        self._hits[ip][path] = [t for t in hits if t > cutoff]
        hits = self._hits[ip][path]

        if len(hits) >= limit:
            return False, 0

        hits.append(now)
        return True, limit - len(hits)

    def cleanup(self):
        """Periodic cleanup of stale entries. Call from a background task."""
        now = time.time()
        cutoff = now - RATE_WINDOW * 2
        stale_ips = []
        for ip, paths in self._hits.items():
            for path in list(paths):
                paths[path] = [t for t in paths[path] if t > cutoff]
                if not paths[path]:
                    del paths[path]
            if not paths:
                stale_ips.append(ip)
        for ip in stale_ips:
            del self._hits[ip]


_rate_limiter = RateLimiter()


# Per-identity rate limiter for /send (contain compromised identity flooding)
IDENTITY_SEND_LIMIT = 10  # max sends per identity per minute
_identity_send_hits: dict[str, list[float]] = defaultdict(list)


def check_identity_send_rate(fingerprint: str) -> bool:
    """Returns True if allowed, False if rate-limited."""
    now = time.time()
    cutoff = now - RATE_WINDOW
    _identity_send_hits[fingerprint] = [t for t in _identity_send_hits[fingerprint] if t > cutoff]
    if len(_identity_send_hits[fingerprint]) >= IDENTITY_SEND_LIMIT:
        return False
    _identity_send_hits[fingerprint].append(now)
    return True


_TRUSTED_PROXIES = {"127.0.0.1", "::1", "172.17.0.1"}  # localhost + Docker bridge


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract client IP — only trust X-Forwarded-For from known proxies (M-1)
        forwarded = request.headers.get("x-forwarded-for")
        peer_ip = request.client.host if request.client else "unknown"
        if forwarded and peer_ip in _TRUSTED_PROXIES:
            # Rightmost entry is set by the trusted proxy (Caddy)
            client_ip = forwarded.split(",")[-1].strip()
        else:
            client_ip = peer_ip

        allowed, remaining = _rate_limiter.check(client_ip, request.url.path)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(RATE_WINDOW)},
            )

        response = await call_next(request)
        if remaining >= 0:
            response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


app.add_middleware(RateLimitMiddleware)


# ── Mode Guard ────────────────────────────────────────────

def require_full_mode():
    """FastAPI dependency — blocks messaging endpoints in registry mode."""
    if SATELLITE_MODE != "full":
        raise HTTPException(
            status_code=403,
            detail=f"Endpoint disabled in {SATELLITE_MODE} mode. Self-host a satellite for full messaging."
        )


# ── Helpers ───────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(db: sqlite3.Connection, event: str, fingerprint: str = None, details: str = None):
    db.execute(
        "INSERT INTO audit_log (event, fingerprint, details, timestamp) VALUES (?, ?, ?, ?)",
        (event, fingerprint, details, now_iso())
    )


def _allowed_senders_hash(sender_fingerprints) -> str:
    """Injective hash of the allowed-senders SET for candle publication (C2).

    Replaces the raw allowed_senders list in the unauthenticated candle so the
    bouncer whitelist is never disclosed via GET /candle/{fp}. Set-semantics
    (dedup + byte-sort) => order- and collation-independent, matching
    candle_verify's set-equality. Length-prefixed TLV defeats the boundary-shift
    collision {"ab","c"} == {"a","bc"} that a naive join has.
    """
    fps = sorted({fp.encode("utf-8") for fp in sender_fingerprints})
    h = hashlib.sha256(b"svrnty-candle-allowed-v1")  # domain separation
    for fpb in fps:
        h.update(len(fpb).to_bytes(4, "big"))  # u32be length prefix
        h.update(fpb)
    return h.hexdigest()


def _audit_chain_hash(audit_rows) -> str:
    """Injective audit-chain hash (order-sensitive — it is a chain).

    Replaces the non-injective f"{event}:{details}:{timestamp}" concat whose ':'
    boundary can shift: [("x","y:z","t")] collides with [("x:y","z","t")] under
    the naive join but not here. NULL details -> b'' (not the string 'None').
    Rows must already be ORDER BY id.
    """
    h = hashlib.sha256(b"svrnty-audit-chain-v1")  # domain separation
    for a in audit_rows:
        for field in (a["event"], a["details"], a["timestamp"]):
            b = b"" if field is None else str(field).encode("utf-8")
            h.update(len(b).to_bytes(4, "big"))  # u32be length prefix
            h.update(b)
    return h.hexdigest()


def _get_display_name(db: sqlite3.Connection, fingerprint: str) -> str:
    """Get display name for a fingerprint, falling back to truncated fingerprint."""
    row = db.execute(
        "SELECT COALESCE(name, display_name) as name FROM identities WHERE fingerprint = ?",
        (fingerprint,)
    ).fetchone()
    return row["name"] if row and row["name"] else fingerprint[:8]


def reject_plaintext(blob: str) -> Optional[str]:
    """Reject messages that aren't properly encrypted.

    Returns an error message if the blob looks like plaintext, None if it passes.
    The satellite should NEVER store readable content — only encrypted blobs.
    """
    import base64
    import math

    # Must be base64-decodable
    try:
        raw = base64.b64decode(blob)
    except Exception:
        return "Message must be base64-encoded encrypted data"

    # Minimum size: Ed25519 signature (64) + nonce (24) + at least 1 byte payload
    if len(raw) < 89:
        return "Encrypted payload too small — check encryption"

    # Entropy check: encrypted data should have ~8 bits/byte entropy
    # Plaintext ASCII typically has 4-5 bits/byte
    #
    # Special case: if the blob decodes to a JSON envelope with a "ciphertext" field,
    # check entropy of the ciphertext (the actual encrypted data), not the JSON wrapper.
    # JSON structure has low entropy (~3.5) even when it contains encrypted values.
    check_bytes = raw
    try:
        import json as _json
        envelope = _json.loads(raw)
        if isinstance(envelope, dict) and "ciphertext" in envelope:
            # Valid encrypted envelope structure — trust it regardless of entropy.
            # Short messages produce short ciphertexts with low entropy due to
            # small sample size, but the structure proves encryption happened.
            # v1 classical envelope
            required_v1 = {"v", "from", "ephemeral_pk", "nonce", "ciphertext", "signature"}
            # v2 hybrid PQ envelope (uses ed_signature + pq_signature instead of signature)
            required_v2 = {"v", "from", "ephemeral_pk", "nonce", "ciphertext", "ed_signature", "pq_signature", "kem_ciphertext"}
            if required_v1.issubset(envelope.keys()) or required_v2.issubset(envelope.keys()):
                return None  # structurally valid envelope — pass
            ct_raw = base64.b64decode(envelope["ciphertext"])
            if len(ct_raw) >= 32:
                check_bytes = ct_raw
    except Exception:
        pass  # not JSON — check entropy on raw bytes as before

    if len(check_bytes) > 0:
        byte_counts = [0] * 256
        for b in check_bytes:
            byte_counts[b] += 1
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / len(check_bytes)
                entropy -= p * math.log2(p)
        # Encrypted data: entropy > 7.0. Plaintext: typically < 6.5
        if entropy < 6.5:
            return "Message appears to be plaintext — encrypt before sending"

    return None


MAX_DISPLAY_NAME = 64


def sanitize_display_name(name: Optional[str]) -> Optional[str]:
    """Sanitize display_name to prevent injection attacks (H-2)."""
    if name is None:
        return None
    import re as _re
    name = name.strip()[:MAX_DISPLAY_NAME]
    # Strip control characters (newlines, tabs, null bytes, etc.)
    name = _re.sub(r'[\x00-\x1f\x7f]', '', name)
    return name or None


# gated-A migration lever (operator-gated, default SECURE). False → per-request
# auth accepts ONLY tag#3 signed by the bound sig_pubkey. True → a bounded dual-accept
# window that ALSO accepts the legacy bare "{fp}:{unix|minute}" proof (identity key) so
# un-bound identities are not locked out. That bare branch is a live cross-context replay
# vector and MUST return to False (branch deleted) once every identity has bound a
# sig_pubkey. Env GATED_A_ACCEPT_LEGACY_BARE=1.
GATED_A_ACCEPT_LEGACY_BARE = os.environ.get("GATED_A_ACCEPT_LEGACY_BARE", "0") == "1"


def _psi_auth_preimage(fingerprint: str, unix_seconds: int) -> bytes:
    return f"svrnty-psi-auth:{fingerprint}:{unix_seconds}".encode()


def _allowed_add_preimage(owner_fp: str, sender_fp: str, unix_seconds: int) -> bytes:
    # Sender-bound consent preimage. Binds the SPECIFIC
    # (owner, sender) pair so a signature authorizing "add sender X" cannot be
    # replayed to add sender Y, nor a generic psi-auth sig replayed onto /allowed
    # (the request sender was previously unsigned). Owner-then-sender; canonical
    # lowercase-hex fps; single ASCII ':'; raw UTF-8, NO svrnty-psi-auth wrap.
    return f"svrnty-allowed-add:{owner_fp}:{sender_fp}:{unix_seconds}".encode()


def _allowed_remove_preimage(owner_fp: str, sender_fp: str, unix_seconds: int) -> bytes:
    # Twin of _allowed_add_preimage with a DISTINCT domain-tag so an add-sig can
    # never replay as a remove (or vice-versa). Same shape, same key axis.
    return f"svrnty-allowed-remove:{owner_fp}:{sender_fp}:{unix_seconds}".encode()


def verify_request_signature(fingerprint: str, signature: str, db: sqlite3.Connection) -> bool:
    """Verify a per-request PSI/trust auth signature.

    gated-A tag#3: Ed25519(sig_pubkey, "svrnty-psi-auth:{fp}:{unix_seconds}"), wire
    "{unix_seconds}:{base64_sig}", ±30s window. The AUTH key is the bound sig_pubkey
    (stored lowercase hex), NOT the identity key — domain-tagged so an ownership proof
    (tag#1) can never be replayed here (the live pre-gated-A bug).

    During a migration window (GATED_A_ACCEPT_LEGACY_BARE=1) the legacy untagged proof
    signed by the IDENTITY key is also accepted so un-bound identities keep working; that
    branch is removed once every identity has bound.
    """
    if not signature:
        return False
    # ── Revocation check (audit v2, Finding 2.1) ──
    revoked = db.execute(
        "SELECT revoked_at, reason FROM revocations WHERE fingerprint = ?",
        (fingerprint,)
    ).fetchone()
    if revoked:
        return False
    identity = db.execute(
        "SELECT public_key, sig_pubkey FROM identities WHERE fingerprint = ?",
        (fingerprint,)
    ).fetchone()
    if not identity:
        return False
    try:
        import base64
        sig_pubkey_hex = identity["sig_pubkey"] if "sig_pubkey" in identity.keys() else None

        # tag#3 — bound sig_pubkey; wire "{unix_seconds}:{b64sig}" (base64 has no ':')
        if ":" in signature and signature.split(":", 1)[0].isdigit():
            ts_str, sig_b64 = signature.split(":", 1)
            client_ts = int(ts_str)
            if abs(int(time.time()) - client_ts) > 30:
                return False  # replay / clock drift > 30s
            sig_bytes = base64.b64decode(sig_b64.replace(" ", "+"))
            if sig_pubkey_hex:
                try:
                    auth_pk = bytes.fromhex(sig_pubkey_hex)
                except ValueError:
                    auth_pk = None
                if auth_pk and _verify_with_key(auth_pk, sig_bytes,
                                                _psi_auth_preimage(fingerprint, client_ts)):
                    return True
            # migration-only fallback: legacy bare "{fp}:{unix}" signed by the identity key
            if GATED_A_ACCEPT_LEGACY_BARE:
                return _verify_with_key(base64.b64decode(identity["public_key"]),
                                        sig_bytes, f"{fingerprint}:{client_ts}".encode())
            return False

        # legacy bare base64 (minute window) — migration-only, default OFF
        if GATED_A_ACCEPT_LEGACY_BARE:
            idpk = base64.b64decode(identity["public_key"])
            sig_bytes = base64.b64decode(signature.replace(" ", "+"))
            ts_minute = int(time.time()) // 60
            for offset in (0, -1):
                if _verify_with_key(idpk, sig_bytes, f"{fingerprint}:{ts_minute + offset}".encode()):
                    return True
        return False
    except Exception:
        return False


def verify_allowed_change_signature(
    owner_fp: str,
    sender_fp: str,
    signature: str,
    db: sqlite3.Connection,
    preimage_fn,
) -> bool:
    """Verify a sender-bound consent signature for /allowed add|remove.

    Hard cutover: the signature MUST commit to the exact
    (owner, sender) pair via preimage_fn — there is NO svrnty-psi-auth fallback and
    NO GATED_A legacy branch here. This closes the cross-endpoint replay where a
    generic owner-liveness (psi-auth) signature could be replayed onto /allowed with
    an attacker-chosen sender (the request body/path sender was previously unsigned).

    Auth key = the bound sig_pubkey (same envelope as tag#3 psi-auth), NOT the
    identity public_key. Dedicated to add/remove_allowed_sender — deliberately does
    NOT touch the shared verify_request_signature (psi/initiate, /trust/*, /mailbox,
    and the /allowed GET list all depend on it). The preimage is reconstructed from
    the owner/sender strings exactly as transmitted (path + body), so the bytes match
    the client's signature verbatim — no server-side re-normalization.
    """
    if not signature:
        return False
    # The owner (the authorizer whose list is mutated) must not be revoked.
    revoked = db.execute(
        "SELECT revoked_at, reason FROM revocations WHERE fingerprint = ?",
        (owner_fp,)
    ).fetchone()
    if revoked:
        return False
    identity = db.execute(
        "SELECT sig_pubkey FROM identities WHERE fingerprint = ?",
        (owner_fp,)
    ).fetchone()
    if not identity:
        return False
    try:
        import base64
        sig_pubkey_hex = identity["sig_pubkey"] if "sig_pubkey" in identity.keys() else None
        if not sig_pubkey_hex:
            return False  # hard cutover: an unbound identity cannot authorize /allowed
        # wire "{unix_seconds}:{b64sig}" (base64 has no ':'), ±30s window
        if ":" not in signature or not signature.split(":", 1)[0].isdigit():
            return False
        ts_str, sig_b64 = signature.split(":", 1)
        client_ts = int(ts_str)
        if abs(int(time.time()) - client_ts) > 30:
            return False  # replay / clock drift > 30s
        sig_bytes = base64.b64decode(sig_b64.replace(" ", "+"))
        try:
            auth_pk = bytes.fromhex(sig_pubkey_hex)
        except ValueError:
            return False
        return _verify_with_key(auth_pk, sig_bytes, preimage_fn(owner_fp, sender_fp, client_ts))
    except Exception:
        return False


def _verify_with_key(pubkey_bytes: bytes, sig_bytes: bytes, message: bytes) -> bool:
    """Verify a signature, auto-detecting key type from key size.

    Ed25519: 32-byte public key, 64-byte signature.
    ML-DSA-65: 1952-byte public key, 3309-byte signature (future, requires liboqs).
    """
    try:
        if len(pubkey_bytes) == 32:
            # Ed25519
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            pubkey.verify(sig_bytes, message)
            return True
        elif len(pubkey_bytes) == 1952:
            # ML-DSA-65 (FIPS 204) — requires liboqs
            try:
                import oqs
                verifier = oqs.Signature("ML-DSA-65")
                return verifier.verify(message, sig_bytes, pubkey_bytes)
            except ImportError:
                return False  # liboqs not installed
        else:
            return False
    except Exception:
        return False


# ── Routes ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Trust Network Dashboard — visual overview of satellite status."""
    dashboard_path = Path(__file__).parent / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())
    return HTMLResponse(content="<h1>Satellite Online</h1><p>Dashboard not found.</p>")


@app.get("/chat")
async def chat_client():
    """Serve the E2E encrypted chat client."""
    chat_path = Path(__file__).parent / "chat.html"
    if chat_path.exists():
        return HTMLResponse(content=chat_path.read_text())
    return HTMLResponse(content="<h1>Chat client not found</h1>", status_code=404)


@app.get("/identities")
async def list_identities(
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    fingerprint: str = "",
):
    """List all registered identities — requires authentication.

    Returns full identity info (signing_pk, encryption_pk) only to authenticated users.
    Requires fingerprint query param + X-Signature header.
    """
    db = get_db()
    try:
        if not fingerprint or not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Authentication required — provide fingerprint and X-Signature")

        rows = db.execute(
            "SELECT fingerprint, COALESCE(name, display_name) as name, signing_pk, encryption_pk, pq_kem_pk, pq_sig_pk, crypto_version, identity_type, registered_at FROM identities"
        ).fetchall()
        return {"identities": [dict(r) for r in rows]}
    finally:
        db.close()


@app.get("/health")
async def health():
    """Health check for Docker/monitoring."""
    db = get_db()
    try:
        identity_count = db.execute("SELECT COUNT(*) FROM identities").fetchone()[0]
        pending_count = db.execute("SELECT COUNT(*) FROM messages WHERE retrieved = 0").fetchone()[0]
        return {
            "status": "online",
            "service": "satellite",
            "version": "0.2.0",
            "mode": SATELLITE_MODE,
            "identities": identity_count,
            "pending_messages": pending_count,
            "timestamp": now_iso(),
        }
    finally:
        db.close()


class BindSyncRequest(BaseModel):
    fingerprint: str
    sig_pubkey: str   # raw ed25519, lowercase hex
    nonce: str        # lowercase hex
    epoch: int
    binding_sig: str  # base64 Ed25519 over tag#2 (identity key)


class MailboxRegisterRequest(BaseModel):
    """Register/rekey a mailbox — spec §4.1 owner_sig pin.

    Stores pubkeys + owner-proof ONLY (I-E / §4.1: no durable user content).
    owner_sig authorizes with the IDENTITY key (same anchor as /bind tag#2)."""
    mailbox_fp: str = Field(..., min_length=64, max_length=64)      # lowercase hex SHA256(x25519||mlkem1024)
    x25519_pk: str = Field(..., min_length=64, max_length=64)        # 32B, lowercase hex
    mlkem1024_pk: str = Field(..., min_length=3136, max_length=3136)  # 1568B, lowercase hex
    owner_identity_fp: str = Field(..., min_length=8, max_length=128)  # full registered identity fingerprint
    epoch: int = Field(..., ge=0)                                    # per-owner monotonic anti-replay
    owner_sig: str = Field(..., description="base64 Ed25519(identity key, 'svrnty-mailbox-reg-v1:{owner_identity_fp}:{mailbox_fp}:{epoch}')")


@app.post("/bind")
async def bind_sig_pubkey_sync(req: BindSyncRequest):
    """gated-A: ingest a sig_pubkey binding propagated from the registration service.

    The satellite does NOT trust the transport — it RE-VERIFIES the tag#2 identity-key
    signature itself against its stored identity public_key (base64). Only a binding
    carrying a valid identity-key signature over
    "svrnty-bind:{hex(sig_pubkey)}:{hex(nonce)}:{epoch}" at the current epoch is
    accepted, so this endpoint is safe even if reachable. Idempotent set of sig_pubkey."""
    import base64
    fp = req.fingerprint
    if not (len(req.sig_pubkey) == 64 and all(c in "0123456789abcdef" for c in req.sig_pubkey)):
        raise HTTPException(status_code=400, detail="sig_pubkey must be 64 lowercase-hex chars")
    if not (all(c in "0123456789abcdef" for c in req.nonce) and len(req.nonce) % 2 == 0):
        raise HTTPException(status_code=400, detail="nonce must be lowercase hex")
    db = get_db()
    try:
        identity = db.execute(
            "SELECT public_key, epoch FROM identities WHERE fingerprint = ?",
            (fp,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Unknown fingerprint")
        current_epoch = identity["epoch"] if ("epoch" in identity.keys() and identity["epoch"] is not None) else 0
        if req.epoch != current_epoch:
            raise HTTPException(status_code=409, detail=f"stale epoch (current={current_epoch})")
        idpk = base64.b64decode(identity["public_key"])  # satellite stores identity key base64
        try:
            sig_bytes = base64.b64decode(req.binding_sig.replace(" ", "+"))
        except Exception:
            raise HTTPException(status_code=400, detail="binding_sig not valid base64")
        # tag#2 preimage (byte-exact with the reference vector + registration _bind_preimage)
        preimage = f"svrnty-bind:{req.sig_pubkey}:{req.nonce}:{req.epoch}".encode()
        if not _verify_with_key(idpk, sig_bytes, preimage):
            raise HTTPException(status_code=403, detail="invalid binding signature")
        # Single-use nonce floor (replay defense). Recorded ONLY after the sig
        # verifies, so a forged/invalid request can never grow bind_nonces (no DoS
        # amplification). A replayed valid bind-tuple reuses (fp, nonce) -> PK
        # collision -> 409. The consume + the sig_pubkey UPDATE ride ONE transaction
        # (the shared db.commit() below): on collision we raise before commit, the
        # finally closes the conn with nothing persisted (fail-closed, no TOCTOU).
        # This is what closes the same-epoch rollback hole — a captured tuple cannot
        # re-set sig_pubkey back to a rotated-out/compromised key.
        try:
            db.execute(
                "INSERT INTO bind_nonces (fingerprint, nonce, epoch) VALUES (?, ?, ?)",
                (fp, req.nonce, req.epoch),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="bind nonce already used (replay rejected)")
        db.execute("UPDATE identities SET sig_pubkey = ? WHERE fingerprint = ?", (req.sig_pubkey, fp))
        db.commit()
        return {"status": "bound", "fingerprint": fp, "epoch": req.epoch}
    finally:
        db.close()


def _norm_pk(v: Optional[str]) -> Optional[str]:
    """Normalize a stored/submitted key field for byte-equality comparison.

    Treats absent (NULL) and empty-string identically as 'absent'. This makes a
    genuine classical identity (NULL pq_kem_pk/pq_sig_pk) re-announcing without
    those keys a no-op, while ADDING a key (NULL-stored -> non-empty-submitted) is
    a real change that must fall through to the rotation signature gate.
    """
    return v if v else None


def _is_noop_reannounce(existing: sqlite3.Row, req: "RegisterRequest") -> bool:
    """True IFF the re-register submits crypto material byte-identical to what is
    stored — an idempotent re-announce, not a key rotation.

    register-403 fix. We compare STORED bytes, never
    the fingerprint: on the existing-identity path the satellite does NOT recompute
    fp == SHA256(keys), and the stored fingerprint is only a 16-char prefix match,
    so trusting it here would be a hijack surface. All crypto-material fields plus
    crypto_version must byte-match:
      - public_key     (== stored signing_pk by construction, see UPDATE/INSERT)
      - encryption_pk
      - pq_kem_pk
      - pq_sig_pk
      - crypto_version (a same-keys / different-version submit is a downgrade-class
                        change — e.g. flip to 'classical' to suppress PQ encap — and
                        must hit the sig gate, not be silently exempted)
    NULL-vs-empty is normalized (see _norm_pk) so 'absent' matches only 'absent',
    closing the NULL->PQ-ADD vector.
    """
    keys = existing.keys()

    def stored(col: str) -> Optional[str]:
        return existing[col] if col in keys else None

    if _norm_pk(req.public_key)    != _norm_pk(stored("public_key")):    return False
    if _norm_pk(req.encryption_pk) != _norm_pk(stored("encryption_pk")): return False
    if _norm_pk(req.pq_kem_pk)     != _norm_pk(stored("pq_kem_pk")):     return False
    if _norm_pk(req.pq_sig_pk)     != _norm_pk(stored("pq_sig_pk")):     return False
    if (req.crypto_version or "classical") != (stored("crypto_version") or "classical"):
        return False
    return True


@app.post("/register")
async def register_identity(req: RegisterRequest):
    """Register a planet's public key with this satellite.

    The satellite only stores public keys — never private keys.
    This establishes the planet's presence in the trust network.
    """
    # Sanitize display_name (H-2: prevent injection)
    req.display_name = sanitize_display_name(req.display_name)

    db = get_db()
    try:
        existing = db.execute(
            "SELECT fingerprint, public_key, encryption_pk, pq_kem_pk, pq_sig_pk, crypto_version "
            "FROM identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()

        if existing:
            # Revocation has PRECEDENCE over both the no-op exemption and rotation:
            # a revoked key can neither rotate NOR refresh its presence (last_seen).
            # (revoked fp + identical keys + no sig -> still 403.)
            revoked = db.execute(
                "SELECT revoked_at FROM revocations WHERE fingerprint = ?",
                (req.fingerprint,)
            ).fetchone()
            if revoked:
                raise HTTPException(
                    status_code=403,
                    detail="Cannot rotate a revoked key"
                )

            # register-403 fix: the client re-registers
            # on every Contacts mount WITHOUT a signature. A re-register of byte-
            # identical key material is an idempotent re-announce, NOT a rotation —
            # exempt it (touch last_seen only; return 409 per the client's
            # res.ok || res.status===409 contract). Without this, every re-announce
            # 403s -> buildPsiSyncOptions returns null -> the PSI /initiate sync loop
            # never restarts -> PSI discovery goes dark for real users. Reserve 403
            # for a genuine key change (rotation / downgrade / PQ-add).
            if _is_noop_reannounce(existing, req):
                db.execute(
                    "UPDATE identities SET last_seen = ? WHERE fingerprint = ?",
                    (now_iso(), req.fingerprint)
                )
                db.commit()
                raise HTTPException(
                    status_code=409,
                    detail="already registered (idempotent re-announce)"
                )

            # SECURITY: a genuine key rotation requires a signature from the EXISTING
            # key. Without this, anyone who knows a fingerprint could replace the key.
            if not req.signature:
                raise HTTPException(
                    status_code=403,
                    detail="Key rotation requires signature from existing key"
                )
            if not verify_request_signature(req.fingerprint, req.signature, db):
                raise HTTPException(
                    status_code=403,
                    detail="Invalid signature — prove you own the existing key before rotating"
                )
            old_key = existing["public_key"] if "public_key" in existing.keys() else None
            db.execute(
                """UPDATE identities SET public_key = ?, signing_pk = ?, encryption_pk = ?,
                   pq_kem_pk = ?, pq_sig_pk = ?, crypto_version = ?,
                   display_name = ?, name = ?, satellite_url = ?, safeword = ?, last_seen = ?
                   WHERE fingerprint = ?""",
                (req.public_key, req.public_key, req.encryption_pk,
                 req.pq_kem_pk, req.pq_sig_pk, req.crypto_version or "classical",
                 req.display_name, req.display_name, req.satellite_url, req.safeword,
                 now_iso(), req.fingerprint)
            )
            # Log rotation in append-only rotation_log
            announcement = json.dumps({
                "type": "key_rotation",
                "fingerprint": req.fingerprint,
                "reason": "voluntary",
                "timestamp": now_iso(),
            })
            db.execute(
                """INSERT INTO rotation_log
                   (old_fingerprint, new_fingerprint, reason, announcement, signature)
                   VALUES (?, ?, ?, ?, ?)""",
                (req.fingerprint, req.fingerprint, "voluntary", announcement, req.signature)
            )
            audit(db, "key_rotation", req.fingerprint)
        else:
            # SECURITY (C-1): Verify fingerprint is derived from public keys.
            # Three valid formats:
            #   1. Hybrid:   SHA256(sign + enc + kem + sig) — all 4 PQ keys
            #   2. Classical: SHA256(sign + enc) — bound pair
            #   3. Legacy:    SHA256(sign) — signing key only
            # Some clients truncate (e.g. first 16 chars) — accept prefix match.
            import base64 as _b64
            try:
                pk_bytes = _b64.b64decode(req.public_key)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid public_key encoding")
            if len(req.fingerprint) < 16:
                raise HTTPException(status_code=400, detail="Fingerprint too short (minimum 16 chars)")

            # Try hybrid fingerprint (4 keys). I-6 (LOCKED): enforce
            # EXACT per-alg pubkey lengths so the raw-concat fp is INJECTIVE (2nd-preimage-safe) —
            # Ed25519 sign=32, X25519 enc=32, ML-KEM-1024 kem=1568, ML-DSA-87 sig=2592. The fp
            # DERIVATION is UNCHANGED; wrong-length ⇒ this branch won't verify.
            verified = False
            if req.encryption_pk and req.pq_kem_pk and req.pq_sig_pk:
                try:
                    enc_b = _b64.b64decode(req.encryption_pk)
                    kem_b = _b64.b64decode(req.pq_kem_pk)
                    sig_b = _b64.b64decode(req.pq_sig_pk)
                    if len(pk_bytes) == 32 and len(enc_b) == 32 and len(kem_b) == 1568 and len(sig_b) == 2592:
                        h = hashlib.sha256()
                        h.update(pk_bytes)
                        h.update(enc_b)
                        h.update(kem_b)
                        h.update(sig_b)
                        if h.hexdigest().startswith(req.fingerprint):
                            verified = True
                except Exception:
                    pass
            # Try classical bound fingerprint (2 keys) — enforce sign=32, enc=32 (injective).
            if not verified and req.encryption_pk:
                try:
                    enc_b = _b64.b64decode(req.encryption_pk)
                    if len(pk_bytes) == 32 and len(enc_b) == 32:
                        h = hashlib.sha256()
                        h.update(pk_bytes)
                        h.update(enc_b)
                        if h.hexdigest().startswith(req.fingerprint):
                            verified = True
                except Exception:
                    pass
            # Try legacy fingerprint (signing key only) — enforce sign=32 (injective).
            if not verified:
                if len(pk_bytes) == 32 and hashlib.sha256(pk_bytes).hexdigest().startswith(req.fingerprint):
                    verified = True

            if not verified:
                raise HTTPException(
                    status_code=400,
                    detail="Fingerprint must equal SHA256 of public keys (hybrid/classical/legacy)"
                )
            db.execute(
                """INSERT INTO identities (fingerprint, public_key, signing_pk, encryption_pk,
                   pq_kem_pk, pq_sig_pk, crypto_version,
                   display_name, name, identity_type, satellite_url, safeword, registered_at, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (req.fingerprint, req.public_key, req.public_key, req.encryption_pk,
                 req.pq_kem_pk, req.pq_sig_pk, req.crypto_version or "classical",
                 req.display_name, req.display_name, req.identity_type,
                 req.satellite_url, req.safeword, now_iso(), now_iso())
            )
            audit(db, "register", req.fingerprint, f"{req.display_name} ({req.identity_type})")

        db.commit()
        return {"status": "registered", "fingerprint": req.fingerprint}
    finally:
        db.close()


@app.post("/mailbox/register")
async def register_mailbox(req: MailboxRegisterRequest):
    """Register (or rekey) a mailbox — spec §4.1 owner_sig pin.

    The relay stores ONLY the mailbox pubkeys + owner-proof epoch (I-E / §4.1: no
    durable user content — never PSI/blinders/allow-block/graph). owner_sig authorizes
    with the IDENTITY key (same trust anchor as /bind tag#2), RE-VERIFIED trustlessly
    here so the endpoint is safe even if reached directly.

    Verify steps (byte-exact to the ML-KEM-1024 conformance vector,
    mailbox_owner_sig_vector_mlkem1024):
      1. recompute mailbox_fp = SHA256(x25519_pk || mlkem1024_pk); 400 if != claimed
         (binds fp<->pubkeys — a client can't claim an fp not derived from its keys)
      2. load identities.public_key (base64) by owner_identity_fp; 404 if unknown
      3. preimage = "svrnty-mailbox-reg-v1:{owner_identity_fp}:{mailbox_fp}:{epoch}"
      4. Ed25519-verify owner_sig against the IDENTITY key; 403 if invalid
      5. anti-replay (refinement): register of an immutable fp->pubkeys
         binding is IDEMPOTENT (mailbox_fp = SHA256(pubkeys) => same fp == same content),
         so keep ONLY a per-MAILBOX epoch floor (never roll back one fp's epoch); one
         owner may hold many mailboxes. The monotonic rollback-guard belongs on the
         MUTABLE ops (rekey / rehydrate / relay-change), NOT this immutable create.
    """
    import base64
    # charset guards (lowercase hex) — model already pins lengths; parity with /bind
    for name, val in (("mailbox_fp", req.mailbox_fp), ("x25519_pk", req.x25519_pk),
                      ("mlkem1024_pk", req.mlkem1024_pk), ("owner_identity_fp", req.owner_identity_fp)):
        if not all(c in "0123456789abcdef" for c in val):
            raise HTTPException(status_code=400, detail=f"{name} must be lowercase hex")
    # 1. recompute + bind fp<->pubkeys (EXACT match; no prefix leniency for mailboxes)
    try:
        x_raw = bytes.fromhex(req.x25519_pk)
        k_raw = bytes.fromhex(req.mlkem1024_pk)
    except ValueError:
        raise HTTPException(status_code=400, detail="pubkeys must be valid hex")
    if len(x_raw) != 32 or len(k_raw) != 1568:
        raise HTTPException(status_code=400, detail="x25519_pk must be 32B, mlkem1024_pk 1568B")
    if hashlib.sha256(x_raw + k_raw).hexdigest() != req.mailbox_fp:
        raise HTTPException(status_code=400, detail="mailbox_fp != SHA256(x25519_pk||mlkem1024_pk)")

    db = get_db()
    try:
        # 2. load the owning identity's key (EXACT fp: full fp, not the C-1 prefix)
        identity = db.execute(
            "SELECT public_key FROM identities WHERE fingerprint = ?",
            (req.owner_identity_fp,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Unknown owner_identity_fp")
        # revoked identities cannot register mailboxes (parity with verify_request_signature)
        revoked = db.execute(
            "SELECT revoked_at FROM revocations WHERE fingerprint = ?",
            (req.owner_identity_fp,)
        ).fetchone()
        if revoked:
            raise HTTPException(status_code=403, detail="owner identity is revoked")
        # 3-4. verify owner_sig with the IDENTITY key (base64), exactly like /bind tag#2
        try:
            idpk = base64.b64decode(identity["public_key"])
            sig_bytes = base64.b64decode(req.owner_sig.replace(" ", "+"))
        except Exception:
            raise HTTPException(status_code=400, detail="owner_sig not valid base64")
        preimage = f"svrnty-mailbox-reg-v1:{req.owner_identity_fp}:{req.mailbox_fp}:{req.epoch}".encode()
        if not _verify_with_key(idpk, sig_bytes, preimage):
            raise HTTPException(status_code=403, detail="invalid owner_sig")
        # 5. Anti-replay (refinement): REGISTER of an immutable fp->pubkeys
        #    binding is IDEMPOTENT — mailbox_fp = SHA256(pubkeys), so same fp == same content —
        #    hence replaying a register is HARMLESS, epoch may be 0, and one owner may hold
        #    MANY mailboxes (each fp registers independently, no per-owner gate). The monotonic
        #    counter that blocks rollback BELONGS ON THE MUTABLE OPS (rekey / rehydrate /
        #    relay-change / metadata-update) — separate signed preimages, NOT this immutable
        #    create. Here we keep only a per-MAILBOX epoch floor (never roll back one fp's epoch).
        existing = db.execute(
            "SELECT epoch FROM mailboxes WHERE mailbox_fp = ?",
            (req.mailbox_fp,)
        ).fetchone()
        if existing:
            stored_epoch = max(existing["epoch"], req.epoch)
            db.execute(
                """UPDATE mailboxes SET x25519_pk = ?, mlkem1024_pk = ?, owner_identity_fp = ?,
                   epoch = ?, updated_at = ? WHERE mailbox_fp = ?""",
                (req.x25519_pk, req.mlkem1024_pk, req.owner_identity_fp, stored_epoch,
                 now_iso(), req.mailbox_fp)
            )
        else:
            stored_epoch = req.epoch
            db.execute(
                """INSERT INTO mailboxes (mailbox_fp, x25519_pk, mlkem1024_pk,
                   owner_identity_fp, epoch, registered_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (req.mailbox_fp, req.x25519_pk, req.mlkem1024_pk, req.owner_identity_fp,
                 req.epoch, now_iso(), now_iso())
            )
        audit(db, "mailbox_register", req.owner_identity_fp,
              f"mailbox_fp={req.mailbox_fp[:16]}… epoch={stored_epoch}")
        db.commit()
        return {"status": "registered", "mailbox_fp": req.mailbox_fp, "epoch": stored_epoch}
    finally:
        db.close()


@app.get("/mailbox/{mailbox_fp}")
async def get_mailbox(mailbox_fp: str):
    """Return a mailbox's public keys so a sender can PQ-seal to it (spec §4.1).

    Returns ONLY pubkeys + epoch — NEVER owner_identity_fp (I-B / §4.5: the registry
    must not let a caller or the relay map mailbox->identity for routing) and never
    any user content. Unknown fp -> uniform 404."""
    if not (len(mailbox_fp) == 64 and all(c in "0123456789abcdef" for c in mailbox_fp)):
        raise HTTPException(status_code=400, detail="mailbox_fp must be 64 lowercase-hex chars")
    db = get_db()
    try:
        row = db.execute(
            "SELECT mailbox_fp, x25519_pk, mlkem1024_pk, epoch FROM mailboxes WHERE mailbox_fp = ?",
            (mailbox_fp,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Unknown mailbox")
        return {
            "mailbox_fp": row["mailbox_fp"],
            "x25519_pk": row["x25519_pk"],
            "mlkem1024_pk": row["mlkem1024_pk"],
            "epoch": row["epoch"],
        }
    finally:
        db.close()


@app.post("/revoke")
async def revoke_key(req: RevokeRequest):
    """Revoke a key permanently. Must be signed by the key being revoked.

    Once revoked, the key cannot authenticate, send messages, or be rotated.
    Revocation is permanent and cannot be undone. This is the sovereignty guarantee:
    only the key holder can revoke their own key.
    """
    db = get_db()
    try:
        # Check key exists
        identity = db.execute(
            "SELECT fingerprint FROM identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        # Check not already revoked
        existing_revocation = db.execute(
            "SELECT revoked_at FROM revocations WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if existing_revocation:
            raise HTTPException(status_code=409, detail="Key already revoked")

        # Verify signature (proves caller holds the private key)
        if not verify_request_signature(req.fingerprint, req.signature, db):
            raise HTTPException(
                status_code=403,
                detail="Invalid signature — prove you own the key to revoke it"
            )

        # Insert revocation record (permanent, append-only)
        db.execute(
            """INSERT INTO revocations
               (fingerprint, revoked_at, successor, reason, signed_by, signature)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (req.fingerprint, now_iso(), req.successor, req.reason,
             req.fingerprint, req.signature)
        )
        audit(db, "key_revocation", req.fingerprint,
              f"reason={req.reason}, successor={req.successor}")
        db.commit()
        return {
            "status": "revoked",
            "fingerprint": req.fingerprint,
            "reason": req.reason,
            "revoked_at": now_iso(),
        }
    finally:
        db.close()


@app.get("/revocation/{fingerprint}")
async def check_revocation(fingerprint: str):
    """Check if a fingerprint has been revoked. Unauthenticated (public info).

    Returns revocation details if revoked, 404 if not revoked.
    This endpoint is intentionally public — revocation status is not secret.
    """
    db = get_db()
    try:
        row = db.execute(
            "SELECT revoked_at, reason, successor FROM revocations WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not revoked")
        return {
            "revoked": True,
            "fingerprint": fingerprint,
            "revoked_at": row["revoked_at"],
            "reason": row["reason"],
            "successor": row["successor"],
        }
    finally:
        db.close()


@app.get("/rotation-log/{fingerprint}")
async def get_rotation_log(fingerprint: str):
    """Get the rotation history for a fingerprint. Unauthenticated (public info).

    Returns the append-only log of key rotations. This is the per-identity
    certificate transparency log — each rotation references its predecessor.
    """
    db = get_db()
    try:
        rows = db.execute(
            """SELECT old_fingerprint, new_fingerprint, reason, created_at
               FROM rotation_log
               WHERE old_fingerprint = ? OR new_fingerprint = ?
               ORDER BY created_at ASC""",
            (fingerprint, fingerprint)
        ).fetchall()
        return {
            "fingerprint": fingerprint,
            "rotations": [
                {
                    "old_fingerprint": r["old_fingerprint"],
                    "new_fingerprint": r["new_fingerprint"],
                    "reason": r["reason"],
                    "timestamp": r["created_at"],
                }
                for r in rows
            ],
        }
    finally:
        db.close()


@app.get("/export/{fingerprint}")
async def export_satellite(fingerprint: str, x_signature: Optional[str] = Header(None, alias="X-Signature")):
    """Generate a personalized satellite Docker package for self-hosting.

    Returns a zip containing docker-compose.yml, Caddyfile, config.json, and README.
    The tree is contained in the seed.
    Requires signature auth — prove you own this identity before downloading.
    """
    from fastapi.responses import StreamingResponse
    import io, zipfile, json as json_mod, secrets

    db = get_db()
    try:
        # SECURITY (C-2): Require signature auth — /export includes full source code.
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Prove you own this identity")

        identity = db.execute(
            "SELECT fingerprint, display_name, name, satellite_url FROM identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Unknown fingerprint")

        config = {
            "name": identity["name"] or identity["display_name"] or fingerprint[:8],
            "fingerprint": fingerprint,
            "url": identity["satellite_url"] or "",
        }

        # Read source files for the self-host package
        import pathlib
        src_dir = pathlib.Path(__file__).parent
        satellite_src = (src_dir / "satellite.py").read_text()
        crypto_src = (src_dir / "crypto_utils.py").read_text()
        registration_src = (src_dir / "registration.py").read_text()

        # Auto-provision a strong admin key so `docker compose up` works out-of-the-box —
        # the satellite lifespan FAIL-CLOSES without SATELLITE_ADMIN_KEY (>=20 chars).
        # Written to .env in the package (compose auto-loads it); gates cleanup endpoints.
        gen_admin_key = secrets.token_urlsafe(24)

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Relay source — EVERY module satellite.py imports at module scope MUST be bundled:
            # mailbox_envelope + satellite_keys are REQUIRED (omitting them = ModuleNotFound on
            # startup — the pre-existing break that made self-host never run) + crypto_utils
            # (client kit) + registration + the served UI (dashboard/chat, COPY'd by the keystone
            # Dockerfile). Read the REAL tracked files — no heredoc copies that silently drift.
            zf.writestr('satellite.py', satellite_src)
            zf.writestr('mailbox_envelope.py', (src_dir / "mailbox_envelope.py").read_text())
            zf.writestr('satellite_keys.py', (src_dir / "satellite_keys.py").read_text())
            zf.writestr('crypto_utils.py', crypto_src)
            zf.writestr('registration.py', registration_src)
            zf.writestr('dashboard.html', (src_dir / "dashboard.html").read_text())
            zf.writestr('chat.html', (src_dir / "chat.html").read_text())
            # registration UI (COPY'd by Dockerfile.registration)
            zf.writestr('landing.html', (src_dir / "landing.html").read_text())
            zf.writestr('profile.html', (src_dir / "profile.html").read_text())
            zf.writestr('about.html', (src_dir / "about.html").read_text())

            # The REAL hardened self-host compose (read_only + cap_drop ALL + no-new-privileges
            # + tmpfs + persistent volume + admin-key wiring). Bundled verbatim from the tracked
            # file → hardened by construction, drift-proof (no heredoc mirror to diverge).
            zf.writestr('docker-compose.yml', (src_dir / "self-host" / "docker-compose.yml").read_text())
            # .env — holds the auto-generated admin key (docker compose auto-loads it).
            # Keep private (gates cleanup endpoints); the relay will NOT start without it.
            zf.writestr('.env', f"""# svrnty self-host secrets — keep private, do NOT commit
SATELLITE_ADMIN_KEY={gen_admin_key}
# Optional: set to your frontend origin(s) if you are NOT using the svrnty.is client
# CORS_ORIGINS=https://your-domain.example
""")
            # The REAL converged keystone Dockerfile (liboqs/ML-KEM-1024 multi-stage, non-root,
            # chown /data, --no-access-log) + the REAL registration Dockerfile. Bundled verbatim
            # from the tracked files → crypto-full + hardened by construction, drift-proof. The
            # self-hoster compiles liboqs from source on `docker compose build` (I-C: zero
            # dependency on a svrnty registry — the tree is contained in the seed).
            zf.writestr('Dockerfile.satellite', (src_dir / "Dockerfile").read_text())
            zf.writestr('Dockerfile.registration', (src_dir / "Dockerfile.registration").read_text())
            # config.json
            zf.writestr('config.json', json_mod.dumps({
                "identity": config,
                "crypto": {"version": "hybrid-v1", "key_exchange": "X25519+ML-KEM-1024"},
                "relay": {"max_message_size": 65536, "enforce_encryption": True, "mode": "full"}
            }, indent=2))
            # README
            zf.writestr('README.md', f"""# Your svrnty Satellite — {config['name']}

Fingerprint: `{config['fingerprint']}`

## Quick Start

```bash
docker compose up -d
curl http://localhost:8100/health
```

Your satellite runs in **full mode** — contact sharing AND messaging.
Your trust graph lives on your phone/planet — the satellite is a dumb relay.

## Your admin key
A unique `SATELLITE_ADMIN_KEY` was generated for you in `.env` (docker compose loads
it automatically). Keep `.env` private — it gates the maintenance/cleanup endpoints,
and **your relay will not start without it**.

## The tree is contained in the seed.
Your identity lives in your .svrnty file, not on any server.
""")

            # Snapshot: allowed senders list
            allowed = db.execute("""
                SELECT sender_fingerprint, added_at
                FROM allowed_senders WHERE owner_fingerprint = ?
                ORDER BY sender_fingerprint
            """, (fingerprint,)).fetchall()

            audit_rows = db.execute(
                "SELECT event, details, timestamp FROM audit_log WHERE fingerprint = ? ORDER BY id",
                (fingerprint,)
            ).fetchall()
            audit_hash = _audit_chain_hash(audit_rows)

            snapshot = {
                "version": 3, "type": "satellite_export", "fingerprint": fingerprint,
                "generated_at": now_iso(),
                "allowed_senders": [{"fingerprint": a["sender_fingerprint"], "added_at": a["added_at"]} for a in allowed],
                "audit_chain_hash": audit_hash, "audit_entry_count": len(audit_rows),
                "satellite_url": config.get("url"),
            }
            zf.writestr('snapshot.json', json_mod.dumps(snapshot, indent=2, sort_keys=True))

        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename={config['name']}_satellite.zip"}
        )
    finally:
        db.close()


@app.get("/qr/{fingerprint}")
async def generate_qr(fingerprint: str, size: int = 10):
    """Generate a QR code PNG for a fingerprint.

    The QR encodes the fingerprint string — scan to add someone as a contact.
    Size parameter controls box size (1-20, default 10).
    """
    from fastapi.responses import Response
    import io

    try:
        import qrcode
    except ImportError:
        raise HTTPException(status_code=500, detail="QR code library not installed")

    size = max(1, min(20, size))

    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, COALESCE(name, display_name) as name FROM identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not registered")

        # QR encodes: svrnty:<fingerprint>
        qr_data = f"svrnty:{fingerprint}"

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=size, border=4)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        name = identity["name"] or fingerprint[:8]
        return Response(
            content=buf.getvalue(),
            media_type="image/png",
            headers={"Content-Disposition": f'inline; filename="{name}_qr.png"'}
        )
    finally:
        db.close()


@app.get("/vcard/{fingerprint}")
async def generate_vcard(fingerprint: str):
    """Generate a vCard (.vcf) for an identity.

    Contains the name and fingerprint as a note. Contact cards (phone, email)
    are encrypted per-recipient, so vCard contains only public identity info.
    """
    from fastapi.responses import Response

    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, COALESCE(name, display_name) as name, registered_at FROM identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not registered")

        name = identity["name"] or fingerprint[:16]
        # Standard vCard 3.0 format
        vcard = f"""BEGIN:VCARD
VERSION:3.0
FN:{name}
NOTE:svrnty fingerprint: {fingerprint}
URL:https://svrnty.is/u/{fingerprint[:16]}
END:VCARD"""

        return Response(
            content=vcard,
            media_type="text/vcard",
            headers={"Content-Disposition": f'attachment; filename="{name}.vcf"'}
        )
    finally:
        db.close()


# /update-route REMOVED — §7.4, svrnty launch 2026-09-12.
# It signed {fp|url|ts|nonce} but NEVER enforced the ts/nonce → a captured relocation REPLAYS to
# re-point an identity's relay = delivery HIJACK ("the sig is real; the replay guard is fiction").
# VESTIGIAL: no production caller — the client uses ONE configured relay (resolveRelayBase, single-
# relay-per-user, "NOT federation"); identities.satellite_url (what this wrote) is
# never read by client routing; migration = sovereign-rehydrate (the book re-derives on the relay
# YOU run). Removed by construction — no counter to get wrong, no attack surface.


# ── Allowed Senders (Bouncer List) ────────────────────────
#
# The phone/planet manages the trust graph. It pushes a whitelist
# of allowed senders to the satellite. The satellite enforces it
# for message delivery and PSI.

@app.post("/allowed/{owner_fingerprint}")
async def add_allowed_sender(owner_fingerprint: str, req: AllowedSenderRequest):
    """Add a sender to the allowed list. Auth: Ed25519 sig from owner's key."""
    db = get_db()
    try:
        if not verify_allowed_change_signature(owner_fingerprint, req.sender_fingerprint, req.signature, db, _allowed_add_preimage):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        if owner_fingerprint == req.sender_fingerprint:
            raise HTTPException(status_code=400, detail="Cannot add yourself to allowed list")

        now = now_iso()
        try:
            db.execute(
                "INSERT INTO allowed_senders (owner_fingerprint, sender_fingerprint, added_at) VALUES (?, ?, ?)",
                (owner_fingerprint, req.sender_fingerprint, now)
            )
        except sqlite3.IntegrityError:
            return {"status": "already_allowed", "sender_fingerprint": req.sender_fingerprint}

        audit(db, "allowed_added", owner_fingerprint, f"sender={req.sender_fingerprint[:16]}...")

        # Check for mutual add — if the other person already added us, notify both
        mutual = db.execute(
            "SELECT 1 FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
            (req.sender_fingerprint, owner_fingerprint)
        ).fetchone()

        is_mutual = False
        if mutual:
            is_mutual = True
            # Notify both parties that the connection is mutual
            owner_name = _get_display_name(db, owner_fingerprint)
            sender_name = _get_display_name(db, req.sender_fingerprint)

            for recipient, other_name in [
                (owner_fingerprint, sender_name),
                (req.sender_fingerprint, owner_name),
            ]:
                notification = json.dumps({
                    "type": "mutual_contact",
                    "partner": owner_fingerprint if recipient == req.sender_fingerprint else req.sender_fingerprint,
                    "partner_name": other_name,
                    "message": f"Mutual connection established with {other_name}",
                    "at": now,
                })
                db.execute(
                    "INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES (?, ?, ?, ?)",
                    (recipient, "satellite:system", notification, now)
                )
            audit(db, "mutual_contact", owner_fingerprint, f"mutual with {req.sender_fingerprint[:16]}...")

        db.commit()
        return {
            "status": "allowed",
            "sender_fingerprint": req.sender_fingerprint,
            "added_at": now,
            "mutual": is_mutual,
        }
    finally:
        db.close()


@app.delete("/allowed/{owner_fingerprint}/{sender_fingerprint}")
async def remove_allowed_sender(
    owner_fingerprint: str,
    sender_fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Remove a sender from the allowed list. Auth: Ed25519 sig from owner's key."""
    db = get_db()
    try:
        if not verify_allowed_change_signature(owner_fingerprint, sender_fingerprint, x_signature, db, _allowed_remove_preimage):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        result = db.execute(
            "DELETE FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
            (owner_fingerprint, sender_fingerprint)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Sender not in allowed list")

        audit(db, "allowed_removed", owner_fingerprint, f"sender={sender_fingerprint[:16]}...")
        db.commit()
        return {"status": "removed", "sender_fingerprint": sender_fingerprint}
    finally:
        db.close()


@app.get("/allowed/{owner_fingerprint}")
async def list_allowed_senders(
    owner_fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """List allowed senders for an identity. Returns fingerprints only (no metadata).
    Auth: Ed25519 sig from owner's key."""
    db = get_db()
    try:
        if not verify_request_signature(owner_fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        rows = db.execute(
            "SELECT sender_fingerprint FROM allowed_senders WHERE owner_fingerprint = ? ORDER BY sender_fingerprint",
            (owner_fingerprint,)
        ).fetchall()

        return {
            "owner_fingerprint": owner_fingerprint,
            "allowed": [r["sender_fingerprint"] for r in rows],
            "count": len(rows),
        }
    finally:
        db.close()


@app.get("/allowed/{fingerprint}/inbound")
async def list_inbound_adds(
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Who has added me to their allowed list? Returns fingerprints + names.

    This lets a user discover pending contact requests — people who added
    them but whom they haven't added back yet. Auth: Ed25519 sig from owner's key.
    """
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        # Find everyone who has me in their allowed_senders list
        rows = db.execute(
            """SELECT a.owner_fingerprint, a.added_at,
                      COALESCE(i.name, i.display_name) as name,
                      i.identity_type
               FROM allowed_senders a
               LEFT JOIN identities i ON i.fingerprint = a.owner_fingerprint
               WHERE a.sender_fingerprint = ?
               ORDER BY a.added_at DESC""",
            (fingerprint,)
        ).fetchall()

        # Check which ones I've added back (mutual)
        my_allowed = set(
            r["sender_fingerprint"] for r in db.execute(
                "SELECT sender_fingerprint FROM allowed_senders WHERE owner_fingerprint = ?",
                (fingerprint,)
            ).fetchall()
        )

        inbound = []
        for r in rows:
            inbound.append({
                "fingerprint": r["owner_fingerprint"],
                "name": r["name"] or r["owner_fingerprint"][:8],
                "identity_type": r["identity_type"] or "human",
                "added_at": r["added_at"],
                "mutual": r["owner_fingerprint"] in my_allowed,
            })

        return {
            "fingerprint": fingerprint,
            "inbound": inbound,
            "pending": [i for i in inbound if not i["mutual"]],
            "mutual_count": sum(1 for i in inbound if i["mutual"]),
        }
    finally:
        db.close()


# ── Sovereign Trust-Rendezvous (Track C, Charter §8.5) ─────
# Blind relay backing the sovereign trust-edge listener
# (src/lib/trust/trust-rendezvous.ts, PR#130). deposit/poll implement the client's TrustRelay
# interface. UNAUTHED BY DESIGN: the capability IS knowing the rendezvous tag R (HKDF over the
# two VERIFY'd peers' X25519 DH secret — the relay cannot compute it), and every beacon is
# Ed25519-signed + PQ-hybrid-sealed to the recipient's mailbox. Adding an auth layer would leak
# who deposits/polls at R and defeat §8.5 sovereignty (the relay must never learn who trusts
# whom). Security = R-secrecy + sealed blobs + bounds (size cap + per-R ring cap + rate-limit).
# The relay stays blind: it never parses the sealed blob, stores no identity/sender/graph, and
# cannot be enumerated (poll requires the exact R).


class RendezvousDepositRequest(BaseModel):
    """Append a signed+sealed trust beacon at rendezvous tag R (Track C)."""
    r: str = Field(..., min_length=43, max_length=64)                  # base64 of the 32B R tag
    blob: str = Field(..., min_length=1, max_length=MAX_MESSAGE_SIZE)  # opaque sealed beacon envelope


class RendezvousPollRequest(BaseModel):
    """Poll all sealed beacons at rendezvous tag R — exact match, no enumerate (Track C)."""
    r: str = Field(..., min_length=43, max_length=64)


def _decode_rendezvous_tag(r: str) -> Optional[bytes]:
    """Return the 32 raw bytes of a base64 rendezvous tag R, or None if it is not a valid 32-byte
    tag. Accepts standard and url-safe base64, padded or not — the relay only needs to confirm R
    is a real 32B tag (this constrains the key space so the endpoint can't be abused as an
    arbitrary-key blob store) and then uses the string verbatim as the DB key."""
    import base64
    s = r.strip()
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except Exception:
            continue
        if len(raw) == 32:
            return raw
    return None


@app.post("/trust/rendezvous/deposit", dependencies=[Depends(require_full_mode)])
async def rendezvous_deposit(req: RendezvousDepositRequest):
    """Append a sealed trust-beacon blob at rendezvous tag R. Idempotent on exact bytes
    (retry / migration-rehydrate no-op); per-R ring-buffer evicts the oldest past the cap so the
    newest beacon is never dropped. Blind: no identity resolved, no audit of R (no R<->IP map)."""
    if _decode_rendezvous_tag(req.r) is None:
        raise HTTPException(status_code=400, detail="r must be base64 of a 32-byte rendezvous tag")
    blob_hash = hashlib.sha256(req.blob.encode("utf-8")).hexdigest()
    db = get_db()
    try:
        # Clean expired blobs first (opportunistic sweep-on-deposit) — the PRIMARY storage bound
        # for this unauthed endpoint. Blindness => GC by deposit wall-clock, not
        # by the beacon's sealed epoch. Mirrors the PSI-session TTL sweep pattern.
        cutoff = datetime.now(timezone.utc).timestamp() - RENDEZVOUS_TTL_SECONDS
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        db.execute("DELETE FROM rendezvous WHERE deposited_at < ?", (cutoff_iso,))
        cur = db.execute(
            "INSERT OR IGNORE INTO rendezvous (r_tag, blob, blob_hash, deposited_at) VALUES (?, ?, ?, ?)",
            (req.r, req.blob, blob_hash, now_iso()),
        )
        if cur.rowcount > 0:
            count = db.execute(
                "SELECT COUNT(*) FROM rendezvous WHERE r_tag = ?", (req.r,)
            ).fetchone()[0]
            if count > MAX_BLOBS_PER_RENDEZVOUS:
                db.execute(
                    "DELETE FROM rendezvous WHERE id IN ("
                    " SELECT id FROM rendezvous WHERE r_tag = ? ORDER BY id ASC LIMIT ?)",
                    (req.r, count - MAX_BLOBS_PER_RENDEZVOUS),
                )
        db.commit()
        return {"deposited": True}
    finally:
        db.close()


@app.post("/trust/rendezvous/poll", dependencies=[Depends(require_full_mode)])
async def rendezvous_poll(req: RendezvousPollRequest):
    """Return all sealed beacon blobs currently at rendezvous tag R (base64). The client opens
    each (wrong-recipient->null is the collision filter) and verifies the depositor's sig."""
    if _decode_rendezvous_tag(req.r) is None:
        raise HTTPException(status_code=400, detail="r must be base64 of a 32-byte rendezvous tag")
    db = get_db()
    try:
        rows = db.execute(
            "SELECT blob FROM rendezvous WHERE r_tag = ? ORDER BY id ASC LIMIT ?",
            (req.r, MAX_BLOBS_PER_RENDEZVOUS),
        ).fetchall()
        return {"blobs": [row["blob"] for row in rows]}
    finally:
        db.close()


# ── Onion blind-router (K0 outer-peel / K1 route) ─────────
# The satellite is the RECIPIENT of the OUTER shell: it peels it with its OWN routing keypair
# (satellite_keys.py) → learns only {route_id, fp-stripped inner} → deposits the still-device-sealed
# `inner` under the K1-blinded rotating route_id. It CANNOT read `inner` (sealed to the recipient
# DEVICE) and stores NO recipient identity (K0-1 strip enforced on the peel output). Peel byte-exact
# to onion-envelope.ts / mailbox-envelope.ts; verified 3 ways. Full mode only.

class OnionPackage(BaseModel):
    """The OUTER onion shell = a MailboxEnvelopePackage sealed to the SATELLITE's routing key.
    Basic shape/size bounds only; peel_onion is hostile-input-safe and performs the real gate."""
    v: int
    alg: str = Field(..., max_length=64)
    mailbox_fp: str = Field(..., min_length=64, max_length=64)
    epk: str = Field(..., min_length=1, max_length=128)        # b64(32B) ≈ 44
    kem_ct: str = Field(..., min_length=1, max_length=4096)    # b64(1568B) ≈ 2092
    nonce: str = Field(..., min_length=1, max_length=64)       # b64(12B) ≈ 16
    ct: str = Field(..., min_length=1, max_length=MAX_MESSAGE_SIZE)


def _valid_route_id(route_id: str) -> bool:
    """K1 route_id = HKDF(rk,'svrnty-route-id-v1')[:16] as hex → exactly 32 lowercase-hex chars
    (route-ratchet.ts:63/104)."""
    return len(route_id) == 32 and all(c in "0123456789abcdef" for c in route_id)


@app.get("/satellite/key", dependencies=[Depends(require_full_mode)])
async def satellite_key():
    """Serve the satellite's OWN routing PUBLIC keys so a client can seal the K0 OUTER shell to it
    (sealOnion). Public info only — the secret half never leaves the box. mailbox_fp binds the pair."""
    _, pub, fp = load_satellite_keypair(SATELLITE_KEY_PATH)
    return {"alg": MAILBOX_ENV_ALG, "x25519_pk": pub["x25519_pk"],
            "mlkem1024_pk": pub["mlkem1024_pk"], "mailbox_fp": fp}


@app.post("/onion", dependencies=[Depends(require_full_mode)])
async def onion_deposit(pkg: OnionPackage):
    """PEEL an OUTER onion shell → deposit the device-sealed `inner` into its route_id bucket.

    A peel failure returns a UNIFORM 400 — no oracle on why (wrong-key / tamper / malformed all
    collapse to None inside peel_onion). Idempotent on exact re-deposit (retry no-op); per-route
    ring-buffer evicts the oldest past the cap so the newest is never dropped; TTL-GC bounds total
    growth. Deliberately UN-audited: a route_id↔time(↔IP) trail would defeat K0/K1 blindness."""
    sat_sec, _, sat_fp = load_satellite_keypair(SATELLITE_KEY_PATH)
    peeled = peel_onion(pkg.model_dump(), sat_sec, sat_fp)
    if peeled is None:
        raise HTTPException(status_code=400, detail="invalid onion envelope")
    route_id = peeled["route"]
    if not _valid_route_id(route_id):
        # bounds the key space (like rendezvous requires a 32B R) so the router can't be abused as an
        # arbitrary-key blob store. A well-formed onion always carries a 32-hex K1 route_id.
        raise HTTPException(status_code=400, detail="invalid route_id")
    inner_json = json.dumps(peeled["inner"], separators=(",", ":"), sort_keys=True)
    inner_hash = hashlib.sha256(inner_json.encode("utf-8")).hexdigest()
    db = get_db()
    try:
        cutoff = datetime.now(timezone.utc).timestamp() - ONION_TTL_SECONDS
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        db.execute("DELETE FROM route_buckets WHERE deposited_at < ?", (cutoff_iso,))
        cur = db.execute(
            "INSERT OR IGNORE INTO route_buckets (route_id, inner_json, inner_hash, deposited_at) "
            "VALUES (?, ?, ?, ?)",
            (route_id, inner_json, inner_hash, now_iso()),
        )
        if cur.rowcount > 0:
            count = db.execute(
                "SELECT COUNT(*) FROM route_buckets WHERE route_id = ?", (route_id,)
            ).fetchone()[0]
            if count > MAX_ONION_PER_ROUTE:
                db.execute(
                    "DELETE FROM route_buckets WHERE id IN ("
                    " SELECT id FROM route_buckets WHERE route_id = ? ORDER BY id ASC LIMIT ?)",
                    (route_id, count - MAX_ONION_PER_ROUTE),
                )
        db.commit()
        return {"deposited": True}
    finally:
        db.close()


@app.get("/route/{route_id}", dependencies=[Depends(require_full_mode)])
async def route_poll(route_id: str):
    """Return all device-sealed inner packages currently at a K1 route_id (opaque). The recipient
    polls its OWN rotating route_id and opens each inner with its device key (openOnionInner) — a
    wrong/other inner won't open. Exact-match only — no enumerate."""
    if not _valid_route_id(route_id):
        raise HTTPException(status_code=400, detail="route_id must be 32 lowercase-hex chars")
    db = get_db()
    try:
        rows = db.execute(
            "SELECT inner_json FROM route_buckets WHERE route_id = ? ORDER BY id ASC LIMIT ?",
            (route_id, MAX_ONION_PER_ROUTE),
        ).fetchall()
        return {"inners": [json.loads(row["inner_json"]) for row in rows]}
    finally:
        db.close()


# ── Messaging ─────────────────────────────────────────────

@app.post("/send", dependencies=[Depends(require_full_mode)])
async def send_message(req: SendMessageRequest):
    """Queue an encrypted message for a registered identity.

    Messages are stored as opaque encrypted blobs — the satellite
    cannot read them. Only the planet with the private key can decrypt.
    Sender must be in recipient's allowed list.
    """
    db = get_db()
    try:
        # Verify sender owns the key (prevent impersonation)
        if not verify_request_signature(req.sender_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own the sender key")

        # Per-identity rate limit (contain compromised identity flooding)
        if not check_identity_send_rate(req.sender_fingerprint):
            raise HTTPException(status_code=429, detail="Per-identity send rate limit exceeded (10/min)")

        # Verify recipient exists
        recipient = db.execute(
            "SELECT fingerprint FROM identities WHERE fingerprint = ?",
            (req.recipient,)
        ).fetchone()
        if not recipient:
            raise HTTPException(status_code=404, detail="Recipient not registered")

        # Block check — silently reject if blocked
        init_block_table()
        if is_blocked(db, req.sender_fingerprint, req.recipient):
            # Return success to sender (silent block — don't reveal block status)
            return {"status": "queued", "message_id": -1, "pending": 0}

        # Allowed senders check — sender must be in recipient's allowed list
        allowed = db.execute(
            "SELECT 1 FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
            (req.recipient, req.sender_fingerprint)
        ).fetchone()
        if not allowed:
            raise HTTPException(status_code=403, detail="Not in recipient's allowed senders list")

        # Encryption enforcement — reject plaintext
        plaintext_err = reject_plaintext(req.encrypted_blob)
        if plaintext_err:
            audit(db, "plaintext_rejected", req.recipient, f"from={req.sender_fingerprint}")
            db.commit()
            raise HTTPException(status_code=400, detail=plaintext_err)

        # Check queue limits
        pending = db.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient = ? AND retrieved = 0",
            (req.recipient,)
        ).fetchone()[0]
        if pending >= MAX_QUEUE_PER_IDENTITY:
            raise HTTPException(status_code=429, detail="Message queue full")

        cursor = db.execute(
            "INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES (?, ?, ?, ?)",
            (req.recipient, req.sender_fingerprint, req.encrypted_blob, now_iso())
        )
        msg_id = cursor.lastrowid
        audit(db, "message_queued", req.recipient, f"from={req.sender_fingerprint}, id={msg_id}")
        db.commit()

        return {"status": "queued", "message_id": msg_id, "pending": pending + 1}
    finally:
        db.close()


@app.get("/retrieve/{fingerprint}", dependencies=[Depends(require_full_mode)])
async def retrieve_messages(
    fingerprint: str,
    limit: int = 50,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Retrieve pending messages for a planet that just came online.

    Requires X-Signature header: Ed25519(sk, fingerprint:timestamp_minute).
    This proves the requester holds the private key — prevents anyone who
    knows a fingerprint from draining someone else's message queue.

    Messages are marked as retrieved but kept for the retention period.
    The planet decrypts them locally with its private key.
    """
    db = get_db()
    try:
        # Verify identity exists
        identity = db.execute(
            "SELECT fingerprint FROM identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not registered")

        # Verify signature — prove you hold the private key
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid or missing signature. Sign: Ed25519(sk, fingerprint:timestamp_minute)")

        # Get pending messages
        messages = db.execute(
            "SELECT id, sender_fingerprint, encrypted_blob, created_at FROM messages WHERE recipient = ? AND retrieved = 0 ORDER BY created_at ASC LIMIT ?",
            (fingerprint, limit)
        ).fetchall()

        # NOTE: Messages are NOT marked as retrieved here.
        # Client must call POST /ack/{fingerprint} with message IDs
        # after saving them to disk. This prevents message loss if the
        # client crashes between retrieve and write.
        msg_ids = [m["id"] for m in messages]

        # Update last_seen
        db.execute(
            "UPDATE identities SET last_seen = ? WHERE fingerprint = ?",
            (now_iso(), fingerprint)
        )
        db.commit()

        return {
            "fingerprint": fingerprint,
            "count": len(messages),
            "messages": [
                {
                    "id": m["id"],
                    "sender": m["sender_fingerprint"],
                    "encrypted_blob": m["encrypted_blob"],
                    "queued_at": m["created_at"],
                }
                for m in messages
            ],
        }
    finally:
        db.close()


# ── Acknowledge Retrieved Messages ─────────────────────────

@app.post("/ack/{fingerprint}", dependencies=[Depends(require_full_mode)])
async def ack_messages(
    fingerprint: str,
    body: dict,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Acknowledge that messages have been safely written to disk.

    Client calls this AFTER saving retrieved messages locally.
    Only then does the server mark them as retrieved.

    Body: {"message_ids": [1, 2, 3]}
    """
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature")

        msg_ids = body.get("message_ids", [])
        if not msg_ids:
            return {"acked": 0}
        msg_ids = msg_ids[:1000]  # Cap to prevent unbounded SQL IN clause

        # Only ack messages that belong to this fingerprint (prevent cross-user ack)
        placeholders = ",".join("?" * len(msg_ids))
        db.execute(
            f"UPDATE messages SET retrieved = 1, retrieved_at = ? WHERE id IN ({placeholders}) AND recipient = ?",
            [now_iso()] + msg_ids + [fingerprint]
        )
        audit(db, "messages_acked", fingerprint, f"count={len(msg_ids)}")
        db.commit()

        return {"acked": len(msg_ids)}
    finally:
        db.close()


# ── Delivery Guarantees ────────────────────────────────────

@app.get("/msg/status/{message_id}")
async def message_status(
    message_id: int,
    fingerprint: str = "",
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Check delivery status of a sent message.

    Returns: queued (waiting), delivered (retrieved by recipient), expired (TTL exceeded).
    Sender can poll this to confirm delivery.

    Requires fingerprint query param + X-Signature header.
    Only the sender can check their own message status.
    """
    db = get_db()
    try:
        if not fingerprint or not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid or missing fingerprint/X-Signature")

        msg = db.execute(
            "SELECT id, sender_fingerprint, recipient, retrieved, retrieved_at, created_at FROM messages WHERE id = ?",
            (message_id,)
        ).fetchone()
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")

        # Only the sender or recipient can check status
        if msg["sender_fingerprint"] != fingerprint and msg["recipient"] != fingerprint:
            raise HTTPException(status_code=403, detail="Not your message")

        # Check TTL (UNDELIVERED_MSG_TTL_DAYS, default 30)
        from datetime import timedelta
        created = datetime.fromisoformat(msg["created_at"].replace("Z", "+00:00"))
        ttl_expired = datetime.now(created.tzinfo) - created > timedelta(seconds=UNDELIVERED_MSG_TTL_SECONDS)

        if msg["retrieved"]:
            status = "delivered"
        elif ttl_expired:
            status = "expired"
        else:
            status = "queued"

        return {
            "message_id": msg["id"],
            "status": status,
            "queued_at": msg["created_at"],
            "delivered_at": msg["retrieved_at"],
        }
    finally:
        db.close()


@app.post("/msg/cleanup")
async def message_cleanup(admin_key: str = Header(None, alias="X-Admin-Key")):
    """Purge expired messages (TTL = UNDELIVERED_MSG_TTL_DAYS, default 30). Run periodically or on heartbeat.

    Requires X-Admin-Key header (SATELLITE_ADMIN_KEY env var).
    """
    expected_key = os.environ.get("SATELLITE_ADMIN_KEY", "")
    if not expected_key or not hmac.compare_digest(admin_key or "", expected_key):
        raise HTTPException(status_code=403, detail="Unauthorized — admin key required")

    db = get_db()
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=UNDELIVERED_MSG_TTL_SECONDS)).isoformat()
        result = db.execute(
            "DELETE FROM messages WHERE retrieved = 0 AND created_at < ?",
            (cutoff,)
        )
        count = result.rowcount
        if count > 0:
            audit(db, "ttl_cleanup", None, f"purged {count} expired messages")
        db.commit()
        return {"status": "ok", "purged": count}
    finally:
        db.close()


@app.post("/heartbeat")
async def heartbeat(req: HeartbeatRequest):
    """Planet checks in — updates last_seen, returns pending count."""
    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        if not verify_request_signature(req.fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        identity = db.execute(
            "SELECT fingerprint FROM identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not registered")

        db.execute(
            "UPDATE identities SET last_seen = ? WHERE fingerprint = ?",
            (now_iso(), req.fingerprint)
        )
        pending = db.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient = ? AND retrieved = 0",
            (req.fingerprint,)
        ).fetchone()[0]
        db.commit()

        return {"status": "alive", "pending": pending, "last_seen": now_iso()}
    finally:
        db.close()


# /directory REMOVED — svrnty launch Option-C, 2026-09-28 (launch directive: no
# enumerable central registry / stranger-lookup). This endpoint was an UNAUTHENTICATED
# public enumeration of every identity (fingerprint, display_name, last_seen) — a
# scraper/deanon target, the exact sovereignty drift Option-C eliminates. Discovery is
# by-card only; there is no who's-who list. Verified 0 web-client callers before the cut
# (deployed-bundle grep). NOTE: /identities (the authenticated list) is retained
# for now — client-kit tooling still depends on it; it is removed together with the
# identities table in the blind-router step of the C substrate rewrite.


@app.get("/audit/{fingerprint}")
async def get_audit_log(
    fingerprint: str,
    limit: int = 50,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Append-only audit log — the satellite's integrity guarantee.

    Planets can verify their satellite hasn't been tampered with
    by checking the audit trail against their local logs.

    Requires X-Signature: Ed25519(sk, fingerprint:timestamp_minute).
    Only the identity owner can read their own audit trail.
    """
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid or missing X-Signature header")
        entries = db.execute(
            "SELECT event, details, timestamp FROM audit_log WHERE fingerprint = ? ORDER BY timestamp DESC LIMIT ?",
            (fingerprint, limit)
        ).fetchall()

        return {
            "fingerprint": fingerprint,
            "entries": [dict(e) for e in entries],
        }
    finally:
        db.close()


# ── Trust Handshake Relay ────────────────────────────────

class HandshakeInitRequest(BaseModel):
    initiator_fingerprint: str = Field(..., min_length=8, max_length=128)
    target_fingerprint: str = Field(..., min_length=8, max_length=128)
    hello_message: str  # JSON-encoded HELLO message
    signature: str  # Ed25519(sk, initiator_fingerprint:timestamp_minute)


class HandshakeRespondRequest(BaseModel):
    handshake_id: int
    responder_fingerprint: str = Field(..., min_length=8, max_length=128)
    response_message: str  # JSON-encoded HELLO_RESPONSE or VERIFY
    signature: str  # Ed25519(sk, responder_fingerprint:timestamp_minute)


def init_handshake_table():
    db = get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS handshakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                initiator TEXT NOT NULL REFERENCES identities(fingerprint),
                target TEXT NOT NULL REFERENCES identities(fingerprint),
                state TEXT NOT NULL DEFAULT 'hello_sent',
                messages TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_handshakes_target
                ON handshakes(target, state);
            CREATE INDEX IF NOT EXISTS idx_handshakes_initiator
                ON handshakes(initiator, state);
        """)
        db.close()
    except Exception:
        db.close()


@app.post("/handshake/initiate")
async def initiate_handshake(req: HandshakeInitRequest):
    """Step 1: Initiator sends HELLO via satellite to target."""
    init_handshake_table()
    db = get_db()
    try:
        # Verify initiator holds the private key
        if not verify_request_signature(req.initiator_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you hold the initiator's private key")

        # Verify both identities exist
        for fp in (req.initiator_fingerprint, req.target_fingerprint):
            if not db.execute("SELECT 1 FROM identities WHERE fingerprint = ?", (fp,)).fetchone():
                raise HTTPException(status_code=404, detail=f"Identity {fp} not registered")

        messages = json.dumps([{"step": "HELLO", "from": req.initiator_fingerprint, "payload": req.hello_message, "at": now_iso()}])
        cursor = db.execute(
            "INSERT INTO handshakes (initiator, target, state, messages, created_at, updated_at) VALUES (?, ?, 'hello_sent', ?, ?, ?)",
            (req.initiator_fingerprint, req.target_fingerprint, messages, now_iso(), now_iso())
        )
        handshake_id = cursor.lastrowid
        audit(db, "handshake_initiated", req.initiator_fingerprint, f"target={req.target_fingerprint},id={handshake_id}")
        db.commit()
        return {"status": "hello_sent", "handshake_id": handshake_id}
    finally:
        db.close()


@app.get("/handshake/pending/{fingerprint}")
async def get_pending_handshakes(
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Check for pending handshake requests (as target or initiator)."""
    init_handshake_table()
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid or missing X-Signature header")
        # Handshakes where I'm the target and need to respond
        incoming = db.execute(
            "SELECT id, initiator, state, messages, created_at FROM handshakes WHERE target = ? AND state IN ('hello_sent', 'verify_sent') ORDER BY created_at DESC",
            (fingerprint,)
        ).fetchall()

        # Handshakes where I'm the initiator and waiting for response
        outgoing = db.execute(
            "SELECT id, target, state, messages, created_at FROM handshakes WHERE initiator = ? AND state IN ('hello_response_sent', 'hello_sent') ORDER BY created_at DESC",
            (fingerprint,)
        ).fetchall()

        return {
            "fingerprint": fingerprint,
            "incoming": [{"id": h["id"], "from": h["initiator"], "state": h["state"], "messages": json.loads(h["messages"]), "created_at": h["created_at"]} for h in incoming],
            "outgoing": [{"id": h["id"], "to": h["target"], "state": h["state"], "messages": json.loads(h["messages"]), "created_at": h["created_at"]} for h in outgoing],
        }
    finally:
        db.close()


@app.post("/handshake/respond")
async def respond_to_handshake(req: HandshakeRespondRequest):
    """Steps 2-4: Respond to a handshake (HELLO_RESPONSE, VERIFY, or TRUST_ESTABLISHED)."""
    init_handshake_table()
    db = get_db()
    try:
        # Verify responder holds the private key
        if not verify_request_signature(req.responder_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you hold the responder's private key")

        handshake = db.execute(
            "SELECT * FROM handshakes WHERE id = ?", (req.handshake_id,)
        ).fetchone()
        if not handshake:
            raise HTTPException(status_code=404, detail="Handshake not found")

        state = handshake["state"]
        messages = json.loads(handshake["messages"])

        # Determine next state based on current state and responder
        if state == "hello_sent" and req.responder_fingerprint == handshake["target"]:
            next_state = "hello_response_sent"
            step = "HELLO_RESPONSE"
        elif state == "hello_response_sent" and req.responder_fingerprint == handshake["initiator"]:
            next_state = "verify_sent"
            step = "VERIFY"
        elif state == "verify_sent" and req.responder_fingerprint == handshake["target"]:
            next_state = "trust_established"
            step = "TRUST_ESTABLISHED"
        else:
            raise HTTPException(status_code=400, detail=f"Invalid handshake state transition: {state} by {req.responder_fingerprint}")

        messages.append({"step": step, "from": req.responder_fingerprint, "payload": req.response_message, "at": now_iso()})

        db.execute(
            "UPDATE handshakes SET state = ?, messages = ?, updated_at = ? WHERE id = ?",
            (next_state, json.dumps(messages), now_iso(), req.handshake_id)
        )
        audit(db, f"handshake_{step.lower()}", req.responder_fingerprint, f"id={req.handshake_id}")
        db.commit()

        return {"status": next_state, "handshake_id": req.handshake_id, "step": step}
    finally:
        db.close()


# ── Block ────────────────────────────────────────────────
#
# Block is silent and one-way. The blocked person is NOT notified.
# Block prevents: PSI sessions, message delivery.
# Unblock removes the block record. No notification either way.

class BlockRequest(BaseModel):
    blocker_fingerprint: str = Field(..., min_length=8, max_length=128)
    blocked_fingerprint: str = Field(..., min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 signature proving ownership of blocker key")


def init_block_table():
    db = get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                blocker TEXT NOT NULL REFERENCES identities(fingerprint),
                blocked TEXT NOT NULL REFERENCES identities(fingerprint),
                created_at TEXT NOT NULL,
                PRIMARY KEY (blocker, blocked)
            );
            CREATE INDEX IF NOT EXISTS idx_blocks_blocked
                ON blocks(blocked);
        """)
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()


def is_blocked(db: sqlite3.Connection, fp_a: str, fp_b: str) -> bool:
    """Check if either party has blocked the other."""
    row = db.execute(
        "SELECT 1 FROM blocks WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)",
        (fp_a, fp_b, fp_b, fp_a)
    ).fetchone()
    return row is not None


@app.post("/trust/block")
async def block_identity(req: BlockRequest):
    """Block another identity. Silent — no notification to the blocked party.
    Prevents PSI, messaging between these parties."""
    init_block_table()
    db = get_db()
    try:
        if not verify_request_signature(req.blocker_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature")

        if req.blocker_fingerprint == req.blocked_fingerprint:
            raise HTTPException(status_code=400, detail="Cannot block yourself")

        now = now_iso()
        try:
            db.execute(
                "INSERT INTO blocks (blocker, blocked, created_at) VALUES (?, ?, ?)",
                (req.blocker_fingerprint, req.blocked_fingerprint, now)
            )
        except sqlite3.IntegrityError:
            return {"status": "already_blocked"}

        audit(db, "block", req.blocker_fingerprint, f"blocked={req.blocked_fingerprint[:16]}...")
        db.commit()

        return {"status": "blocked", "message": "Identity blocked. They will not be notified."}
    finally:
        db.close()


@app.post("/trust/unblock")
async def unblock_identity(req: BlockRequest):
    """Unblock an identity. Silent — no notification."""
    init_block_table()
    db = get_db()
    try:
        if not verify_request_signature(req.blocker_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature")

        result = db.execute(
            "DELETE FROM blocks WHERE blocker = ? AND blocked = ?",
            (req.blocker_fingerprint, req.blocked_fingerprint)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="No block found")

        audit(db, "unblock", req.blocker_fingerprint, f"unblocked={req.blocked_fingerprint[:16]}...")
        db.commit()

        return {"status": "unblocked"}
    finally:
        db.close()


# ── Identity Deletion ────────────────────────────────────
#
# User-facing DELETE with signed challenge. Removes:
# - Identity record
# - All allowed_senders entries (by and for this identity)
# - All pending messages
# - All PSI sessions
# - All blocks (by and against)
# - All group memberships

class DeleteIdentityRequest(BaseModel):
    fingerprint: str = Field(..., min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 signature proving key ownership")
    confirm: str = Field(..., pattern="^DELETE_MY_IDENTITY$",
                         description="Must be exactly 'DELETE_MY_IDENTITY'")


@app.delete("/identity/{fingerprint}")
async def delete_identity(fingerprint: str, req: DeleteIdentityRequest):
    """Permanently delete an identity and all associated data.
    Requires signature proof and explicit confirmation string."""
    if req.fingerprint != fingerprint:
        raise HTTPException(status_code=400, detail="Fingerprint mismatch")

    db = get_db()
    try:
        if not verify_request_signature(fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        identity = db.execute(
            "SELECT fingerprint FROM identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        now = now_iso()

        # Count what we're deleting (for audit)
        allowed_count = db.execute(
            "SELECT COUNT(*) as c FROM allowed_senders WHERE owner_fingerprint = ? OR sender_fingerprint = ?",
            (fingerprint, fingerprint)
        ).fetchone()["c"]
        msg_count = db.execute(
            "SELECT COUNT(*) as c FROM messages WHERE recipient = ?",
            (fingerprint,)
        ).fetchone()["c"]

        # Delete in order: dependent tables first
        try:
            db.execute("DELETE FROM blocks WHERE blocker = ? OR blocked = ?", (fingerprint, fingerprint))
        except sqlite3.OperationalError:
            pass  # table may not exist

        try:
            db.execute("DELETE FROM psi_sessions WHERE initiator = ? OR responder = ?", (fingerprint, fingerprint))
        except sqlite3.OperationalError:
            pass

        try:
            db.execute("DELETE FROM group_members WHERE fingerprint = ?", (fingerprint,))
        except sqlite3.OperationalError:
            pass

        try:
            db.execute("DELETE FROM contact_cards WHERE owner_fingerprint = ? OR recipient_fingerprint = ?", (fingerprint, fingerprint))
        except sqlite3.OperationalError:
            pass

        # Remove from allowed_senders (both as owner and as sender)
        db.execute("DELETE FROM allowed_senders WHERE owner_fingerprint = ? OR sender_fingerprint = ?",
                   (fingerprint, fingerprint))
        db.execute("DELETE FROM messages WHERE recipient = ?", (fingerprint,))
        db.execute("DELETE FROM identities WHERE fingerprint = ?", (fingerprint,))

        audit(db, "identity_deleted", fingerprint,
              f"allowed={allowed_count},messages={msg_count},deleted_at={now}")
        db.commit()

        return {
            "status": "deleted",
            "fingerprint": fingerprint,
            "deleted": {
                "allowed_senders": allowed_count,
                "messages": msg_count,
            },
            "message": "Identity and all associated data permanently deleted."
        }
    finally:
        db.close()


# ── Contact Cards ─────────────────────────────────────────
#
# Per-recipient encrypted contact info. Alice encrypts her contact
# card specifically for Bob using Bob's public key. Only Bob can
# decrypt it. The satellite stores opaque encrypted blobs.
#
# This enables: "Share my phone with Bob but not Carol."

class ContactCardStoreRequest(BaseModel):
    owner_fingerprint: str = Field(..., min_length=8, max_length=128)
    recipient_fingerprint: str = Field(..., min_length=8, max_length=128)
    encrypted_card: str = Field(..., max_length=65536,
                                description="Encrypted contact card blob (encrypted with recipient's public key)")
    signature: str = Field(..., description="Ed25519 signature proving ownership")


def init_contact_card_table():
    db = get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS contact_cards (
                owner_fingerprint TEXT NOT NULL REFERENCES identities(fingerprint),
                recipient_fingerprint TEXT NOT NULL REFERENCES identities(fingerprint),
                encrypted_card TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (owner_fingerprint, recipient_fingerprint)
            );
            CREATE INDEX IF NOT EXISTS idx_contact_cards_recipient
                ON contact_cards(recipient_fingerprint);
        """)
    except sqlite3.OperationalError:
        pass
    finally:
        db.close()


@app.post("/contact-card/store")
async def store_contact_card(req: ContactCardStoreRequest):
    """Store an encrypted contact card for a specific recipient.
    Overwrites any existing card for the same owner→recipient pair."""
    init_contact_card_table()
    init_block_table()
    db = get_db()
    try:
        if not verify_request_signature(req.owner_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature")

        # Check block
        if is_blocked(db, req.owner_fingerprint, req.recipient_fingerprint):
            raise HTTPException(status_code=403, detail="Cannot share with blocked identity")

        # Verify both exist
        for fp in [req.owner_fingerprint, req.recipient_fingerprint]:
            if not db.execute("SELECT 1 FROM identities WHERE fingerprint = ?", (fp,)).fetchone():
                raise HTTPException(status_code=404, detail=f"Identity {fp} not registered")

        # Check plaintext
        plaintext_err = reject_plaintext(req.encrypted_card)
        if plaintext_err:
            raise HTTPException(status_code=400, detail=plaintext_err)

        now = now_iso()
        db.execute("""
            INSERT INTO contact_cards (owner_fingerprint, recipient_fingerprint, encrypted_card, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(owner_fingerprint, recipient_fingerprint)
            DO UPDATE SET encrypted_card = excluded.encrypted_card, updated_at = excluded.updated_at
        """, (req.owner_fingerprint, req.recipient_fingerprint, req.encrypted_card, now))

        # Notify recipient
        notification = json.dumps({
            "type": "contact_card_shared",
            "from": req.owner_fingerprint,
            "updated_at": now,
        })
        db.execute(
            "INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES (?, ?, ?, ?)",
            (req.recipient_fingerprint, "satellite:contact", notification, now)
        )

        audit(db, "contact_card_stored", req.owner_fingerprint,
              f"recipient={req.recipient_fingerprint[:16]}...")
        db.commit()

        return {"status": "stored", "updated_at": now}
    finally:
        db.close()


@app.get("/contact-card/{fingerprint}")
async def get_contact_cards(fingerprint: str, signature: str = ""):
    """Get all contact cards shared with this fingerprint."""
    init_contact_card_table()
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        cards = db.execute(
            "SELECT owner_fingerprint, encrypted_card, updated_at FROM contact_cards WHERE recipient_fingerprint = ? ORDER BY updated_at DESC",
            (fingerprint,)
        ).fetchall()

        return {
            "fingerprint": fingerprint,
            "cards": [
                {
                    "from": c["owner_fingerprint"],
                    "encrypted_card": c["encrypted_card"],
                    "updated_at": c["updated_at"],
                }
                for c in cards
            ],
        }
    finally:
        db.close()


@app.delete("/contact-card/{owner_fingerprint}/{recipient_fingerprint}")
async def revoke_contact_card(owner_fingerprint: str, recipient_fingerprint: str, signature: str = ""):
    """Revoke a shared contact card. Only the owner can revoke."""
    init_contact_card_table()
    db = get_db()
    try:
        if not verify_request_signature(owner_fingerprint, signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature")

        result = db.execute(
            "DELETE FROM contact_cards WHERE owner_fingerprint = ? AND recipient_fingerprint = ?",
            (owner_fingerprint, recipient_fingerprint)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Contact card not found")

        audit(db, "contact_card_revoked", owner_fingerprint,
              f"recipient={recipient_fingerprint[:16]}...")
        db.commit()

        return {"status": "revoked"}
    finally:
        db.close()


# ── Candle — Signed Trust Graph Export ────────────────────


class CandleStoreRequest(BaseModel):
    fingerprint: str = Field(..., min_length=8, max_length=128)
    candle_json: str = Field(..., description="Signed Candle JSON string")
    signature: str = Field(..., description="Ed25519 signature for auth")


@app.post("/candle/generate")
async def candle_generate(
    fingerprint: str = "",
    signature: str = Header("", alias="X-Signature"),
):
    """Assemble unsigned Candle from satellite records. Client signs locally.

    Phase 2: Candle now contains allowed_senders list instead of trust edges.
    Trust graph lives on the phone — candle is a satellite state snapshot.
    """
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, signature, db):
            raise HTTPException(status_code=403, detail="Signature verification failed")

        # Gather allowed senders
        allowed = db.execute("""
            SELECT sender_fingerprint, added_at
            FROM allowed_senders WHERE owner_fingerprint = ?
            ORDER BY sender_fingerprint
        """, (fingerprint,)).fetchall()

        # Compute audit chain hash
        audit_rows = db.execute("""
            SELECT event, details, timestamp FROM audit_log
            WHERE fingerprint = ? ORDER BY id
        """, (fingerprint,)).fetchall()

        audit_chain_hash = _audit_chain_hash(audit_rows)

        # Look up satellite_url from identity
        identity = db.execute(
            "SELECT satellite_url FROM identities WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        candle = {
            "version": 3,
            "type": "candle",
            "fingerprint": fingerprint,
            "generated_at": now_iso(),
            # C2: publish only an injective HASH of the allowed-senders set (+ its
            # cardinality), never the raw list — this candle is served
            # unauthenticated via GET /candle/{fingerprint}.
            "allowed_senders_hash": _allowed_senders_hash(a["sender_fingerprint"] for a in allowed),
            "allowed_senders_count": len(allowed),
            "audit_chain_hash": audit_chain_hash,
            "audit_entry_count": len(audit_rows),
            "satellite_url": identity["satellite_url"] if identity and identity["satellite_url"] else None,
        }

        return {"status": "unsigned", "candle": candle}
    finally:
        db.close()


@app.post("/candle/store")
async def candle_store(req: CandleStoreRequest):
    """Store a signed Candle. Client must sign it before uploading."""
    db = get_db()
    try:
        if not verify_request_signature(req.fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Signature verification failed")

        # Validate the candle JSON
        try:
            candle = json.loads(req.candle_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON")

        if candle.get("type") != "candle":
            raise HTTPException(status_code=400, detail="Not a candle")
        if candle.get("fingerprint") != req.fingerprint:
            raise HTTPException(status_code=400, detail="Fingerprint mismatch")
        if "signature" not in candle:
            raise HTTPException(status_code=400, detail="Candle must be signed before storing")

        # C2 ingress invariant: candle_store is the storage chokepoint that feeds
        # the unauthenticated GET /candle/{fingerprint}. Reject any candle that
        # carries the raw allowed_senders list, so a hand-crafted candle cannot
        # bypass the candle_generate assembler and re-introduce the leak. This is
        # what makes "no stored candle carries the raw list" unbypassable.
        if "allowed_senders" in candle:
            raise HTTPException(
                status_code=400,
                detail="Candle must carry allowed_senders_hash, not the raw allowed_senders list",
            )
        if candle.get("version", 0) < 3 or "allowed_senders_hash" not in candle:
            raise HTTPException(
                status_code=400,
                detail="Candle must be version >= 3 and carry allowed_senders_hash",
            )

        # Determine version
        latest = db.execute(
            "SELECT MAX(version) as v FROM candles WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        version = (latest["v"] or 0) + 1

        db.execute(
            "INSERT INTO candles (fingerprint, version, candle_json, created_at) VALUES (?, ?, ?, ?)",
            (req.fingerprint, version, req.candle_json, now_iso())
        )

        # Audit
        db.execute(
            "INSERT INTO audit_log (event, fingerprint, details, timestamp) VALUES (?, ?, ?, ?)",
            ("candle_stored", req.fingerprint, f"version={version}", now_iso())
        )
        db.commit()

        return {"status": "stored", "version": version}
    finally:
        db.close()


@app.get("/candle/{fingerprint}")
async def candle_get(fingerprint: str):
    """Retrieve the latest signed Candle for a fingerprint. Public — no auth required."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT candle_json, version, created_at FROM candles WHERE fingerprint = ? ORDER BY version DESC LIMIT 1",
            (fingerprint,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="No candle found")

        return {
            "status": "found",
            "version": row["version"],
            "created_at": row["created_at"],
            "candle": json.loads(row["candle_json"]),
        }
    finally:
        db.close()


@app.get("/candle/verify/{fingerprint}")
async def candle_verify(fingerprint: str):
    """Verify a stored Candle against current satellite state."""
    db = get_db()
    try:
        row = db.execute(
            "SELECT candle_json FROM candles WHERE fingerprint = ? ORDER BY version DESC LIMIT 1",
            (fingerprint,)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="No candle found")

        candle = json.loads(row["candle_json"])
        candle_version = candle.get("version", 2)
        checks = []

        # 1. Verify signature exists
        has_sig = "signature" in candle
        checks.append({"check": "signature_present", "pass": has_sig})

        # 2. Verify audit chain hash matches current state
        audit_rows = db.execute("""
            SELECT event, details, timestamp FROM audit_log
            WHERE fingerprint = ? ORDER BY id
        """, (fingerprint,)).fetchall()

        if candle_version >= 3:
            current_hash = _audit_chain_hash(audit_rows)
        else:
            # Legacy v2 candle: recompute with the original (non-injective) concat
            # it was built with, so pre-existing candles still verify.
            audit_concat = "".join(
                f"{a['event']}:{a['details']}:{a['timestamp']}" for a in audit_rows
            )
            current_hash = hashlib.sha256(audit_concat.encode()).hexdigest()
        candle_hash = candle.get("audit_chain_hash", "")
        audit_match = current_hash == candle_hash
        checks.append({
            "check": "audit_chain_hash",
            "pass": audit_match,
            "detail": "matches current state" if audit_match else "diverged — state changed since candle was generated",
        })

        # 3. Cross-check allowed senders against current state
        current_allowed_rows = db.execute(
            "SELECT sender_fingerprint FROM allowed_senders WHERE owner_fingerprint = ?",
            (fingerprint,)
        ).fetchall()
        current_allowed = set(r["sender_fingerprint"] for r in current_allowed_rows)
        if candle_version >= 3:
            # v3 candle carries only the injective hash + count, never the raw list.
            current_allowed_hash = _allowed_senders_hash(current_allowed)
            allowed_match = candle.get("allowed_senders_hash", "") == current_allowed_hash
            candle_count = candle.get("allowed_senders_count", 0)
        else:
            candle_allowed = set(a.get("fingerprint", "") for a in candle.get("allowed_senders", []))
            allowed_match = candle_allowed == current_allowed
            candle_count = len(candle_allowed)
        checks.append({
            "check": "allowed_senders",
            "pass": allowed_match,
            "candle_count": candle_count,
            "current_count": len(current_allowed),
            "detail": "matches" if allowed_match else "diverged — allowed list changed since candle",
        })

        all_pass = has_sig and audit_match and allowed_match

        return {
            "status": "verified" if all_pass else "diverged",
            "checks": checks,
            "note": "diverged means state changed since candle was generated — not necessarily invalid" if not all_pass else None,
        }
    finally:
        db.close()


@app.get("/candle/history/{fingerprint}")
async def candle_history(fingerprint: str):
    """List all Candle versions for a fingerprint (timestamps only)."""
    db = get_db()
    try:
        rows = db.execute(
            "SELECT version, created_at FROM candles WHERE fingerprint = ? ORDER BY version DESC",
            (fingerprint,)
        ).fetchall()

        return {
            "fingerprint": fingerprint,
            "count": len(rows),
            "versions": [{"version": r["version"], "created_at": r["created_at"]} for r in rows],
        }
    finally:
        db.close()


# ── Group Messaging ──────────────────────────────────────

class CreateGroupRequest(BaseModel):
    creator_fingerprint: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=1, max_length=128)
    member_fingerprints: list[str] = Field(..., min_length=1, max_length=100)
    signature: str = Field(..., description="Ed25519 signature proving creator key ownership")
    encrypted_keys: dict[str, dict] = Field(
        ..., description="Map of fingerprint → encrypted group key envelope"
    )


class GroupSendRequest(BaseModel):
    sender_fingerprint: str = Field(..., min_length=8, max_length=128)
    encrypted_blob: str = Field(..., max_length=MAX_MESSAGE_SIZE)
    thread_id: Optional[str] = Field(None, max_length=128)
    signature: str = Field(..., description="Ed25519 signature proving sender key ownership")


def init_group_tables():
    db = get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                creator TEXT NOT NULL REFERENCES identities(fingerprint),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL REFERENCES groups(group_id),
                fingerprint TEXT NOT NULL REFERENCES identities(fingerprint),
                encrypted_key TEXT NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (group_id, fingerprint)
            );
            CREATE INDEX IF NOT EXISTS idx_group_members_fp
                ON group_members(fingerprint);
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL REFERENCES groups(group_id),
                sender TEXT NOT NULL,
                encrypted_blob TEXT NOT NULL,
                thread_id TEXT,
                sequence INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_group_messages
                ON group_messages(group_id, sequence);
            CREATE INDEX IF NOT EXISTS idx_group_threads
                ON group_messages(group_id, thread_id, sequence);
        """)
        db.close()
    except Exception:
        db.close()


@app.post("/group/create", dependencies=[Depends(require_full_mode)])
async def create_group(req: CreateGroupRequest):
    """Create a group. Creator distributes encrypted group key to each member."""
    init_group_tables()
    db = get_db()
    try:
        # Auth: prove you own the creator key
        if not verify_request_signature(req.creator_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        # Verify all members exist
        all_members = set(req.member_fingerprints) | {req.creator_fingerprint}
        for fp in all_members:
            if not db.execute("SELECT 1 FROM identities WHERE fingerprint = ?", (fp,)).fetchone():
                raise HTTPException(status_code=404, detail=f"Identity {fp} not registered")

        # Verify encrypted keys provided for all members
        for fp in all_members:
            if fp not in req.encrypted_keys:
                raise HTTPException(status_code=400, detail=f"Missing encrypted key for {fp}")

        import secrets
        group_id = secrets.token_hex(16)

        db.execute(
            "INSERT INTO groups (group_id, name, creator, created_at) VALUES (?, ?, ?, ?)",
            (group_id, req.name, req.creator_fingerprint, now_iso())
        )

        for fp in all_members:
            db.execute(
                "INSERT INTO group_members (group_id, fingerprint, encrypted_key, joined_at) VALUES (?, ?, ?, ?)",
                (group_id, fp, json.dumps(req.encrypted_keys[fp]), now_iso())
            )

        audit(db, "group_created", req.creator_fingerprint, f"group={group_id},members={len(all_members)}")
        db.commit()
        return {"status": "created", "group_id": group_id, "members": len(all_members)}
    finally:
        db.close()


@app.post("/group/{group_id}/send", dependencies=[Depends(require_full_mode)])
async def send_group_message(group_id: str, req: GroupSendRequest):
    """Send an encrypted message to a group. One ciphertext, all members can decrypt."""
    init_group_tables()
    db = get_db()
    try:
        # Auth: prove you own the sender key
        if not verify_request_signature(req.sender_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        # Verify group exists and sender is member
        group = db.execute("SELECT group_id FROM groups WHERE group_id = ?", (group_id,)).fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        member = db.execute(
            "SELECT 1 FROM group_members WHERE group_id = ? AND fingerprint = ?",
            (group_id, req.sender_fingerprint)
        ).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Not a member of this group")

        # Encryption enforcement
        plaintext_err = reject_plaintext(req.encrypted_blob)
        if plaintext_err:
            audit(db, "group_plaintext_rejected", req.sender_fingerprint, f"group={group_id}")
            db.commit()
            raise HTTPException(status_code=400, detail=plaintext_err)

        # Get next sequence number
        last_seq = db.execute(
            "SELECT MAX(sequence) FROM group_messages WHERE group_id = ?", (group_id,)
        ).fetchone()[0]
        next_seq = (last_seq or 0) + 1

        db.execute(
            "INSERT INTO group_messages (group_id, sender, encrypted_blob, thread_id, sequence, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (group_id, req.sender_fingerprint, req.encrypted_blob, req.thread_id, next_seq, now_iso())
        )
        audit(db, "group_message", req.sender_fingerprint, f"group={group_id},seq={next_seq}")
        db.commit()
        return {"status": "sent", "group_id": group_id, "sequence": next_seq}
    finally:
        db.close()


@app.get("/group/{group_id}/messages", dependencies=[Depends(require_full_mode)])
async def get_group_messages(
    group_id: str,
    fingerprint: str,
    after_sequence: int = 0,
    thread_id: Optional[str] = None,
    limit: int = 50,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Retrieve group messages. Caller must be a member."""
    init_group_tables()
    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        member = db.execute(
            "SELECT encrypted_key FROM group_members WHERE group_id = ? AND fingerprint = ?",
            (group_id, fingerprint)
        ).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="Not a member of this group")

        if thread_id:
            messages = db.execute(
                "SELECT id, sender, encrypted_blob, thread_id, sequence, created_at FROM group_messages WHERE group_id = ? AND thread_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?",
                (group_id, thread_id, after_sequence, limit)
            ).fetchall()
        else:
            messages = db.execute(
                "SELECT id, sender, encrypted_blob, thread_id, sequence, created_at FROM group_messages WHERE group_id = ? AND sequence > ? ORDER BY sequence ASC LIMIT ?",
                (group_id, after_sequence, limit)
            ).fetchall()

        return {
            "group_id": group_id,
            "encrypted_group_key": json.loads(member["encrypted_key"]),
            "messages": [
                {
                    "id": m["id"],
                    "sender": m["sender"],
                    "encrypted_blob": m["encrypted_blob"],
                    "thread_id": m["thread_id"],
                    "sequence": m["sequence"],
                    "sent_at": m["created_at"],
                }
                for m in messages
            ],
        }
    finally:
        db.close()


@app.get("/group/list/{fingerprint}", dependencies=[Depends(require_full_mode)])
async def list_groups(
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """List groups a fingerprint belongs to. Caller must prove ownership."""
    init_group_tables()
    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")
        groups = db.execute(
            """SELECT g.group_id, g.name, g.creator, g.created_at,
                      (SELECT COUNT(*) FROM group_members WHERE group_id = g.group_id) as member_count
               FROM groups g
               JOIN group_members gm ON g.group_id = gm.group_id
               WHERE gm.fingerprint = ?
               ORDER BY g.created_at DESC""",
            (fingerprint,)
        ).fetchall()
        return {
            "fingerprint": fingerprint,
            "groups": [
                {
                    "group_id": g["group_id"],
                    "name": g["name"],
                    "creator": g["creator"],
                    "members": g["member_count"],
                    "created_at": g["created_at"],
                }
                for g in groups
            ],
        }
    finally:
        db.close()


# ── DH-PSI: Private Set Intersection (Mutual Contact Discovery) ──
#
# Two mutually-connected users can discover shared contacts WITHOUT
# revealing their full contact lists. The satellite relays blinded
# DH values — it never sees plaintext fingerprints or the result.
#
# Protocol (3-step relay):
# 1. Alice POSTs her blinded contact set → satellite stores it
# 2. Bob GETs Alice's blinded set, re-blinds client-side, POSTs back
#    along with his own blinded set
# 3. Alice GETs Bob's re-blinded-of-hers + Bob's blinded set,
#    re-blinds Bob's set client-side, compares → intersection
#
# Session expires after 1 hour. One-time use. Ephemeral keys.
#
# Phase 2: PSI requires both parties to be in each other's allowed_senders list.

PSI_SESSION_TTL = 3600  # 1 hour


class PSIInitiateRequest(BaseModel):
    """Start a PSI session. Initiator sends their blinded contact set."""
    initiator_fingerprint: str = Field(..., min_length=8, max_length=128)
    responder_fingerprint: str = Field(..., min_length=8, max_length=128)
    blinded_set: list[str] = Field(
        ..., min_length=1, max_length=5000,
        description="Base64-encoded blinded contact values: X25519(psi_sk, H(fp)) for each contact"
    )
    signature: str = Field(..., description="Ed25519 signature proving initiator key ownership")


class PSIRespondRequest(BaseModel):
    """Respond to a PSI session. Responder sends their blinded set + re-blinded initiator set."""
    responder_fingerprint: str = Field(..., min_length=8, max_length=128)
    blinded_set: list[str] = Field(
        ..., min_length=1, max_length=5000,
        description="Responder's own blinded contacts"
    )
    reblinded_initiator_set: list[str] = Field(
        ..., min_length=1, max_length=5000,
        description="Initiator's blinded set, re-blinded with responder's PSI key"
    )
    signature: str = Field(..., description="Ed25519 signature proving responder key ownership")


def init_psi_tables():
    db = get_db()
    try:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS psi_sessions (
                session_id TEXT PRIMARY KEY,
                initiator TEXT NOT NULL REFERENCES identities(fingerprint),
                responder TEXT NOT NULL REFERENCES identities(fingerprint),
                initiator_blinded TEXT NOT NULL,
                responder_blinded TEXT,
                reblinded_initiator TEXT,
                initiator_response_pub TEXT,   -- PQ-wrap: initiator's ephemeral seal-back key (JSON)
                responder_response_pub TEXT,   -- PQ-wrap: responder's ephemeral seal-back key (JSON)
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                UNIQUE(initiator, responder, status)
            );
            CREATE INDEX IF NOT EXISTS idx_psi_responder
                ON psi_sessions(responder, status);
            CREATE INDEX IF NOT EXISTS idx_psi_initiator
                ON psi_sessions(initiator, status);
            -- block≡offline sinkhole ring-buffer: a nothing-reads-it dead table. A blocked/
            -- severed /initiate writes here (NOT psi_sessions) + commits, so it pays the same
            -- fsync as a genuine /initiate (timing parity) while creating NO session a peer can
            -- complete. Fixed slot space + INSERT OR REPLACE => bounded (no growth, no GC needed).
            CREATE TABLE IF NOT EXISTS psi_sinkhole (
                slot INTEGER PRIMARY KEY,
                blob TEXT,
                created_at TEXT
            );
        """)
        # PQ-wrap migration: add the response_pub columns to a PRE-EXISTING table (idempotent;
        # a fresh table already has them from the CREATE above).
        for col in ("initiator_response_pub", "responder_response_pub"):
            try:
                db.execute(f"ALTER TABLE psi_sessions ADD COLUMN {col} TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists
        db.commit()
    except sqlite3.OperationalError:
        pass  # tables already exist
    finally:
        db.close()


_PSI_SINKHOLE_RING = 256  # bounded dead-table size

def _psi_sinkhole_commit(db: sqlite3.Connection, blinded_set=None):
    """block≡offline sinkhole. Mirror a genuine /initiate's write profile (1 DELETE + 3 INSERT
    + 1 commit) into a nothing-reads-it ring-buffer so a blocked/severed initiate is
    TIMING-indistinguishable from a genuine offline-mutual peer (the WAL commit fsync dominates
    /initiate latency: genuine 2.58ms vs no-commit 0.21ms). Creates NO
    psi_sessions row => the peer has no /respond or /blinded path (completion-safe by
    construction) and the responder's /pending never surfaces it. Ring-buffer (fixed slot space +
    INSERT OR REPLACE) stays bounded => zero storage amplification even under sinkhole-ALL."""
    import secrets
    now = now_iso()
    # Same-LENGTH dummy, never the real blinded set: the dead table is unread + ring-overwritten,
    # but we persist zero real blinded data even transiently (defense-in-depth).
    # Same byte-length => identical INSERT size => timing parity unchanged (seal carries).
    blob = "0" * len(json.dumps(blinded_set)) if blinded_set is not None else "{}"
    # 1 DELETE + 3 INSERT + 1 commit — matches genuine's write count; the commit is the parity term.
    db.execute("DELETE FROM psi_sinkhole WHERE slot = ?", (secrets.randbelow(_PSI_SINKHOLE_RING),))
    db.execute("INSERT OR REPLACE INTO psi_sinkhole (slot, blob, created_at) VALUES (?, ?, ?)",
               (secrets.randbelow(_PSI_SINKHOLE_RING), blob, now))   # carries ~blinded_set-sized payload
    db.execute("INSERT OR REPLACE INTO psi_sinkhole (slot, blob, created_at) VALUES (?, ?, ?)",
               (secrets.randbelow(_PSI_SINKHOLE_RING), "{}", now))
    db.execute("INSERT OR REPLACE INTO psi_sinkhole (slot, blob, created_at) VALUES (?, ?, ?)",
               (secrets.randbelow(_PSI_SINKHOLE_RING), "{}", now))
    db.commit()


# ── PQ-wrap PSI helpers (single-shell seal-TO-satellite; the satellite READS the blinders) ──────
def _open_psi_sealed(body) -> dict:
    """Open a PQ-wrapped PSI request body (sealed to THIS satellite's key) → inner JSON dict.
    Uniform 400 on any open/parse failure (no oracle — wrong-key/tamper/malformed all collapse)."""
    sat_sec, _pub, sat_fp = load_satellite_keypair(SATELLITE_KEY_PATH)
    pt = open_mailbox_envelope(body, sat_sec, sat_fp)
    if pt is None:
        raise HTTPException(status_code=400, detail="invalid PSI envelope")
    try:
        inner = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="invalid PSI envelope payload")
    if not isinstance(inner, dict):
        raise HTTPException(status_code=400, detail="invalid PSI envelope payload")
    return inner


def _valid_response_pub(rp) -> bool:
    """A client ephemeral response_pub = {x25519_pub_b64(32B), mlkem1024_pub_b64(1568B), mailbox_fp}
    whose fp binds the pair (fp == SHA256(x25519||mlkem)). Reject anything else — we seal to it later."""
    import base64
    if not isinstance(rp, dict):
        return False
    try:
        x = base64.b64decode(rp["x25519_pub_b64"], validate=True)
        k = base64.b64decode(rp["mlkem1024_pub_b64"], validate=True)
    except (KeyError, TypeError, ValueError, base64.binascii.Error):
        return False
    if len(x) != 32 or len(k) != 1568:
        return False
    return rp.get("mailbox_fp") == hashlib.sha256(x + k).hexdigest()


def _seal_psi_to(result: dict, response_pub) -> dict:
    """Seal a PSI response to a party's stored ephemeral response_pub. 500 if malformed (it was
    _valid_response_pub-checked on store, so this is a should-never-happen integrity guard)."""
    import base64
    try:
        x_pub = base64.b64decode(response_pub["x25519_pub_b64"], validate=True)
        k_pub = base64.b64decode(response_pub["mlkem1024_pub_b64"], validate=True)
    except (KeyError, TypeError, ValueError, base64.binascii.Error):
        raise HTTPException(status_code=500, detail="malformed stored response_pub")
    return seal_mailbox_envelope(
        json.dumps(result, separators=(",", ":")).encode("utf-8"), x_pub, k_pub
    )


@app.get("/trust/psi/satellite-key", dependencies=[Depends(require_full_mode)])
async def psi_satellite_key():
    """The satellite's OWN routing PUBLIC key, served UNDER /trust/psi/* so it is reachable via the
    EXISTING frontend proxy (app/api/satellite/trust/psi/[...path]) — the client seals PQ-wrap PSI
    requests to this key. IDENTICAL payload to GET /satellite/key (public info only; the secret half
    never leaves the box). Canonical /satellite/key stays for a dedicated FE proxy (fast-follow)."""
    _, pub, fp = load_satellite_keypair(SATELLITE_KEY_PATH)
    return {"alg": MAILBOX_ENV_ALG, "x25519_pk": pub["x25519_pk"],
            "mlkem1024_pk": pub["mlkem1024_pk"], "mailbox_fp": fp}


@app.post("/trust/psi/initiate")
async def psi_initiate(body: dict):
    """Start a DH-PSI session (PQ-wrapped). The request body is a MailboxEnvelope sealed to THIS
    satellite's key; we open it and the inner carries the existing PSI fields + the initiator's
    ephemeral response_pub (so the result GET can be sealed back). Both parties must be in each
    other's allowed_senders list — you can't discover shared contacts with a stranger.
    """
    init_psi_tables()
    inner = _open_psi_sealed(body)
    try:
        req = PSIInitiateRequest(
            initiator_fingerprint=inner.get("initiator_fingerprint"),
            responder_fingerprint=inner.get("responder_fingerprint"),
            blinded_set=inner.get("blinded_set"),
            signature=inner.get("signature"),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="invalid PSI inner fields")
    response_pub = inner.get("response_pub")
    if not _valid_response_pub(response_pub):
        raise HTTPException(status_code=400, detail="invalid or missing response_pub")
    db = get_db()
    try:
        # Auth: prove you own the initiator key
        if not verify_request_signature(req.initiator_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        # Verify both identities exist
        for fp in [req.initiator_fingerprint, req.responder_fingerprint]:
            if not db.execute("SELECT 1 FROM identities WHERE fingerprint = ?", (fp,)).fetchone():
                raise HTTPException(status_code=404, detail=f"Identity {fp} not registered")

        import secrets

        # ── block≡offline (sinkhole-ALL) ──────────────────────────────────────────────
        # A PSI can't complete for two reasons: the pair is BLOCKED, or they're NOT mutually
        # connected — either never were, OR a severance (untrust / go-private / remove) deleted
        # the allowed_senders rows (#572). The server CANNOT distinguish was-severed from
        # never-mutual (both leave no allowed_senders row and no blocks row), so to make a
        # block/severance indistinguishable from a peer who is simply OFFLINE, EVERY
        # non-completing reason returns the SAME 200-pending shape as a genuine offline-mutual
        # peer whose responder never answers.
        # No psi_sessions row is created => nothing for the blocked peer to /respond or /blinded
        # (completion-safe by construction) and the responder's /pending never surfaces it. A real
        # committed write IS paid (the fsync dominates /initiate latency) so the sinkhole is
        # timing-indistinguishable from the genuine path.
        init_block_table()
        blocked = is_blocked(db, req.initiator_fingerprint, req.responder_fingerprint)
        fwd = db.execute(
            "SELECT 1 FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
            (req.initiator_fingerprint, req.responder_fingerprint)
        ).fetchone()
        rev = db.execute(
            "SELECT 1 FROM allowed_senders WHERE owner_fingerprint = ? AND sender_fingerprint = ?",
            (req.responder_fingerprint, req.initiator_fingerprint)
        ).fetchone()
        mutual = bool(fwd) and bool(rev) and not blocked

        # PSI cooldown runs for BOTH paths so a severed pair with a recent completion returns 429
        # identically to an offline-mutual pair with a recent completion (cooldown-parity).
        PSI_COOLDOWN_SECONDS = 86400  # 24 hours
        cooldown_cutoff = datetime.fromtimestamp(
            datetime.now(timezone.utc).timestamp() - PSI_COOLDOWN_SECONDS, timezone.utc
        ).isoformat()
        recent = db.execute("""
            SELECT session_id, created_at FROM psi_sessions
            WHERE ((initiator = ? AND responder = ?) OR (initiator = ? AND responder = ?))
              AND status IN ('complete', 'responded')
              AND created_at > ?
            ORDER BY created_at DESC LIMIT 1
        """, (req.initiator_fingerprint, req.responder_fingerprint,
              req.responder_fingerprint, req.initiator_fingerprint,
              cooldown_cutoff)).fetchone()
        if recent:
            raise HTTPException(
                status_code=429,
                detail=f"PSI cooldown: you can run PSI with this person once per day. Last session: {recent['created_at']}"
            )

        if not mutual:
            # sinkhole: pay the committed write (timing parity) WITHOUT a real session.
            _psi_sinkhole_commit(db, req.blinded_set)
            return {
                "status": "pending",
                "session_id": secrets.token_hex(16),
                "message": "Blinded set stored. Waiting for responder.",
            }

        # ── genuine mutual path ───────────────────────────────────────────────────────
        # Cancel any existing pending session between these two
        db.execute(
            "DELETE FROM psi_sessions WHERE initiator = ? AND responder = ? AND status = 'pending'",
            (req.initiator_fingerprint, req.responder_fingerprint)
        )
        session_id = secrets.token_hex(16)
        db.execute(
            "INSERT INTO psi_sessions (session_id, initiator, responder, initiator_blinded, initiator_response_pub, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)",
            (session_id, req.initiator_fingerprint, req.responder_fingerprint,
             json.dumps(req.blinded_set), json.dumps(response_pub), now_iso())
        )
        notification = json.dumps({
            "type": "psi_request",
            "session_id": session_id,
            "from": req.initiator_fingerprint,
            "message": "wants to discover mutual contacts with you",
        })
        db.execute(
            "INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES (?, ?, ?, ?)",
            (req.responder_fingerprint, "satellite:psi", notification, now_iso())
        )
        audit(db, "psi_initiated", req.initiator_fingerprint,
              f"session={session_id},responder={req.responder_fingerprint[:16]}...,set_size={len(req.blinded_set)}")
        db.commit()
        return {
            "status": "pending",
            "session_id": session_id,
            "message": "Blinded set stored. Waiting for responder.",
        }
    finally:
        db.close()


@app.get("/trust/psi/pending/{fingerprint}")
async def psi_pending(
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Check for pending PSI requests where this identity is the responder.

    Requires X-Signature: Ed25519(sk, fingerprint:timestamp_minute).
    Only the responder can see their own pending PSI sessions.
    """
    init_psi_tables()
    db = get_db()
    try:
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid or missing X-Signature header")
        # Clean expired sessions first
        cutoff = datetime.now(timezone.utc).timestamp() - PSI_SESSION_TTL
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
        db.execute(
            "DELETE FROM psi_sessions WHERE status = 'pending' AND created_at < ?",
            (cutoff_iso,)
        )
        db.commit()

        sessions = db.execute(
            "SELECT session_id, initiator, created_at FROM psi_sessions WHERE responder = ? AND status = 'pending' ORDER BY created_at DESC",
            (fingerprint,)
        ).fetchall()

        return {
            "fingerprint": fingerprint,
            "pending_sessions": [
                {
                    "session_id": s["session_id"],
                    "initiator": s["initiator"],
                    "created_at": s["created_at"],
                }
                for s in sessions
            ],
        }
    finally:
        db.close()


@app.post("/trust/psi/session/{session_id}/blinded")
async def psi_get_blinded(session_id: str, body: dict):
    """Fetch the initiator's blinded set for re-blinding (PQ-wrapped). POST (not GET) because the
    responder registers their ephemeral response_pub HERE — a 1568B ML-KEM pub can't ride a GET
    query — and the response is SEALED to it. Body = MailboxEnvelope sealed to THIS satellite;
    inner = { responder_fingerprint, signature, response_pub }. Only the responder may fetch."""
    init_psi_tables()
    inner = _open_psi_sealed(body)
    fingerprint = inner.get("responder_fingerprint")
    signature = inner.get("signature")
    response_pub = inner.get("response_pub")
    if not isinstance(fingerprint, str) or not isinstance(signature, str):
        raise HTTPException(status_code=400, detail="invalid PSI inner fields")
    if not _valid_response_pub(response_pub):
        raise HTTPException(status_code=400, detail="invalid or missing response_pub")
    db = get_db()
    try:
        # Auth: prove you own this fingerprint (same liveness sig, now carried inside the seal)
        if not verify_request_signature(fingerprint, signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — ownership proof required")

        session = db.execute(
            "SELECT * FROM psi_sessions WHERE session_id = ? AND status = 'pending'",
            (session_id,)
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="PSI session not found or expired")

        if session["responder"] != fingerprint:
            raise HTTPException(status_code=403, detail="Only the responder can access the initiator's blinded set")

        # Register the responder's ephemeral response_pub (first session touch) so this response
        # — and any later responder-facing one — can be sealed back. Idempotent (retry re-sets same).
        db.execute(
            "UPDATE psi_sessions SET responder_response_pub = ? WHERE session_id = ?",
            (json.dumps(response_pub), session_id)
        )
        db.commit()

        return _seal_psi_to({
            "session_id": session_id,
            "initiator": session["initiator"],
            "blinded_set": json.loads(session["initiator_blinded"]),
        }, response_pub)
    finally:
        db.close()


@app.post("/trust/psi/session/{session_id}/respond")
async def psi_respond(session_id: str, body: dict):
    """Submit responder's blinded set + re-blinded initiator set (PQ-wrapped: body is a
    MailboxEnvelope sealed to this satellite; inner carries responder_blinded_set + the
    reblinded initiator set + auth). The responder has fetched the initiator's blinded set
    (POST /blinded), re-blinded it client-side, and generated their own; they submit both here.
    """
    init_psi_tables()
    inner = _open_psi_sealed(body)
    try:
        req = PSIRespondRequest(
            responder_fingerprint=inner.get("responder_fingerprint"),
            blinded_set=inner.get("responder_blinded_set"),
            reblinded_initiator_set=inner.get("reblinded_initiator_set"),
            signature=inner.get("signature"),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="invalid PSI inner fields")
    db = get_db()
    try:
        # Auth: prove you own the responder key
        if not verify_request_signature(req.responder_fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        session = db.execute(
            "SELECT * FROM psi_sessions WHERE session_id = ? AND status = 'pending'",
            (session_id,)
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="PSI session not found or expired")

        if session["responder"] != req.responder_fingerprint:
            raise HTTPException(status_code=403, detail="Not the designated responder")

        # Store responder's data
        db.execute(
            """UPDATE psi_sessions
               SET responder_blinded = ?, reblinded_initiator = ?,
                   status = 'responded', completed_at = ?
               WHERE session_id = ?""",
            (json.dumps(req.blinded_set), json.dumps(req.reblinded_initiator_set),
             now_iso(), session_id)
        )

        # Notify initiator
        notification = json.dumps({
            "type": "psi_response",
            "session_id": session_id,
            "from": req.responder_fingerprint,
            "message": "PSI response ready — you can now discover mutual contacts",
        })
        db.execute(
            "INSERT INTO messages (recipient, sender_fingerprint, encrypted_blob, created_at) VALUES (?, ?, ?, ?)",
            (session["initiator"], "satellite:psi", notification, now_iso())
        )

        audit(db, "psi_responded", req.responder_fingerprint,
              f"session={session_id},set_size={len(req.blinded_set)}")
        db.commit()

        return {
            "status": "responded",
            "session_id": session_id,
            "message": "Response stored. Initiator can now complete the PSI exchange.",
        }
    finally:
        db.close()


@app.get("/trust/psi/session/{session_id}/result")
async def psi_get_result(
    session_id: str,
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Get the PSI result data. Only the initiator can access this.

    Returns the responder's blinded set (for re-blinding) and the
    re-blinded version of the initiator's set (for comparison).
    The actual intersection is computed client-side.
    """
    init_psi_tables()
    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        session = db.execute(
            "SELECT * FROM psi_sessions WHERE session_id = ? AND status = 'responded'",
            (session_id,)
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="PSI session not found or not yet responded")

        if session["initiator"] != fingerprint:
            raise HTTPException(status_code=403, detail="Only the initiator can access the result")

        result = {
            "session_id": session_id,
            "responder": session["responder"],
            "responder_blinded_set": json.loads(session["responder_blinded"]),
            "reblinded_initiator_set": json.loads(session["reblinded_initiator"]),
        }

        # PQ-wrap: SEAL the result to the initiator's ephemeral response_pub (registered at initiate).
        irp = session["initiator_response_pub"]
        if not irp:
            raise HTTPException(status_code=409, detail="session has no initiator response key (legacy/pre-PQ-wrap session)")
        sealed = _seal_psi_to(result, json.loads(irp))

        # Mark session complete and schedule deletion
        db.execute(
            "UPDATE psi_sessions SET status = 'complete' WHERE session_id = ?",
            (session_id,)
        )
        audit(db, "psi_completed", fingerprint, f"session={session_id}")
        db.commit()

        return sealed
    finally:
        db.close()


@app.delete("/trust/psi/session/{session_id}")
async def psi_cancel(
    session_id: str,
    fingerprint: str,
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
):
    """Cancel a PSI session. Either party can cancel."""
    init_psi_tables()
    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        if not verify_request_signature(fingerprint, x_signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — X-Signature header required")

        session = db.execute(
            "SELECT initiator, responder FROM psi_sessions WHERE session_id = ?",
            (session_id,)
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="PSI session not found")

        if fingerprint not in (session["initiator"], session["responder"]):
            raise HTTPException(status_code=403, detail="Not a party to this session")

        db.execute("DELETE FROM psi_sessions WHERE session_id = ?", (session_id,))
        audit(db, "psi_cancelled", fingerprint, f"session={session_id}")
        db.commit()

        return {"status": "cancelled", "session_id": session_id}
    finally:
        db.close()


# ── Cleanup ──────────────────────────────────────────────

@app.post("/admin/cleanup")
async def cleanup_old_messages(admin_key: str = Header(None, alias="X-Admin-Key")):
    """Remove retrieved messages older than retention period."""
    expected_key = os.environ.get("SATELLITE_ADMIN_KEY", "")
    if not expected_key or not hmac.compare_digest(admin_key or "", expected_key):
        raise HTTPException(status_code=403, detail="Unauthorized")

    db = get_db()
    try:
        cutoff = datetime.now(timezone.utc).timestamp() - (RETENTION_DAYS * 86400)
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()

        result = db.execute(
            "DELETE FROM messages WHERE retrieved = 1 AND retrieved_at < ?",
            (cutoff_iso,)
        )
        deleted = result.rowcount

        # Clean up expired/completed PSI sessions
        psi_cutoff = datetime.now(timezone.utc).timestamp() - PSI_SESSION_TTL
        psi_cutoff_iso = datetime.fromtimestamp(psi_cutoff, timezone.utc).isoformat()
        try:
            psi_result = db.execute(
                "DELETE FROM psi_sessions WHERE status IN ('complete', 'pending') AND created_at < ?",
                (psi_cutoff_iso,)
            )
            psi_deleted = psi_result.rowcount
        except sqlite3.OperationalError:
            psi_deleted = 0  # table may not exist yet

        audit(db, "cleanup", details=f"messages={deleted},psi_sessions={psi_deleted}")
        db.commit()

        return {"deleted": deleted, "psi_deleted": psi_deleted, "retention_days": RETENTION_DAYS}
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    # access_log=False: linkable ids ride in URL paths; suppress the
    # access log on the direct-run path too, matching the Docker CMD --no-access-log.
    uvicorn.run(app, host="0.0.0.0", port=PORT, access_log=False)
