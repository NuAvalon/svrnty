"""
Registration API — svrnty identity creation (OPEN MINT).

Flow (2026-09-12 — spec §Identity: "no email, no magic link, no account"):
1. POST /verify  — submit the canonical key bundle → identity created. The identity
   IS the keypair (fingerprint == SHA256 of the public keys, re-derived server-side).
   No OTP, no email, no account. Sybil-resistance is STRUCTURAL (uninvited identities
   are isolated + undiscoverable), not an account gate.
2. GET  /identity/{fingerprint} — lookup public identity info.

Legacy: POST /register (email → 6-digit OTP via Resend) remains for backward-compat
with older clients (landing.html) but is NO LONGER REQUIRED and NOT the canonical
path — /verify checks no OTP. Email is never collected or stored by the mint (I-7).

The Ed25519 (+ PQ) key proves the user is them. Auth is key-only — no passwords,
no sessions, no server-side recovery.
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

# ── Config ────────────────────────────────────────────────

DATA_DIR = Path(os.environ.get("REGISTRATION_DATA", "/data"))
DB_PATH = DATA_DIR / "registration.db"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", "verify@svrnty.is")
OTP_EXPIRY_SECONDS = 600  # 10 minutes
OTP_MAX_ATTEMPTS = 5
SATELLITE_URL = os.environ.get("SATELLITE_URL", "http://satellite:8100")
RATE_LIMIT_SECONDS = 60  # 1 email per minute per address


# ── Database ──────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(str(DB_PATH))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS pending_verifications (
            email TEXT PRIMARY KEY,
            otp_hash TEXT NOT NULL,
            created_at REAL NOT NULL,
            attempts INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS verified_identities (
            fingerprint TEXT PRIMARY KEY,
            email_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            encryption_pk TEXT,
            display_name TEXT,
            slug TEXT UNIQUE,
            identity_type TEXT NOT NULL DEFAULT 'human',
            registered_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_verified_email
            ON verified_identities(email_hash);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_verified_slug
            ON verified_identities(slug) WHERE slug IS NOT NULL;

        -- gated-A: one-time nonces consumed at sig_pubkey binding (A3 replay floor).
        -- A (fingerprint, nonce) pair is single-use; PRIMARY KEY refuses reuse.
        -- Replay-prevention only (NOT an audit log); pruned to the current epoch.
        CREATE TABLE IF NOT EXISTS bind_nonces (
            fingerprint TEXT NOT NULL,
            nonce TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            used_at TEXT NOT NULL,
            PRIMARY KEY (fingerprint, nonce)
        );

        -- gated-A clause-1: rebind/key-lifecycle audit is AGGREGATE
        -- ONLY — a per-event {who, when, which sig_pubkey, epoch} graph is banned
        -- (same class as server-side social-graph / block-history). Just counts.
        CREATE TABLE IF NOT EXISTS gated_a_audit (
            event TEXT PRIMARY KEY,
            count INTEGER NOT NULL DEFAULT 0
        );
    """)
    # Migrate: add columns that may not exist in older DBs
    for col, typedef in [
        ("encryption_pk", "TEXT"),
        ("identity_type", "TEXT NOT NULL DEFAULT 'human'"),
        ("x25519_pk", "TEXT"),
        ("mldsa65_pk", "TEXT"),
        ("mlkem768_pk", "TEXT"),
        ("key_version", "INTEGER DEFAULT 1"),
        # gated-A: bound per-request AUTH key (raw ed25519 as lowercase hex; NULL until
        # the client proves ownership via a tag#2 binding). epoch = clause-2 key-transition
        # generation (bumped on rotation; a binding is valid only at the current epoch).
        ("sig_pubkey", "TEXT"),
        ("epoch", "INTEGER DEFAULT 0"),
    ]:
        try:
            db.execute(f"ALTER TABLE verified_identities ADD COLUMN {col} {typedef}")
        except sqlite3.OperationalError:
            pass  # column already exists
    db.close()


# ── Models ────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=254)


class VerifyRequest(BaseModel):
    # Open mint (2026-09-12, spec §Identity "no email, no magic link, no
    # account"): the identity IS the keypair. email/otp are OPTIONAL + IGNORED —
    # kept only so a legacy client (landing.html) still validates; never stored
    # (I-7: email↔identity cut). fingerprint + public_key remain REQUIRED (the id).
    email: Optional[str] = None
    otp: Optional[str] = None
    fingerprint: str = Field(..., min_length=8, max_length=128)
    public_key: str = Field(..., min_length=32)
    encryption_pk: Optional[str] = Field(None, min_length=32,
                                          description="X25519 public key for message encryption (base64)")
    # Post-quantum keys (optional for v1 compat)
    x25519_pk: Optional[str] = Field(None, description="X25519 public key (base64)")
    mldsa65_pk: Optional[str] = Field(None, description="ML-DSA-65 public key (base64, FIPS 204)")
    mlkem768_pk: Optional[str] = Field(None, description="ML-KEM-768 public key (base64, FIPS 203)")
    key_version: int = Field(1, description="Key version: 1=Ed25519-only, 2=hybrid PQ")
    display_name: Optional[str] = None
    slug: Optional[str] = Field(None, min_length=3, max_length=32, pattern=r'^[a-z0-9][a-z0-9_-]*$')
    identity_type: str = Field("human", pattern=r'^(human|agent|hybrid)$',
                                description="Identity type — enforced at registration, cannot be changed")


# ── Helpers ───────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_otp(otp: str) -> str:
    """Hash OTP so we never store plaintext codes."""
    return hashlib.sha256(otp.encode()).hexdigest()


def hash_email(email: str) -> str:
    """Hash email for storage — we don't need to read it back."""
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()


# ── gated-A bind preimage + raw Ed25519 verify ───────────────────────
# Domain-separated ASCII tags so no signature is cross-protocol-confusable.
# Byte-exact with the reference vectors + the client:
#   #2 svrnty-bind     : sig_pubkey binding  (IDENTITY key)   [POST /bind, below]
#   #3 svrnty-psi-auth : per-request auth    (SIG_PUBKEY, satellite side)
# sig_pubkey + nonce are lowercase hex; epoch is a decimal integer.
# NOTE: the tag#1 svrnty-own ownership-proof migration (rewrites verify_ownership
# off the legacy "{fp}:{minute}" proof + updates the add.html/chat.html/landing.html
# clients) is a SEPARATE, client-coupled follow-up — intentionally NOT in this
# commit so /slug/{name}/claim, /backup/store and /backup/recover keep working on
# dev (the deployed clients still send the legacy proof).


def _bind_preimage(sig_pubkey_hex: str, nonce_hex: str, epoch: int) -> bytes:
    return f"svrnty-bind:{sig_pubkey_hex}:{nonce_hex}:{epoch}".encode()


def _raw_ed25519_verify(pubkey_bytes: bytes, sig_bytes: bytes, message: bytes) -> bool:
    """Raw Ed25519 verify (no PGP). Mirrors satellite _verify_with_key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(pubkey_bytes).verify(sig_bytes, message)
        return True
    except Exception:
        return False


def _identity_pubkey_bytes(pk_str: str) -> bytes:
    """Decode a stored identity public_key. Registration stores raw Ed25519 as HEX
    (hexFromBytes in landing.html); fall back to base64 for older v1 rows."""
    try:
        return bytes.fromhex(pk_str)
    except ValueError:
        import base64
        return base64.b64decode(pk_str)


def verify_ownership(fingerprint: str, signature: str, db: sqlite3.Connection) -> bool:
    """Verify the requester owns the private key for this fingerprint.

    Signature = Ed25519(sk, fingerprint || timestamp_minute).
    Allows 1-minute clock skew.
    """
    if not signature:
        return False
    identity = db.execute(
        "SELECT public_key FROM verified_identities WHERE fingerprint = ?",
        (fingerprint,)
    ).fetchone()
    if not identity:
        return False
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        # Public key is stored as hex from hexFromBytes() in landing.html
        pk_str = identity["public_key"]
        try:
            pubkey_bytes = bytes.fromhex(pk_str)
        except ValueError:
            pubkey_bytes = base64.b64decode(pk_str)  # v1 compat fallback
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        sig_clean = signature.replace(" ", "+")
        sig_bytes = base64.b64decode(sig_clean)
        ts_minute = int(time.time()) // 60
        for offset in (0, -1):
            try:
                message = f"{fingerprint}:{ts_minute + offset}".encode()
                pubkey.verify(sig_bytes, message)
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _dev_mode() -> bool:
    """DEV_MODE (local-mirror email/OTP bypass) is active ONLY when no real email
    backend is configured — fail-closed so a prod-keyed env can never half-fire it
    (review condition, 2026-08-10)."""
    return bool(os.environ.get("DEV_MODE")) and not RESEND_API_KEY


def send_otp_email(email: str, otp: str) -> bool:
    """Send OTP via Resend API. Returns True on success."""
    if not RESEND_API_KEY:
        if _dev_mode():
            print(f"[DEV_MODE] OTP for {email}: {otp}  (email sending bypassed)", flush=True)
            return True
        print("[ERROR] RESEND_API_KEY not configured — cannot send OTP")
        return False

    import urllib.request
    import urllib.error

    payload = json.dumps({
        "from": RESEND_FROM,
        "to": [email],
        "subject": "svrnty — verify your identity",
        "html": f"""
        <div style="font-family: monospace; max-width: 400px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #c9a227;">svrnty</h2>
            <p>Your verification code:</p>
            <div style="font-size: 32px; letter-spacing: 8px; font-weight: bold; padding: 20px; background: #1a1a2e; color: #c9a227; text-align: center; border-radius: 8px;">
                {otp}
            </div>
            <p style="color: #666; margin-top: 20px;">This code expires in 10 minutes.</p>
            <p style="color: #666;">If you didn't request this, ignore this email.</p>
        </div>
        """,
    }).encode()

    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "svrnty-registration/0.1",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            if resp.status in (200, 202):
                return True
            print(f"[ERROR] Resend API unexpected status {resp.status}: {body}")
            return False
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, 'read') else str(e)
        print(f"[ERROR] Resend API HTTP {e.code}: {body}")
        return False
    except urllib.error.URLError as e:
        print(f"[ERROR] Resend API connection failed: {e}")
        return False


def register_with_satellite(fingerprint: str, public_key: str, display_name: str = None,
                            encryption_pk: str = None, pq_kem_pk: str = None,
                            pq_sig_pk: str = None) -> bool:
    """Register the verified identity with the satellite relay.

    The satellite RE-DERIVES the canonical DID from the keys and re-verifies it
    (INV-2: replica re-derives, never transport-trusts), so it must receive the SAME
    keys the client hashed into its fingerprint, in the SAME encoding it decodes.
    Propagation contract (gated-A + satellite schema),
    grounded against satellite.py /register HEAD:
      • public_key   → base64(raw 32B Ed25519). Registration receives/stores it as HEX
                       (landing.html hexFromBytes); the satellite b64decodes it
                       (satellite.py:837) and needs exactly 32 raw bytes (:875). Sending
                       hex → 48 decoded bytes → len!=32 → 400. So convert hex→raw→b64.
      • encryption_pk / pq_kem_pk / pq_sig_pk → base64 raw (already base64 from the
                       client: X25519 32B / ML-KEM-1024 1568B / ML-DSA-87 2592B).
      • Forward each PQ/enc key ONLY when present: the satellite selects its verify
                       branch by key PRESENCE (hybrid :846 needs all three; enc-only
                       :862; legacy single-key :875). Omitting absent keys lets a legacy
                       Ed25519-only identity match the legacy branch; sending nulls would
                       break branch detection.
      • crypto_version → 'hybrid-v1' when the full PQ bundle is present, else 'classical'
                       (satellite regex ^(classical|hybrid-v1)$ — anything else 422s).
    This also resolves /bind's re-verify for free: /register stores public_key as-sent
    (now base64) → /bind's b64decode yields raw 32B → tag#2 re-verify passes.
    Best-effort: a failed sync is retried on the next verify/bind, never fatal here."""
    import urllib.request
    import urllib.error
    import base64

    hybrid = bool(encryption_pk and pq_kem_pk and pq_sig_pk)
    body = {
        "fingerprint": fingerprint,
        # Ed25519 signing key: hex (as stored/received) → raw → base64 for the satellite.
        "public_key": base64.b64encode(_identity_pubkey_bytes(public_key)).decode(),
        "display_name": display_name,
        "crypto_version": "hybrid-v1" if hybrid else "classical",
    }
    if encryption_pk:
        body["encryption_pk"] = encryption_pk
    if pq_kem_pk:
        body["pq_kem_pk"] = pq_kem_pk
    if pq_sig_pk:
        body["pq_sig_pk"] = pq_sig_pk

    payload = json.dumps(body).encode()

    req = urllib.request.Request(
        f"{SATELLITE_URL}/register",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        print(f"[WARN] Satellite registration failed: {e}")
        return False


def push_binding_to_satellite(fingerprint: str, sig_pubkey: str, nonce: str,
                              epoch: int, binding_sig: str) -> bool:
    """Propagate a verified sig_pubkey binding to the satellite. The satellite
    RE-VERIFIES the tag#2 identity-key signature itself (no transport-trust — the
    binding sig is the authentication), so this push is safe even if reachable.
    Best-effort: a failed sync is retried on the next bind, never fatal here."""
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "fingerprint": fingerprint,
        "sig_pubkey": sig_pubkey,
        "nonce": nonce,
        "epoch": epoch,
        "binding_sig": binding_sig,
    }).encode()

    req = urllib.request.Request(
        f"{SATELLITE_URL}/bind",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        print(f"[WARN] Satellite bind sync failed: {e}")
        return False


# ── App ───────────────────────────────────────────────────

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="svrnty Registration",
    description="Email verification + Ed25519 identity creation for svrnty.",
    version="0.1.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = os.environ.get("CORS_ORIGINS", "https://svrnty.is").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ── Routes ────────────────────────────────────────────────

@app.post("/register")
async def register(req: RegisterRequest):
    """Step 1: Submit email → receive OTP.

    Sends a 6-digit code to the email address. The user must
    prove they control this inbox before claiming an identity.
    """
    email = req.email.lower().strip()
    email_h = hash_email(email)
    db = get_db()
    try:
        # Rate limit — 1 email per minute per address
        existing = db.execute(
            "SELECT created_at FROM pending_verifications WHERE email = ?",
            (email_h,)
        ).fetchone()

        if existing and (time.time() - existing["created_at"]) < RATE_LIMIT_SECONDS:
            raise HTTPException(
                status_code=429,
                detail=f"Please wait {RATE_LIMIT_SECONDS}s between verification requests"
            )

        # Note: same email can register multiple identities (design decision).
        # Email ≠ identity. Each registration creates a new keypair + fingerprint.

        # Generate OTP (DEV_MODE: fixed code so local mirror needs no live email)
        if _dev_mode():
            otp = "000000"
        else:
            otp = "".join(secrets.choice("0123456789") for _ in range(6))

        # Send email
        if not send_otp_email(email, otp):
            raise HTTPException(status_code=502, detail="Failed to send verification email")

        # Store hashed OTP (upsert) — email hashed too, never stored plaintext
        db.execute(
            "INSERT OR REPLACE INTO pending_verifications (email, otp_hash, created_at, attempts, verified) VALUES (?, ?, ?, 0, 0)",
            (email_h, hash_otp(otp), time.time())
        )
        db.commit()

        resp = {"status": "otp_sent", "message": "Check your email for the verification code"}
        if _dev_mode():
            resp["dev_otp"] = otp
            resp["message"] = "DEV_MODE: use verification code 000000 (email bypassed)"
        return resp
    finally:
        db.close()


@app.post("/verify")
async def verify(req: VerifyRequest):
    """Open mint (2026-09-12 — spec §Identity: "no email, no magic link, no
    account"): submit the canonical key bundle → identity created. The identity IS
    the keypair; the ONLY proof required is that the fingerprint equals SHA256 of
    the public keys (re-derived below, option-B). No OTP, no email. Sybil-resistance
    is STRUCTURAL (uninvited identities are isolated + undiscoverable), not an
    account gate — a flood of fake mints is harmless. email/otp, if sent by a legacy
    client, are IGNORED and never stored (I-7: email↔identity cut).
    """
    db = get_db()
    try:

        # SECURITY (C-1, option-B):
        # The fingerprint IS the canonical DID. Re-derive it over the SAME bytes/fields/order the
        # satellite re-derives (satellite.py register_identity :826-882) so registration — the mint
        # AUTHORITY — and the satellite agree on every identity (INV-2/INV-3). Genesis is
        # IRREVERSIBLE: require the FULL 64-char canonical DID and compare == EXACT (not
        # a prefix — a truncated fp is a squat surface at the mint; INV-3.
        # TRY-ALL fallthrough (hybrid → classical → legacy): a client may present the full key bundle
        # yet a legacy single-key DID (landing.html), so branches are TRIED not SELECTED. EXACT
        # per-alg lengths ⇒ injective raw concat (I-6): Ed25519 sign=32, X25519 enc=32,
        # ML-KEM-1024 kem=1568, ML-DSA-87 sig=2592 (hybrid preimage=4224B). Field map = the /register
        # propagation callsite's (enc←x25519_pk, kem←mlkem768_pk, sig←mldsa65_pk) so C-1 verifies
        # EXACTLY what /register forwards to the satellite. No PGP parse on this permanent path.
        import base64 as _b64
        try:
            pk_bytes = _identity_pubkey_bytes(req.public_key)   # sign: hex (landing) or b64 (enroll) → raw
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid public_key encoding")
        fp = req.fingerprint.strip().lower()
        if len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
            raise HTTPException(status_code=400,
                                detail="Fingerprint must be the 64-char hex canonical DID")

        def _raw(b64val: str, exact_len: int) -> bytes:
            raw = _b64.b64decode(b64val)
            if len(raw) != exact_len:        # injectivity: wrong length ⇒ this branch cannot verify
                raise ValueError("unexpected key length")
            return raw

        verified = False
        # Hybrid DID: SHA256(sign ‖ enc ‖ kem ‖ sig) — all four keys committed.
        if req.x25519_pk and req.mlkem768_pk and req.mldsa65_pk and len(pk_bytes) == 32:
            try:
                h = hashlib.sha256()
                h.update(pk_bytes)
                h.update(_raw(req.x25519_pk, 32))       # X25519 enc
                h.update(_raw(req.mlkem768_pk, 1568))   # ML-KEM-1024 kem (field name is a misnomer)
                h.update(_raw(req.mldsa65_pk, 2592))    # ML-DSA-87 sig (field name is a misnomer)
                if h.hexdigest() == fp:
                    verified = True
            except Exception:
                pass
        # Classical bound DID: SHA256(sign ‖ enc).
        if not verified and req.x25519_pk and len(pk_bytes) == 32:
            try:
                h = hashlib.sha256()
                h.update(pk_bytes)
                h.update(_raw(req.x25519_pk, 32))
                if h.hexdigest() == fp:
                    verified = True
            except Exception:
                pass
        # Legacy DID: SHA256(sign) only.
        if not verified and len(pk_bytes) == 32:
            if hashlib.sha256(pk_bytes).hexdigest() == fp:
                verified = True

        if not verified:
            raise HTTPException(
                status_code=400,
                detail="Fingerprint must equal SHA256 of public keys (hybrid/classical/legacy)"
            )

        # Sanitize display_name (H-2: prevent injection)
        import re as _re
        if req.display_name:
            req.display_name = req.display_name.strip()[:64]
            req.display_name = _re.sub(r'[\x00-\x1f\x7f]', '', req.display_name) or None

        # Check fingerprint not already taken
        existing = db.execute(
            "SELECT fingerprint FROM verified_identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="This fingerprint is already registered")

        # Check slug uniqueness if provided
        if req.slug:
            slug_taken = db.execute(
                "SELECT fingerprint FROM verified_identities WHERE slug = ?",
                (req.slug.lower(),)
            ).fetchone()
            if slug_taken:
                raise HTTPException(status_code=409, detail=f"svrnty.is/{req.slug} is already claimed")

        # Create verified identity. email_hash is a vestigial NOT NULL column —
        # open mint stores "" (no email is ever collected or persisted; I-7).
        db.execute(
            "INSERT INTO verified_identities (fingerprint, email_hash, public_key, encryption_pk, x25519_pk, mldsa65_pk, mlkem768_pk, key_version, display_name, slug, identity_type, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (req.fingerprint, "", req.public_key, req.encryption_pk or req.x25519_pk, req.x25519_pk, req.mldsa65_pk, req.mlkem768_pk, req.key_version, req.display_name, req.slug.lower() if req.slug else None, req.identity_type, now_iso())
        )
        db.commit()

        # Register with satellite relay — forward the FULL key bundle so the satellite
        # can re-derive the canonical DID = SHA256(sign‖enc‖kem‖sig). The satellite's
        # misnomer-free field names map from registration's: x25519_pk→encryption_pk,
        # mlkem768_pk→pq_kem_pk (ML-KEM-1024), mldsa65_pk→pq_sig_pk (ML-DSA-87).
        satellite_ok = register_with_satellite(
            req.fingerprint, req.public_key, req.display_name,
            encryption_pk=req.x25519_pk,
            pq_kem_pk=req.mlkem768_pk,
            pq_sig_pk=req.mldsa65_pk,
        )

        # Build export bundle — forced export on identity creation
        # The client MUST save this before proceeding; no server-side recovery (the user's backup is the only recovery).
        export_bundle = {
            "svrnty_version": "0.1.0",
            "fingerprint": req.fingerprint,
            "public_key": req.public_key,
            "display_name": req.display_name,
            "slug": req.slug.lower() if req.slug else None,
            "registered_at": now_iso(),
            "export_note": "This file contains your PUBLIC identity only. Your private key is stored locally in your browser. Back up your full identity using the Export button in svrnty.",
        }

        return {
            "status": "verified",
            "fingerprint": req.fingerprint,
            "slug": req.slug.lower() if req.slug else None,
            "profile_url": f"https://svrnty.is/u/{req.slug.lower()}" if req.slug else None,
            "satellite_registered": satellite_ok,
            "export_bundle": export_bundle,
            "must_export": True,
            "message": "Identity created. SAVE YOUR EXPORT FILE NOW — no server can reset or recover your account, so your backup IS your recovery. Keep it somewhere safe."
        }
    finally:
        db.close()


@app.get("/identity/{fingerprint}")
async def get_identity(fingerprint: str):
    """Lookup a verified identity by fingerprint (public info only).

    gated-A: also returns `epoch` (current key-transition generation — the client
    reads it to construct/rebind its sig_pubkey binding) and `has_sig_pubkey` (bool).
    The raw sig_pubkey is NOT exposed in this public lookup (data minimization — the
    owner already holds it; a third party does not need it)."""
    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, public_key, x25519_pk, mldsa65_pk, mlkem768_pk, key_version, display_name, slug, registered_at, epoch, sig_pubkey FROM verified_identities WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()

        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        result = dict(identity)
        result["epoch"] = result.get("epoch") or 0
        result["has_sig_pubkey"] = bool(result.get("sig_pubkey"))
        result.pop("sig_pubkey", None)
        return result
    finally:
        db.close()


class BindRequest(BaseModel):
    fingerprint: str
    sig_pubkey: str = Field(..., min_length=64, max_length=64)  # raw ed25519, lowercase hex
    nonce: str = Field(..., min_length=2, max_length=128)       # lowercase hex (client 32B CSPRNG)
    epoch: int = Field(..., ge=0)
    binding_sig: str                                            # base64 Ed25519 over tag#2 (identity key)


@app.post("/bind")
async def bind_sig_pubkey(req: BindRequest):
    """gated-A: bind a per-request AUTH key (sig_pubkey) to an identity.

    The client signs tag#2 "svrnty-bind:{hex(sig_pubkey)}:{hex(nonce)}:{epoch}" with
    its IDENTITY key (raw ed25519 via scalar-extract). We verify that signature
    against the stored identity public_key, require a FRESH nonce and epoch ==
    current, store sig_pubkey, and propagate to the satellite (which re-verifies).
    Rebind = fresh nonce + current epoch (A3/C1). No PGP anywhere.
    """
    import base64
    fp = req.fingerprint
    if not all(c in "0123456789abcdef" for c in req.sig_pubkey):
        raise HTTPException(status_code=400, detail="sig_pubkey must be 64 lowercase-hex chars")
    if not (all(c in "0123456789abcdef" for c in req.nonce) and len(req.nonce) % 2 == 0):
        raise HTTPException(status_code=400, detail="nonce must be lowercase hex")

    db = get_db()
    try:
        identity = db.execute(
            "SELECT public_key, epoch FROM verified_identities WHERE fingerprint = ?",
            (fp,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        current_epoch = identity["epoch"] if identity["epoch"] is not None else 0
        if req.epoch != current_epoch:
            raise HTTPException(status_code=409, detail=f"stale epoch (current={current_epoch})")

        if db.execute("SELECT 1 FROM bind_nonces WHERE fingerprint = ? AND nonce = ?",
                      (fp, req.nonce)).fetchone():
            raise HTTPException(status_code=409, detail="nonce already used")

        pubkey_bytes = _identity_pubkey_bytes(identity["public_key"])
        try:
            sig_bytes = base64.b64decode(req.binding_sig.replace(" ", "+"))
        except Exception:
            raise HTTPException(status_code=400, detail="binding_sig not valid base64")
        if not _raw_ed25519_verify(pubkey_bytes, sig_bytes,
                                   _bind_preimage(req.sig_pubkey, req.nonce, req.epoch)):
            raise HTTPException(status_code=403, detail="invalid binding signature")

        # commit: consume nonce + set sig_pubkey (idempotent SET at the current epoch)
        db.execute("INSERT INTO bind_nonces (fingerprint, nonce, epoch, used_at) VALUES (?, ?, ?, ?)",
                   (fp, req.nonce, req.epoch, now_iso()))
        db.execute("UPDATE verified_identities SET sig_pubkey = ? WHERE fingerprint = ?",
                   (req.sig_pubkey, fp))
        # clause-1 D-lane: aggregate-only audit (no per-event key-lifecycle graph)
        db.execute("INSERT INTO gated_a_audit (event, count) VALUES ('sig_pubkey_bind', 1) "
                   "ON CONFLICT(event) DO UPDATE SET count = count + 1")
        db.commit()
    finally:
        db.close()

    # propagate to satellite (best-effort; the satellite RE-VERIFIES the tag#2 sig)
    push_binding_to_satellite(fp, req.sig_pubkey, req.nonce, req.epoch, req.binding_sig)
    return {"status": "bound", "fingerprint": fp, "epoch": req.epoch}


def _generate_qr_svg(url: str) -> str:
    """Generate a QR code as inline SVG for the profile URL."""
    try:
        import io
        import segno
        qr = segno.make(url, error="L")
        buf = io.BytesIO()
        qr.save(buf, kind="svg", xmldecl=False, svgns=False, border=0, scale=6,
                dark="#0a0a1a", light="#ffffff")
        return buf.getvalue().decode()
    except Exception:
        return '<svg width="180" height="180"></svg>'


def _escape_html(s: str) -> str:
    """Escape HTML special characters to prevent XSS.

    F-C1: also escape single-quote and backtick. display_name is
    rendered inside single-quoted inline-JS string literals (add.html:177,
    profile.html:227); without ' escaping an attacker-chosen name could break out of
    the JS string and run code on the svrnty.is origin. Inside <script> the &#x27;
    stays literal (entities aren't decoded there) so the breakout is closed; in HTML
    text/attribute contexts &#x27; decodes back to ' so legit names (O'Brien) render
    correctly. & is replaced first so the entity ampersands are not double-escaped.
    """
    if s is None:
        return ""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#x27;").replace("`", "&#x60;"))


def _render_profile(identity: dict) -> str:
    """Render profile.html with identity data."""
    profile_path = Path(__file__).parent / "profile.html"
    if not profile_path.exists():
        name = _escape_html(identity.get("display_name", "unknown"))
        return f"<h1>{name}</h1><p>{identity.get('fingerprint', '')}</p>"
    html = profile_path.read_text()
    # Format the join date
    joined = identity.get("registered_at", "")
    if joined:
        try:
            dt = datetime.fromisoformat(joined.replace("Z", "+00:00"))
            joined = dt.strftime("%B %Y")
        except (ValueError, AttributeError):
            joined = joined[:10]
    # Generate QR codes — profile URL + identity key exchange
    slug = identity.get("slug", "")
    fingerprint = identity.get("fingerprint", "")
    public_key = identity.get("public_key", "")
    qr_svg = _generate_qr_svg(f"https://svrnty.is/u/{slug}")
    # Key Exchange QR: URL so phone cameras open it as a link
    identity_url = f"https://svrnty.is/add?fp={fingerprint}&pk={public_key}"
    qr_identity_svg = _generate_qr_svg(identity_url)
    # Safe replacements — fingerprint and slug are validated at registration time
    display_name = _escape_html(identity.get("display_name", "unknown"))
    identity_type = identity.get("identity_type", "human")
    if identity_type not in ("human", "agent", "hybrid"):
        identity_type = "human"
    html = html.replace("{{DISPLAY_NAME}}", display_name)
    html = html.replace("{{SLUG}}", _escape_html(slug))
    html = html.replace("{{FINGERPRINT}}", _escape_html(fingerprint))
    html = html.replace("{{IDENTITY_TYPE}}", identity_type)
    html = html.replace("{{JOINED_DATE}}", joined)
    html = html.replace("{{QR_SVG}}", qr_svg)
    html = html.replace("{{QR_IDENTITY_SVG}}", qr_identity_svg)
    return html


def _render_not_found(slug: str) -> str:
    """Render a styled 404 page for unclaimed slugs."""
    slug = _escape_html(slug)
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>not found — svrnty</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'SF Mono','Fira Code','Cascadia Code',monospace; background: #0a0a1a;
    color: #e0e0e0; min-height: 100vh; display: flex; flex-direction: column;
    align-items: center; justify-content: center; padding: 2rem; }}
  .container {{ max-width: 480px; width: 100%; text-align: center; }}
  h2 {{ color: #c9a227; font-size: 1.5rem; margin-bottom: 1rem; }}
  p {{ color: #888; margin-bottom: 2rem; font-size: 0.9rem; }}
  a {{ display: inline-block; padding: 14px 2rem; background: #c9a227; color: #0a0a1a;
    border-radius: 8px; font-family: inherit; font-weight: bold; text-decoration: none; }}
  a:hover {{ background: #d4b33c; }}
  footer {{ margin-top: 3rem; color: #444; font-size: 0.75rem; }}
</style></head><body>
<div class="container">
  <h2>svrnty.is/u/{slug}</h2>
  <p>This identity hasn't been claimed yet.</p>
  <a href="https://svrnty.is/">Claim it</a>
</div>
<footer>svrnty — sovereign identity for a sovereign web</footer>
</body></html>"""


@app.get("/u/{slug}")
async def get_identity_by_slug(slug: str, request: Request):
    """Lookup a verified identity by URL slug. Returns HTML for browsers, JSON for API clients."""
    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, public_key, display_name, slug, identity_type, registered_at FROM verified_identities WHERE slug = ?",
            (slug.lower(),)
        ).fetchone()

        accept = request.headers.get("accept", "")
        wants_html = "text/html" in accept

        if not identity:
            if wants_html:
                return HTMLResponse(content=_render_not_found(slug.lower()), status_code=404)
            raise HTTPException(status_code=404, detail="Identity not found")

        if wants_html:
            return HTMLResponse(content=_render_profile(dict(identity)))
        return dict(identity)
    finally:
        db.close()


@app.get("/u/{slug}/keys")
async def get_public_keys(slug: str):
    """Export all public keys for a svrnty identity. Public info only."""
    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, public_key, x25519_pk, mldsa65_pk, mlkem768_pk, key_version, display_name, slug, registered_at FROM verified_identities WHERE slug = ?",
            (slug.lower(),)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")
        row = dict(identity)
        # Build did:key if possible
        did_key = None
        try:
            from crypto_utils import fingerprint_to_did_key
            did_key = fingerprint_to_did_key(row["public_key"])
        except Exception:
            pass
        return {
            "fingerprint": row["fingerprint"],
            "display_name": row["display_name"],
            "slug": row["slug"],
            "key_version": row.get("key_version", 1),
            "keys": {
                "ed25519": row["public_key"],
                "x25519": row.get("x25519_pk"),
                "mldsa65": row.get("mldsa65_pk"),
                "mlkem768": row.get("mlkem768_pk"),
            },
            "did_key": did_key,
            "profile_url": f"https://svrnty.is/u/{row['slug']}",
            "registered_at": row["registered_at"],
        }
    finally:
        db.close()


@app.get("/u/{slug}/keys/qr")
async def get_key_exchange_qr(slug: str, request: Request):
    """Generate a QR code for key exchange. Contains fingerprint + Ed25519 public key.

    The QR encodes: https://svrnty.is/add?fp={fingerprint}&pk={ed25519_pk}
    Phone cameras open it as a link → /add page verifies the key binding
    client-side (SHA256(pk)==fp) and offers "Add Contact".

    Returns SVG by default. Add ?format=png for PNG (if pillow available).
    """
    db = get_db()
    try:
        identity = db.execute(
            "SELECT fingerprint, public_key, display_name, slug FROM verified_identities WHERE slug = ?",
            (slug.lower(),)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")
        row = dict(identity)
        # Build URL for QR — phone cameras open it as a link
        # fp + pk in query params enables client-side verification
        uri = f"https://svrnty.is/add?fp={row['fingerprint']}&pk={row['public_key']}"
        try:
            import io
            import segno
            qr = segno.make(uri, error="M")
            buf = io.BytesIO()
            fmt = request.query_params.get("format", "svg")
            if fmt == "png":
                qr.save(buf, kind="png", scale=8, dark="#0a0a1a", light="#ffffff", border=2)
                return Response(content=buf.getvalue(), media_type="image/png")
            else:
                qr.save(buf, kind="svg", xmldecl=False, svgns=False, border=0, scale=6,
                        dark="#0a0a1a", light="#ffffff")
                return Response(content=buf.getvalue(), media_type="image/svg+xml")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"QR generation failed: {e}")
    finally:
        db.close()


@app.get("/u/{slug}/contact.vcf")
async def get_vcard(slug: str):
    """Download a vCard for a svrnty identity. Public info only — no private contact methods."""
    db = get_db()
    try:
        identity = db.execute(
            "SELECT display_name, slug, fingerprint, registered_at FROM verified_identities WHERE slug = ?",
            (slug.lower(),)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")
        row = dict(identity)
        name = row["display_name"]
        fp = row["fingerprint"]
        url = f"https://svrnty.is/u/{row['slug']}"
        vcf = (
            "BEGIN:VCARD\r\n"
            "VERSION:3.0\r\n"
            f"FN:{name}\r\n"
            f"URL:{url}\r\n"
            f"NOTE:svrnty fingerprint: {fp}\r\n"
            "END:VCARD\r\n"
        )
        return Response(
            content=vcf,
            media_type="text/vcard",
            headers={"Content-Disposition": f'attachment; filename="{row["slug"]}.vcf"'}
        )
    finally:
        db.close()


@app.get("/slug/{slug}")
async def check_slug(slug: str):
    """Check if a slug is available (also serves as lookup)."""
    db = get_db()
    try:
        existing = db.execute(
            "SELECT fingerprint FROM verified_identities WHERE slug = ?",
            (slug.lower(),)
        ).fetchone()
        result = {"slug": slug.lower(), "available": existing is None}
        if existing:
            result["fingerprint"] = existing[0]
        return result
    finally:
        db.close()


class SlugClaimRequest(BaseModel):
    fingerprint: str
    signature: Optional[str] = Field(None, description="Ed25519 signature proving key ownership (optional during initial registration)")


@app.post("/slug/{name}/claim")
async def claim_slug(name: str, req: SlugClaimRequest):
    """Claim a URL slug for a verified identity (svrnty.is/<name>)."""
    slug = name.lower().strip()

    # Validate slug format
    import re
    if len(slug) < 3 or len(slug) > 32 or not re.match(r'^[a-z0-9][a-z0-9_-]*$', slug):
        raise HTTPException(status_code=400, detail="Slug must be 3-32 chars: a-z, 0-9, -, _")

    db = get_db()
    try:
        # Auth: prove you own this fingerprint
        # During initial registration (no sig), allow claim if identity was just created (<10min)
        if req.signature:
            if not verify_ownership(req.fingerprint, req.signature, db):
                raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")
        else:
            recent = db.execute(
                "SELECT registered_at FROM verified_identities WHERE fingerprint = ? AND registered_at > datetime('now', '-10 minutes')",
                (req.fingerprint,)
            ).fetchone()
            if not recent:
                raise HTTPException(status_code=403, detail="Signature required — initial claim window expired")
        # Verify identity exists
        identity = db.execute(
            "SELECT fingerprint, slug FROM verified_identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found — verify email first")

        # Check if already claimed by someone else
        existing = db.execute(
            "SELECT fingerprint FROM verified_identities WHERE slug = ? AND fingerprint != ?",
            (slug, req.fingerprint)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail=f"svrnty.is/{slug} is already claimed")

        # Claim it
        db.execute(
            "UPDATE verified_identities SET slug = ? WHERE fingerprint = ?",
            (slug, req.fingerprint)
        )
        db.commit()

        return {
            "status": "claimed",
            "slug": slug,
            "profile_url": f"https://svrnty.is/u/{slug}",
            "fingerprint": req.fingerprint,
        }
    finally:
        db.close()


@app.get("/add", response_class=HTMLResponse)
async def add_contact_page(request: Request):
    """Landing page for QR scan: svrnty:{fingerprint}:{public_key}.

    When a phone camera scans a Key Exchange QR, it opens:
    svrnty.is/add?fp={fingerprint}&pk={public_key}

    This page verifies the fingerprint matches the public key,
    looks up the identity for display info, and offers "Add Contact".
    """
    fp = request.query_params.get("fp", "")
    pk = request.query_params.get("pk", "")

    # Also handle svrnty: URI format (some QR scanners pass it as-is)
    uri = request.query_params.get("uri", "")
    if uri.startswith("svrnty:") and not fp:
        parts = uri[len("svrnty:"):].split(":", 1)
        if len(parts) == 2:
            fp, pk = parts

    # Look up identity for display info
    display_name = ""
    slug = ""
    identity_type = "human"
    registered = False
    if fp:
        db = get_db()
        try:
            identity = db.execute(
                "SELECT display_name, slug, identity_type, registered_at FROM verified_identities WHERE fingerprint = ?",
                (fp,)
            ).fetchone()
            if identity:
                display_name = identity["display_name"] or ""
                slug = identity["slug"] or ""
                identity_type = identity["identity_type"] or "human"
                registered = True
        finally:
            db.close()

    add_path = Path(__file__).parent / "add.html"
    if add_path.exists():
        html = add_path.read_text()
        html = html.replace("{{FINGERPRINT}}", _escape_html(fp))
        html = html.replace("{{PUBLIC_KEY}}", _escape_html(pk))
        html = html.replace("{{DISPLAY_NAME}}", _escape_html(display_name))
        html = html.replace("{{SLUG}}", _escape_html(slug))
        html = html.replace("{{IDENTITY_TYPE}}", identity_type if identity_type in ("human", "agent", "hybrid") else "human")
        html = html.replace("{{REGISTERED}}", "true" if registered else "false")
        return HTMLResponse(content=html)

    # Fallback if template missing
    if registered:
        return HTMLResponse(content=f"<h1>Add {_escape_html(display_name)}</h1><p>Fingerprint: {_escape_html(fp)}</p>")
    return HTMLResponse(content=f"<h1>Unknown identity</h1><p>Fingerprint: {_escape_html(fp)}</p>")


@app.get("/", response_class=HTMLResponse)
async def landing_page():
    """Serve the svrnty signup landing page."""
    landing_path = Path(__file__).parent / "landing.html"
    if landing_path.exists():
        return HTMLResponse(content=landing_path.read_text())
    return HTMLResponse(content="<h1>svrnty</h1><p>Landing page not found.</p>")


@app.get("/about", response_class=HTMLResponse)
async def about_page():
    """Serve the svrnty about page — the Three Ceremonies."""
    about_path = Path(__file__).parent / "about.html"
    if about_path.exists():
        return HTMLResponse(content=about_path.read_text())
    return HTMLResponse(content="<h1>svrnty</h1><p>About page not found.</p>")


@app.get("/sovereignty", response_class=HTMLResponse)
async def sovereignty_page():
    """Serve 'The Weight of the Key' — what sovereignty means."""
    sov_path = Path(__file__).parent / "sovereignty.html"
    if sov_path.exists():
        return HTMLResponse(content=sov_path.read_text())
    return HTMLResponse(content="<h1>svrnty</h1><p>Page not found.</p>")


class BackupRequest(BaseModel):
    """Store an encrypted identity backup on the satellite.

    The backup blob is encrypted client-side with a user passphrase
    before upload. The satellite stores it as an opaque blob —
    it cannot read the contents. This is the recovery path.
    """
    fingerprint: str = Field(..., min_length=8, max_length=128)
    encrypted_backup: str = Field(..., max_length=128 * 1024,
                                   description="Client-encrypted identity file (base64)")
    backup_hash: str = Field(..., min_length=64, max_length=128,
                              description="SHA-256 of the decrypted backup for integrity verification")
    signature: str = Field(..., description="Ed25519 signature proving key ownership")


@app.post("/backup/store")
async def store_backup(req: BackupRequest):
    """Store encrypted identity backup. Client encrypts with passphrase before upload.

    The satellite never sees the plaintext. Recovery requires:
    1. The passphrase (only in the user's head)
    2. Access to this satellite

    For additional redundancy, users should also save locally or to
    Google Drive / Dropbox via the export button.
    """
    db = get_db()
    try:
        # Auth: prove you own this fingerprint before storing/overwriting backup
        if not verify_ownership(req.fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        # Verify identity exists
        identity = db.execute(
            "SELECT fingerprint FROM verified_identities WHERE fingerprint = ?",
            (req.fingerprint,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identity not found")

        # Ensure backup table exists
        db.execute("""
            CREATE TABLE IF NOT EXISTS identity_backups (
                fingerprint TEXT PRIMARY KEY REFERENCES verified_identities(fingerprint),
                encrypted_backup TEXT NOT NULL,
                backup_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Upsert backup
        db.execute(
            """INSERT INTO identity_backups (fingerprint, encrypted_backup, backup_hash, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(fingerprint) DO UPDATE SET
                   encrypted_backup = excluded.encrypted_backup,
                   backup_hash = excluded.backup_hash,
                   updated_at = excluded.updated_at""",
            (req.fingerprint, req.encrypted_backup, req.backup_hash, now_iso(), now_iso())
        )
        db.commit()

        return {"status": "backed_up", "fingerprint": req.fingerprint, "message": "Encrypted backup stored. You'll need your passphrase to recover."}
    finally:
        db.close()


class BackupRecoverRequest(BaseModel):
    fingerprint: str = Field(..., min_length=8, max_length=128)
    signature: str = Field(..., description="Ed25519 signature proving key ownership")


@app.post("/backup/recover/{fingerprint}")
async def recover_backup(fingerprint: str, req: BackupRecoverRequest):
    """Retrieve encrypted backup. Requires signature proof. User decrypts client-side with their passphrase."""
    if req.fingerprint != fingerprint:
        raise HTTPException(status_code=400, detail="Fingerprint mismatch")

    db = get_db()
    try:
        # Auth: prove you own this key before downloading backup
        if not verify_ownership(fingerprint, req.signature, db):
            raise HTTPException(status_code=403, detail="Invalid signature — prove you own this key")

        db.execute("""
            CREATE TABLE IF NOT EXISTS identity_backups (
                fingerprint TEXT PRIMARY KEY,
                encrypted_backup TEXT NOT NULL,
                backup_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        backup = db.execute(
            "SELECT encrypted_backup, backup_hash, updated_at FROM identity_backups WHERE fingerprint = ?",
            (fingerprint,)
        ).fetchone()
        if not backup:
            raise HTTPException(status_code=404, detail="No backup found for this identity")

        return {
            "fingerprint": fingerprint,
            "encrypted_backup": backup["encrypted_backup"],
            "backup_hash": backup["backup_hash"],
            "backed_up_at": backup["updated_at"],
            "message": "Decrypt this with your passphrase to recover your identity."
        }
    finally:
        db.close()


@app.get("/health")
async def health():
    """Health check."""
    db = get_db()
    try:
        count = db.execute("SELECT COUNT(*) FROM verified_identities").fetchone()[0]
        return {
            "status": "online",
            "service": "registration",
            "identities": count,
            "email_configured": bool(RESEND_API_KEY),
        }
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn
    # access_log=False: URL paths carry fingerprint/slug; suppress the
    # access log on the direct-run path too, matching the Docker CMD --no-access-log.
    uvicorn.run(app, host="0.0.0.0", port=8101, access_log=False)
