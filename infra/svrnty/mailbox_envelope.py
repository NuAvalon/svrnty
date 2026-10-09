"""PQ-hybrid mailbox envelope + onion peel — SATELLITE (server) side, Python.

Byte-exact reimplementation of the co-verified client primitives:
  - src/lib/crypto/mailbox-envelope.ts  (openMailboxEnvelope / sealToMailbox)
  - src/lib/crypto/onion-envelope.ts    (peelOnion / sealOnion)
against the Track A §5 PQ-hybrid mailbox-envelope contract.

The satellite is the RECIPIENT of the OUTER onion shell: it OPENS the outer with its OWN
{x25519, ML-KEM-1024} secret keys, learns only {route, fp-stripped inner}, and routes by `route`.
It CANNOT read `inner` (that is sealed to the recipient DEVICE, not the satellite) and it MUST NOT
learn a stable recipient id (K0-1 blinding: inner.mailbox_fp is stripped on the wire and re-stripped
here unconditionally).

Byte-exactness proven before this module was written:
  - §5 combiner/AEAD KAT matches @noble byte-for-byte (Python `cryptography` HKDF/AAD/AES-256-GCM).
  - ML-KEM-1024 noble<->oqs interop matches both directions (client @noble encaps -> satellite oqs decaps).

Contract, byte-for-byte (do NOT change without a version bump + security co-verify):
  ALG   = "X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM"
  K     = HKDF-SHA256(IKM = ss_c || ss_pq || epk || kem_ct, salt=None, info="svrnty-mailbox-env-v1:"||fp_HEX, L=32)
  AAD   = 0x01 || "|" || ALG || "|" || fp_RAW32 || "|" || epk || "|" || kem_ct
          (NOTE: fp enters the KDF info as the 64-char HEX string, but the AAD as RAW 32 bytes.)
  ct    = AES-256-GCM(K, nonce[12], plaintext, AAD) = ciphertext || 16B tag
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ── Contract constants (byte-exact to mailbox-envelope.ts) ──────────────────────
MAILBOX_ENV_ALG = "X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM"
_ALG_BYTES = MAILBOX_ENV_ALG.encode("ascii")
_KDF_INFO_PREFIX = b"svrnty-mailbox-env-v1:"
_AAD_VERSION = 0x01
X25519_LEN = 32
KEM_CT_LEN = 1568
KEM_PUB_LEN = 1568
KEM_SEC_LEN = 3168
NONCE_LEN = 12
AES_KEY_LEN = 32
_ZERO32 = b"\x00" * 32

_MLKEM_ALG = "ML-KEM-1024"


# ── Key material ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class MailboxSecretKeys:
    """The satellite's OWN mailbox secret keys (never leave the box)."""
    x25519_sec: bytes  # 32B raw
    mlkem1024_sec: bytes  # 3168B raw (FIPS 203 ML-KEM-1024 decapsulation key)


@dataclass(frozen=True)
class MailboxPublicKeys:
    x25519_pub: bytes  # 32B raw
    mlkem1024_pub: bytes  # 1568B raw


def derive_mailbox_fp(x25519_pub: bytes, mlkem1024_pub: bytes) -> str:
    """mailbox_fp = lowercase_hex(SHA256(x25519_pub[32] || mlkem1024_pub[1568]))."""
    if len(x25519_pub) != X25519_LEN:
        raise ValueError(f"bad x25519 pub length {len(x25519_pub)}")
    if len(mlkem1024_pub) != KEM_PUB_LEN:
        raise ValueError(f"bad ml-kem pub length {len(mlkem1024_pub)}")
    return hashlib.sha256(x25519_pub + mlkem1024_pub).hexdigest()


# ── Combiner + AEAD (byte-exact, KAT-pinned) ────────────────────────────────────
def derive_envelope_key(
    ss_c: bytes, ss_pq: bytes, epk: bytes, kem_ct: bytes, mailbox_fp_hex: str
) -> bytes:
    """K = HKDF-SHA256(IKM=ss_c||ss_pq||epk||kem_ct, salt=None, info=prefix||fp_HEX, L=32).

    `mailbox_fp_hex` enters `info` as its HEX STRING (per the §5 vector). Python HKDF salt=None
    == @noble undefined salt (both = HashLen zero bytes). KAT-verified."""
    ikm = ss_c + ss_pq + epk + kem_ct
    info = _KDF_INFO_PREFIX + mailbox_fp_hex.encode("ascii")
    return HKDF(algorithm=SHA256(), length=AES_KEY_LEN, salt=None, info=info).derive(ikm)


def build_envelope_aad(mailbox_fp_hex: str, epk: bytes, kem_ct: bytes) -> bytes:
    """AAD = 0x01 || "|" || ALG || "|" || mailbox_fp(RAW 32B) || "|" || epk || "|" || kem_ct.

    fp enters here as RAW 32 bytes (bytes.fromhex) — NOT hex. Binds version+recipient+both cts."""
    pipe = b"|"
    return (
        bytes([_AAD_VERSION]) + pipe
        + _ALG_BYTES + pipe
        + bytes.fromhex(mailbox_fp_hex) + pipe
        + epk + pipe
        + kem_ct
    )


def _mlkem_decapsulate(kem_ct: bytes, mlkem1024_sec: bytes) -> bytes:
    """ML-KEM-1024 decapsulate via liboqs (FIPS 203). IND-CCA2 implicit-reject: a tampered ct
    decaps to a PSEUDO-RANDOM ss (does NOT raise) → wrong K → the GCM tag fails downstream."""
    import oqs  # lazy: only the decap path needs liboqs (Dockerfile must install it)

    with oqs.KeyEncapsulation(_MLKEM_ALG, secret_key=mlkem1024_sec) as kem:
        return kem.decap_secret(kem_ct)


# ── OPEN (satellite decrypts the outer shell) ───────────────────────────────────
def open_mailbox_envelope(
    pkg: Any, secrets: MailboxSecretKeys, my_mailbox_fp_hex: str
) -> Optional[bytes]:
    """OPEN a package with the recipient (satellite) mailbox secrets. Returns plaintext bytes, or
    None on ANY rejection (version/alg mismatch, wrong-recipient fp, malformed field, tag failure,
    fail-closed x25519). NEVER raises on attacker-controlled input."""
    try:
        # Hostile input: a polled/POSTed blob can be null / a primitive / missing fields.
        if not isinstance(pkg, dict):
            return None
        if pkg.get("v") != 1 or pkg.get("alg") != MAILBOX_ENV_ALG:
            return None
        if pkg.get("mailbox_fp") != my_mailbox_fp_hex:
            return None  # wrong recipient — reject before any crypto

        try:
            epk = base64.b64decode(pkg["epk"], validate=True)
            kem_ct = base64.b64decode(pkg["kem_ct"], validate=True)
            nonce = base64.b64decode(pkg["nonce"], validate=True)
            ct = base64.b64decode(pkg["ct"], validate=True)
        except (KeyError, TypeError, ValueError, base64.binascii.Error):
            return None
        if len(epk) != X25519_LEN or len(kem_ct) != KEM_CT_LEN or len(nonce) != NONCE_LEN:
            return None

        # x25519 raw ECDH. Reject invalid point (raises) and all-zero shared secret (low-order
        # point) to match @noble's fail-closed behaviour (contract §5 note).
        try:
            ss_c = X25519PrivateKey.from_private_bytes(secrets.x25519_sec).exchange(
                X25519PublicKey.from_public_bytes(epk)
            )
        except Exception:
            return None
        if ss_c == _ZERO32:
            return None

        # IND-CCA2 implicit reject: tampered kem_ct → pseudo-random ss_pq → wrong K → tag fail.
        ss_pq = _mlkem_decapsulate(kem_ct, secrets.mlkem1024_sec)

        # fp for the KDF/AAD is the package's own claimed fp; it already == my_mailbox_fp_hex
        # (checked above), so a mismatch cannot smuggle a different binding past the recipient gate.
        fp_hex = pkg["mailbox_fp"]
        k = derive_envelope_key(ss_c, ss_pq, epk, kem_ct, fp_hex)
        aad = build_envelope_aad(fp_hex, epk, kem_ct)
        try:
            return AESGCM(k).decrypt(nonce, ct, aad)
        except Exception:
            return None  # tag failure ⇒ REJECT (wrong ss_pq / tamper / wrong recipient)
    except Exception:
        # Defensive belt: the contract says OPEN never throws on hostile input.
        return None


# ── SEAL (satellite encrypts a response TO a client mailbox) ─────────────────────
def _mlkem_encapsulate(mlkem1024_pub: bytes) -> Tuple[bytes, bytes]:
    """ML-KEM-1024 encapsulate via liboqs (FIPS 203) to a recipient public key.
    Returns (kem_ct[1568], ss_pq[32]). The ENCAP counterpart to _mlkem_decapsulate."""
    import oqs  # lazy: only the seal path needs liboqs (Dockerfile installs it)

    if len(mlkem1024_pub) != KEM_PUB_LEN:
        raise ValueError(f"bad ml-kem pub length {len(mlkem1024_pub)}")
    with oqs.KeyEncapsulation(_MLKEM_ALG) as kem:
        kem_ct, ss_pq = kem.encap_secret(mlkem1024_pub)
    return kem_ct, ss_pq


def seal_mailbox_envelope(
    plaintext: bytes, recipient_x25519_pub: bytes, recipient_mlkem1024_pub: bytes
) -> dict:
    """SEAL `plaintext` TO a recipient's mailbox pubkeys — the byte-exact ENCAP inverse of
    open_mailbox_envelope (SAME §5 contract, SAME KAT-pinned derive_envelope_key/build_envelope_aad).
    A package produced here is recovered byte-for-byte by the client's TS openMailboxEnvelope.

    Satellite-side use: seal a PSI GET response to the REQUESTING client's (ephemeral, per-session)
    mailbox key so all 4 PSI exchanges are hybrid-PQ end-to-end. Reject-classical:
    ML-KEM is REQUIRED, no classical-only fallback. Fresh single-use ephemeral x25519 epk + random
    12B nonce per call (never reused — contract + forward-secrecy)."""
    if len(recipient_x25519_pub) != X25519_LEN:
        raise ValueError(f"bad x25519 pub length {len(recipient_x25519_pub)}")
    # recipient_mlkem1024_pub length is validated inside _mlkem_encapsulate + derive_mailbox_fp.

    fp_hex = derive_mailbox_fp(recipient_x25519_pub, recipient_mlkem1024_pub)

    # fresh single-use ephemeral x25519; epk is the PUBLIC half carried on the wire.
    eph_sec = X25519PrivateKey.generate()
    epk = eph_sec.public_key().public_bytes_raw()
    ss_c = eph_sec.exchange(X25519PublicKey.from_public_bytes(recipient_x25519_pub))
    if ss_c == _ZERO32:
        # low-order / degenerate recipient point — fail closed (never seal to an all-zero secret).
        raise ValueError("x25519 shared secret is all-zero (invalid recipient key)")

    # ML-KEM-1024 encapsulate to the recipient KEM pub → (ct[1568], ss_pq[32]).
    kem_ct, ss_pq = _mlkem_encapsulate(recipient_mlkem1024_pub)
    if len(kem_ct) != KEM_CT_LEN:
        raise ValueError(f"ml-kem ciphertext wrong length {len(kem_ct)}")

    # IDENTICAL combiner + AAD as OPEN (reused, not re-derived) → byte-exact interop by construction.
    k = derive_envelope_key(ss_c, ss_pq, epk, kem_ct, fp_hex)
    aad = build_envelope_aad(fp_hex, epk, kem_ct)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(k).encrypt(nonce, plaintext, aad)

    return {
        "v": 1,
        "alg": MAILBOX_ENV_ALG,
        "mailbox_fp": fp_hex,
        "epk": base64.b64encode(epk).decode("ascii"),
        "kem_ct": base64.b64encode(kem_ct).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


# ── PEEL the OUTER onion shell (satellite routing) ──────────────────────────────
def peel_onion(
    outer: Any, satellite_secrets: MailboxSecretKeys, satellite_mailbox_fp_hex: str
) -> Optional[dict]:
    """PEEL the OUTER shell with the SATELLITE's secrets → {"route": str, "inner": dict}.

    Returns None on ANY rejection (wrong satellite / tamper / malformed) and NEVER raises on hostile
    input. Enforces the K0-1 blinding invariant UNCONDITIONALLY: any `mailbox_fp` a malformed wire
    might carry inside `inner` is deleted, so a peeled inner is always fp-stripped regardless of wire."""
    try:
        pt = open_mailbox_envelope(outer, satellite_secrets, satellite_mailbox_fp_hex)
        if pt is None:
            return None
        try:
            obj = json.loads(pt.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None  # outer opened but plaintext isn't our JSON shape
        if (
            not isinstance(obj, dict)
            or not isinstance(obj.get("route"), str)
            or not isinstance(obj.get("inner"), dict)
        ):
            return None
        inner = obj["inner"]
        inner.pop("mailbox_fp", None)  # K0-1 blinding — enforced on the peel output, always
        return {"route": obj["route"], "inner": inner}
    except Exception:
        return None
