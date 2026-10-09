"""Satellite's OWN routing keypair (x25519 + ML-KEM-1024) for the K0 blind-router.

⚠ THREAT-MODEL NOTE: the base satellite holds NO private keys — "Stateless relay,
nothing to steal" (satellite.py header). The blind-router is the ONE deliberate exception: it holds
its OWN routing keypair to PEEL the OUTER onion shell. This is the designed two-keypair separation
(satellite keypair ≠ device keypair — onion-envelope.ts:11-14). Blast radius of a compromise of THIS
key is BOUNDED:
  • it lets an attacker peel OUTER shells → learn route_ids + that traffic flows, for the window;
  • it CANNOT read user CONTENT — `inner` is sealed to the recipient DEVICE, not the satellite;
  • route_ids are K1-blinded + rotating (HKDF[:16], one-way per window) → no cross-time linkage.
The key NEVER leaves the box (secret file, mode 0600); only the PUBLIC half + mailbox_fp are served.
Rotation posture (how often to mint a fresh satellite keypair, and how clients learn the new pub) is
an operator call — served live at GET /satellite/key so a rotation is a file swap + restart.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mailbox_envelope import (
    KEM_PUB_LEN,
    KEM_SEC_LEN,
    MAILBOX_ENV_ALG,
    X25519_LEN,
    MailboxSecretKeys,
    derive_mailbox_fp,
)

_MLKEM = "ML-KEM-1024"
_cache: Dict[str, Tuple[MailboxSecretKeys, dict, str]] = {}


def _generate() -> dict:
    import oqs  # lazy: only the blind-router (full mode) mints a satellite keypair

    xsk = X25519PrivateKey.generate()
    x_sec = xsk.private_bytes_raw()
    x_pub = xsk.public_key().public_bytes_raw()
    kem = oqs.KeyEncapsulation(_MLKEM)
    try:
        k_pub = kem.generate_keypair()
        k_sec = kem.export_secret_key()
    finally:
        kem.free()
    return {
        "alg": MAILBOX_ENV_ALG,
        "x25519_sec": x_sec.hex(),
        "x25519_pk": x_pub.hex(),
        "mlkem1024_sec": k_sec.hex(),
        "mlkem1024_pk": k_pub.hex(),
        "mailbox_fp": derive_mailbox_fp(x_pub, k_pub),
    }


def verify_mlkem_available() -> None:
    """Fail-fast self-check: prove liboqs ML-KEM-1024 is present + functional (keygen→encap→decap
    round-trip). Called at full-mode startup so a missing/broken liboqs fails LOUDLY here instead of
    silently 400-ing every /onion at runtime (open_mailbox_envelope catches all exceptions → None)."""
    try:
        import oqs
    except Exception as e:  # pragma: no cover - environment guard
        raise RuntimeError(
            "liboqs (`oqs`) is required for the full-mode blind-router (ML-KEM-1024 decap) but is "
            f"not importable: {e!r}. Install it in the image (the Dockerfile installs liboqs)."
        )
    with oqs.KeyEncapsulation(_MLKEM) as kem:
        pk = kem.generate_keypair()          # the object retains the matching secret internally
        ct, ss_encap = kem.encap_secret(pk)
        ss_decap = kem.decap_secret(ct)      # decaps with the object's own secret
    if ss_encap != ss_decap:
        raise RuntimeError("liboqs ML-KEM-1024 self-check failed: decap shared secret != encap")


def ensure_satellite_keypair(path) -> None:
    """Generate + persist the satellite routing keypair on first run (atomic, mode 0600). No-op if
    it already exists. Idempotent — safe to call at every startup."""
    path = Path(path)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(_generate()).encode("utf-8")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".satkey-")
    try:
        os.write(fd, data)
        os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(path))  # atomic; if a concurrent startup won the race, this replaces it
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    os.chmod(str(path), 0o600)


def load_satellite_keypair(path) -> Tuple[MailboxSecretKeys, dict, str]:
    """Load (generating on first use) the satellite routing keypair. Returns
    (MailboxSecretKeys, {"x25519_pk","mlkem1024_pk"} hex, mailbox_fp). Cached per path."""
    key = str(path)
    if key in _cache:
        return _cache[key]
    ensure_satellite_keypair(key)
    with open(key) as f:
        d = json.load(f)
    x_sec = bytes.fromhex(d["x25519_sec"])
    k_sec = bytes.fromhex(d["mlkem1024_sec"])
    x_pub = bytes.fromhex(d["x25519_pk"])
    k_pub = bytes.fromhex(d["mlkem1024_pk"])
    if (len(x_sec) != X25519_LEN or len(k_sec) != KEM_SEC_LEN
            or len(x_pub) != X25519_LEN or len(k_pub) != KEM_PUB_LEN):
        raise ValueError("satellite keypair file has bad key lengths")
    fp = derive_mailbox_fp(x_pub, k_pub)
    if fp != d.get("mailbox_fp"):
        raise ValueError("satellite keypair fp mismatch (corrupt key file)")
    sec = MailboxSecretKeys(x25519_sec=x_sec, mlkem1024_sec=k_sec)
    pub = {"x25519_pk": d["x25519_pk"], "mlkem1024_pk": d["mlkem1024_pk"]}
    _cache[key] = (sec, pub, fp)
    return _cache[key]
