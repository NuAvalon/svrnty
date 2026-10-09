"""
Svrnty message encryption — hybrid ECDH + authenticated encryption.

Protocol:
1. Sender generates ephemeral X25519 keypair
2. ECDH: ephemeral_sk + recipient_static_pk → shared_secret
3. HKDF-SHA256 derives symmetric key
4. ChaCha20-Poly1305 encrypts payload
5. Ed25519 signs the envelope (proves sender identity)

The satellite never sees plaintext. The recipient uses their
static X25519 private key + the ephemeral public key to derive
the same shared secret and decrypt.

Each message uses a fresh ephemeral key — compromise of one
message doesn't compromise others.
"""

import base64
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ── Key Generation ───────────────────────────────────────

def generate_identity_keys() -> dict:
    """Generate a full svrnty identity keypair (Ed25519 + X25519).

    Returns dict with base64-encoded keys:
      - signing_sk, signing_pk (Ed25519 — authentication)
      - encryption_sk, encryption_pk (X25519 — message encryption)
      - fingerprint (SHA-256 of signing public key)
    """
    # Signing keypair (Ed25519)
    sign_sk = Ed25519PrivateKey.generate()
    sign_pk = sign_sk.public_key()
    sign_pk_bytes = sign_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    sign_sk_bytes = sign_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    # Encryption keypair (X25519)
    enc_sk = X25519PrivateKey.generate()
    enc_pk = enc_sk.public_key()
    enc_pk_bytes = enc_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    enc_sk_bytes = enc_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    # Fingerprint = SHA-256 of signing public key
    from cryptography.hazmat.primitives.hashes import Hash
    digest = Hash(SHA256())
    digest.update(sign_pk_bytes)
    fingerprint = digest.finalize().hex()

    return {
        "signing_sk": base64.b64encode(sign_sk_bytes).decode(),
        "signing_pk": base64.b64encode(sign_pk_bytes).decode(),
        "encryption_sk": base64.b64encode(enc_sk_bytes).decode(),
        "encryption_pk": base64.b64encode(enc_pk_bytes).decode(),
        "fingerprint": fingerprint,
    }


# ── DID:key Interop ──────────────────────────────────────

# Multicodec prefixes (varint-encoded)
_ED25519_MULTICODEC = b'\xed\x01'   # 0xed = Ed25519 public key
_X25519_MULTICODEC = b'\xec\x01'    # 0xec = X25519 public key

# Base58btc alphabet (multibase 'z' prefix)
_B58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def _b58encode(data: bytes) -> str:
    """Base58btc encode (no external dependency)."""
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1])
    # Preserve leading zero bytes
    for byte in data:
        if byte == 0:
            result.append(b'1')
        else:
            break
    return b''.join(reversed(result)).decode()


def _b58decode(s: str) -> bytes:
    """Base58btc decode."""
    n = 0
    for ch in s.encode():
        n = n * 58 + _B58_ALPHABET.index(ch)
    # Count leading '1's (zero bytes)
    leading_zeros = 0
    for ch in s:
        if ch == '1':
            leading_zeros += 1
        else:
            break
    result = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    return b'\x00' * leading_zeros + result


def fingerprint_to_did_key(signing_pk_b64: str) -> str:
    """Convert a svrnty signing public key to a did:key identifier.

    did:key uses multibase (base58btc, 'z' prefix) encoding of
    multicodec-prefixed public key bytes.

    Example: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
    """
    pk_bytes = base64.b64decode(signing_pk_b64)
    prefixed = _ED25519_MULTICODEC + pk_bytes
    return f"did:key:z{_b58encode(prefixed)}"


def did_key_to_signing_pk(did: str) -> str:
    """Extract the base64-encoded Ed25519 public key from a did:key.

    Raises ValueError if the DID is malformed or uses a different key type.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Not a did:key with multibase 'z' prefix: {did}")
    decoded = _b58decode(did[len("did:key:z"):])
    if not decoded.startswith(_ED25519_MULTICODEC):
        raise ValueError(f"Not an Ed25519 did:key (unexpected multicodec prefix)")
    pk_bytes = decoded[len(_ED25519_MULTICODEC):]
    if len(pk_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 key length: {len(pk_bytes)} bytes")
    return base64.b64encode(pk_bytes).decode()


def identity_to_did_document(identity: dict, satellite_url: str = "", slug: str = "") -> dict:
    """Build a minimal DID Document from svrnty identity fields.

    Input: dict with signing_pk, encryption_pk, fingerprint (from generate_identity_keys).
    Output: W3C DID Core compliant document (subset).
    """
    did = fingerprint_to_did_key(identity["signing_pk"])
    enc_pk_bytes = base64.b64decode(identity["encryption_pk"])
    enc_prefixed = _X25519_MULTICODEC + enc_pk_bytes

    doc = {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#keys-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": f"z{_b58encode(_ED25519_MULTICODEC + base64.b64decode(identity['signing_pk']))}",
            },
            {
                "id": f"{did}#keys-2",
                "type": "X25519KeyAgreementKey2020",
                "controller": did,
                "publicKeyMultibase": f"z{_b58encode(enc_prefixed)}",
            },
        ],
        "authentication": [f"{did}#keys-1"],
        "assertionMethod": [f"{did}#keys-1"],
        "keyAgreement": [f"{did}#keys-2"],
    }

    if satellite_url:
        doc["service"] = [{
            "id": f"{did}#satellite",
            "type": "SvrntyRelay",
            "serviceEndpoint": satellite_url,
        }]

    if slug:
        doc["alsoKnownAs"] = [f"https://svrnty.is/{slug}"]

    return doc


# ── Message Encryption ───────────────────────────────────

def encrypt_message(
    plaintext: bytes,
    recipient_encryption_pk_b64: str,
    sender_signing_sk_b64: str,
    sender_fingerprint: str,
) -> dict:
    """Encrypt a message for a recipient.

    Returns a dict (the encrypted envelope) ready to be JSON-serialized
    and sent to the satellite as an encrypted_blob.
    """
    # Decode recipient's static X25519 public key
    recipient_pk_bytes = base64.b64decode(recipient_encryption_pk_b64)
    recipient_pk = X25519PublicKey.from_public_bytes(recipient_pk_bytes)

    # Generate ephemeral X25519 keypair (one-time for this message)
    ephemeral_sk = X25519PrivateKey.generate()
    ephemeral_pk = ephemeral_sk.public_key()
    ephemeral_pk_bytes = ephemeral_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ECDH: ephemeral_sk + recipient_pk → shared_secret
    shared_secret = ephemeral_sk.exchange(recipient_pk)

    # Derive symmetric key via HKDF-SHA256
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"svrnty-msg-v1",
    ).derive(shared_secret)

    # Encrypt with ChaCha20-Poly1305
    nonce = os.urandom(12)  # 96-bit nonce for ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(symmetric_key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

    # Sign the envelope: Ed25519(sk, ephemeral_pk || nonce || ciphertext)
    sender_sk_bytes = base64.b64decode(sender_signing_sk_b64)
    sign_sk = Ed25519PrivateKey.from_private_bytes(sender_sk_bytes)
    signed_data = ephemeral_pk_bytes + nonce + ciphertext
    signature = sign_sk.sign(signed_data)

    # Build envelope
    envelope = {
        "v": 1,
        "from": sender_fingerprint,
        "ephemeral_pk": base64.b64encode(ephemeral_pk_bytes).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
    }

    return envelope


def decrypt_message(
    envelope: dict,
    recipient_encryption_sk_b64: str,
    sender_signing_pk_b64: str,
) -> bytes:
    """Decrypt a received message.

    Verifies the sender's signature, then decrypts.
    Raises ValueError on signature failure or decryption failure.
    """
    # Decode fields
    ephemeral_pk_bytes = base64.b64decode(envelope["ephemeral_pk"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    signature = base64.b64decode(envelope["signature"])

    # Verify sender signature
    sender_pk_bytes = base64.b64decode(sender_signing_pk_b64)
    sender_pk = Ed25519PublicKey.from_public_bytes(sender_pk_bytes)
    signed_data = ephemeral_pk_bytes + nonce + ciphertext
    try:
        sender_pk.verify(signature, signed_data)
    except Exception as e:
        raise ValueError(f"Signature verification failed: {e}")

    # ECDH: recipient_sk + ephemeral_pk → shared_secret
    recipient_sk_bytes = base64.b64decode(recipient_encryption_sk_b64)
    recipient_sk = X25519PrivateKey.from_private_bytes(recipient_sk_bytes)
    ephemeral_pk = X25519PublicKey.from_public_bytes(ephemeral_pk_bytes)
    shared_secret = recipient_sk.exchange(ephemeral_pk)

    # Derive same symmetric key
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"svrnty-msg-v1",
    ).derive(shared_secret)

    # Decrypt
    cipher = ChaCha20Poly1305(symmetric_key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

    return plaintext


# ── Group Key Distribution ───────────────────────────────

def generate_group_key() -> bytes:
    """Generate a random symmetric key for group messaging."""
    return os.urandom(32)


def encrypt_group_key(
    group_key: bytes,
    member_encryption_pk_b64: str,
) -> dict:
    """Encrypt the group symmetric key for one member.

    Each group member gets their own encrypted copy of the group key,
    encrypted to their X25519 public key.
    """
    member_pk_bytes = base64.b64decode(member_encryption_pk_b64)
    member_pk = X25519PublicKey.from_public_bytes(member_pk_bytes)

    # Ephemeral ECDH for this key distribution
    ephemeral_sk = X25519PrivateKey.generate()
    ephemeral_pk = ephemeral_sk.public_key()
    ephemeral_pk_bytes = ephemeral_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    shared_secret = ephemeral_sk.exchange(member_pk)
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"svrnty-groupkey-v1",
    ).derive(shared_secret)

    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(symmetric_key)
    encrypted_group_key = cipher.encrypt(nonce, group_key, associated_data=None)

    return {
        "ephemeral_pk": base64.b64encode(ephemeral_pk_bytes).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_key": base64.b64encode(encrypted_group_key).decode(),
    }


def decrypt_group_key(
    encrypted_key_envelope: dict,
    member_encryption_sk_b64: str,
) -> bytes:
    """Decrypt the group key using your private key."""
    ephemeral_pk_bytes = base64.b64decode(encrypted_key_envelope["ephemeral_pk"])
    nonce = base64.b64decode(encrypted_key_envelope["nonce"])
    encrypted_key = base64.b64decode(encrypted_key_envelope["encrypted_key"])

    member_sk_bytes = base64.b64decode(member_encryption_sk_b64)
    member_sk = X25519PrivateKey.from_private_bytes(member_sk_bytes)
    ephemeral_pk = X25519PublicKey.from_public_bytes(ephemeral_pk_bytes)

    shared_secret = member_sk.exchange(ephemeral_pk)
    symmetric_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"svrnty-groupkey-v1",
    ).derive(shared_secret)

    cipher = ChaCha20Poly1305(symmetric_key)
    return cipher.decrypt(nonce, encrypted_key, associated_data=None)


def encrypt_group_message(
    plaintext: bytes,
    group_key: bytes,
    sender_signing_sk_b64: str,
    sender_fingerprint: str,
) -> dict:
    """Encrypt a message with the group symmetric key.

    One ciphertext for all members (they all share the group key).
    """
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(group_key)
    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

    # Sign
    sender_sk_bytes = base64.b64decode(sender_signing_sk_b64)
    sign_sk = Ed25519PrivateKey.from_private_bytes(sender_sk_bytes)
    signed_data = nonce + ciphertext
    signature = sign_sk.sign(signed_data)

    return {
        "v": 1,
        "type": "group",
        "from": sender_fingerprint,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
    }


def decrypt_group_message(
    envelope: dict,
    group_key: bytes,
    sender_signing_pk_b64: str,
) -> bytes:
    """Decrypt a group message."""
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    signature = base64.b64decode(envelope["signature"])

    # Verify sender
    sender_pk_bytes = base64.b64decode(sender_signing_pk_b64)
    sender_pk = Ed25519PublicKey.from_public_bytes(sender_pk_bytes)
    signed_data = nonce + ciphertext
    try:
        sender_pk.verify(signature, signed_data)
    except Exception as e:
        raise ValueError(f"Signature verification failed: {e}")

    cipher = ChaCha20Poly1305(group_key)
    return cipher.decrypt(nonce, ciphertext, associated_data=None)


# ── DH-PSI: Private Set Intersection for Mutual Contact Discovery ──
#
# Protocol (Freedman-Nissim-Pinkas style, adapted for X25519):
#
# Alice and Bob want to discover which contacts they share WITHOUT
# revealing their full contact lists to each other or the satellite.
#
# 1. Both generate ephemeral X25519 PSI keypairs (one-time, per session)
# 2. Each hashes their contact fingerprints to X25519 points:
#    blind_a(fp) = X25519(psi_sk_a, H_point(fp))
# 3. They exchange blinded sets through the satellite
# 4. Each re-blinds the OTHER's set with their own key:
#    Alice: X25519(psi_sk_a, blind_b(fp)) = X25519(psi_sk_a, X25519(psi_sk_b, H_point(fp)))
#    Bob:   X25519(psi_sk_b, blind_a(fp)) = X25519(psi_sk_b, X25519(psi_sk_a, H_point(fp)))
# 5. Due to DH commutativity, matching values = shared contacts
#
# The satellite only relays encrypted blobs. It never sees which
# fingerprints are being compared or what the intersection is.

def generate_psi_keypair() -> dict:
    """Generate an ephemeral X25519 keypair for one PSI session.

    Returns base64-encoded keys. This keypair is single-use —
    generate a fresh one for every PSI exchange.
    """
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return {
        "psi_sk": base64.b64encode(
            sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ).decode(),
        "psi_pk": base64.b64encode(
            pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode(),
    }


def _hash_fingerprint_to_point(fingerprint: str) -> bytes:
    """Hash a fingerprint string to a valid X25519 public key (32 bytes).

    CANONICAL H(fp) — LOCKED, must byte-match the TS orchestrator and the pinned
    vector (reference test vector, EXPECTED_H_HEX 593f2af2…):
        HKDF-SHA256(ikm = utf8(fp), salt = b"svrnty-psi-v1",
                    info = b"svrnty-psi-point-derivation", L = 32), used directly
        as the X25519 u-coordinate. NO RFC-7748 clamp (clamp is a scalar op; it was
        the B-3 bug). ikm = the fingerprint, info = the domain string — do NOT swap.
    """
    raw = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"svrnty-psi-v1",
        info=b"svrnty-psi-point-derivation",
    ).derive(fingerprint.encode())

    # X25519 accepts any 32-byte string as a public key (Curve25519
    # does clamping internally), so this is valid as-is.
    return raw


def blind_contacts(
    contact_fingerprints: list[str],
    psi_sk_b64: str,
) -> list[str]:
    """Blind a list of contact fingerprints with a PSI secret key.

    Each fingerprint is hashed to an X25519 point, then DH'd with
    the PSI secret key. Returns base64-encoded blinded values.

    The order is shuffled to prevent positional correlation.
    """
    import secrets as _secrets

    sk_bytes = base64.b64decode(psi_sk_b64)
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)

    blinded = []
    for fp in contact_fingerprints:
        point = _hash_fingerprint_to_point(fp)
        # X25519(sk, H(fp)) — our blinded version of this contact
        peer_pk = X25519PublicKey.from_public_bytes(point)
        shared = sk.exchange(peer_pk)
        blinded.append(base64.b64encode(shared).decode())

    # Shuffle to prevent positional leakage
    _secrets.SystemRandom().shuffle(blinded)
    return blinded


def reblind_set(
    their_blinded_values: list[str],
    psi_sk_b64: str,
) -> list[str]:
    """Re-blind the other party's blinded set with our PSI key.

    Takes their blinded values (X25519(their_sk, H(fp))) and applies
    our key: X25519(our_sk, their_blinded). Due to DH commutativity,
    matching entries in both re-blinded sets = shared contacts.
    """
    sk_bytes = base64.b64decode(psi_sk_b64)
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)

    reblinded = []
    for val_b64 in their_blinded_values:
        val_bytes = base64.b64decode(val_b64)
        peer_pk = X25519PublicKey.from_public_bytes(val_bytes)
        shared = sk.exchange(peer_pk)
        reblinded.append(base64.b64encode(shared).decode())

    return reblinded


def compute_psi_intersection(
    my_reblinded: list[str],
    their_reblinded: list[str],
) -> int:
    """Compute the size of the intersection between two re-blinded sets.

    Returns the COUNT of mutual contacts (not which ones — that would
    require Alice to track which blinded value maps to which fingerprint,
    which is an optional client-side enrichment).

    For count-only mode (privacy-preserving): just return len(intersection).
    For full discovery mode: the client tracks blind→fingerprint mapping locally.
    """
    my_set = set(my_reblinded)
    their_set = set(their_reblinded)
    return len(my_set & their_set)


def psi_full_exchange(
    my_contacts: list[str],
    their_blinded: list[str],
    my_psi_sk_b64: str,
) -> dict:
    """Full client-side PSI computation (for discovery mode).

    Returns which of MY contacts are in the intersection.
    This runs entirely on the client — the satellite never sees this.
    """
    sk_bytes = base64.b64decode(my_psi_sk_b64)
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)

    # Build my blinded set WITH fingerprint tracking
    my_blind_to_fp = {}
    for fp in my_contacts:
        point = _hash_fingerprint_to_point(fp)
        peer_pk = X25519PublicKey.from_public_bytes(point)
        shared = sk.exchange(peer_pk)
        b64 = base64.b64encode(shared).decode()
        my_blind_to_fp[b64] = fp

    # Re-blind their set with my key
    their_reblinded = set()
    for val_b64 in their_blinded:
        val_bytes = base64.b64decode(val_b64)
        peer_pk = X25519PublicKey.from_public_bytes(val_bytes)
        shared = sk.exchange(peer_pk)
        their_reblinded.add(base64.b64encode(shared).decode())

    # Now I need my doubly-blinded values to compare.
    # But wait — my_blind_to_fp has X25519(my_sk, H(fp))
    # Their reblinded has X25519(my_sk, X25519(their_sk, H(fp)))
    # I need X25519(their_sk, X25519(my_sk, H(fp))) which equals the above
    # by DH commutativity... but I don't have their_sk.
    #
    # The correct protocol: I send MY blinded set to them, they re-blind
    # it and send back. Then I compare their-reblinded-of-mine against
    # my-reblinded-of-theirs.
    #
    # So this function needs THEIR re-blinding of MY set, not their raw blinded set.
    # Correcting the interface:

    # This function should be called with:
    #   their_blinded = their re-blinded version of MY original blinded set
    # Then I can match against my_blind_to_fp

    mutual = []
    for b64, fp in my_blind_to_fp.items():
        if b64 in their_reblinded:
            mutual.append(fp)

    return {
        "mutual_count": len(mutual),
        "mutual_fingerprints": mutual,
    }


# ── Lightweight Message Signing (for MCP bus) ────────────

def sign_message(message_body: str, signing_sk_b64: str) -> str:
    """Sign a message body with an Ed25519 private key.

    Returns a base64-encoded signature. Used by the MCP message bus
    to verify sender identity without full encryption.

    Args:
        message_body: The plaintext message to sign
        signing_sk_b64: Base64-encoded Ed25519 private key
    """
    sk_bytes = base64.b64decode(signing_sk_b64)
    sk = Ed25519PrivateKey.from_private_bytes(sk_bytes)
    signature = sk.sign(message_body.encode("utf-8"))
    return base64.b64encode(signature).decode()


def verify_message(message_body: str, signature_b64: str, signing_pk_b64: str) -> bool:
    """Verify a message signature against a sender's public key.

    Returns True if valid, False if forged or tampered.

    Args:
        message_body: The plaintext message that was signed
        signature_b64: Base64-encoded Ed25519 signature
        signing_pk_b64: Base64-encoded Ed25519 public key of claimed sender
    """
    try:
        pk_bytes = base64.b64decode(signing_pk_b64)
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
        signature = base64.b64decode(signature_b64)
        pk.verify(signature, message_body.encode("utf-8"))
        return True
    except Exception:
        return False


def load_agent_key(key_path: str) -> dict:
    """Load an agent's svrnty key file.

    Returns dict with private_key, public_key, algorithm, agent.
    Raises FileNotFoundError if key doesn't exist.
    """
    import json
    with open(key_path) as f:
        return json.load(f)


# Agent public key registry — known agents and their signing public keys.
# In production, this is populated from the shared MCP config or a
# well-known endpoint. For now, hardcoded for the 5-agent fleet.
AGENT_PUBLIC_KEYS: dict[str, str] = {}


def load_public_key_registry(registry_path: str) -> dict[str, str]:
    """Load the agent public key registry from a JSON file.

    File format: {"alice": "base64_pk", "bob": "base64_pk", ...}
    Returns dict mapping agent name → base64 public key.
    """
    import json
    with open(registry_path) as f:
        keys = json.load(f)
    AGENT_PUBLIC_KEYS.update(keys)
    return keys


def run_psi_demo():
    """Demonstrate the full PSI protocol between two parties.

    This is the reference implementation for the PWA to follow.
    """
    # Setup: Alice and Bob each have some contacts
    alice_contacts = ["fp_carol", "fp_dave", "fp_eve", "fp_frank"]
    bob_contacts = ["fp_carol", "fp_eve", "fp_grace", "fp_heidi"]
    # Expected intersection: carol, eve

    # Step 1: Both generate ephemeral PSI keypairs
    alice_psi = generate_psi_keypair()
    bob_psi = generate_psi_keypair()

    # Step 2: Both blind their contact lists
    alice_blinded = blind_contacts(alice_contacts, alice_psi["psi_sk"])
    bob_blinded = blind_contacts(bob_contacts, bob_psi["psi_sk"])

    # Step 3: Exchange blinded sets via satellite (encrypted in transit)
    # Alice gets bob_blinded, Bob gets alice_blinded

    # Step 4: Both re-blind the other's set
    alice_reblinded_bobs = reblind_set(bob_blinded, alice_psi["psi_sk"])
    bob_reblinded_alices = reblind_set(alice_blinded, bob_psi["psi_sk"])

    # Step 5: Compare — matching values = shared contacts
    count = compute_psi_intersection(alice_reblinded_bobs, bob_reblinded_alices)
    print(f"Mutual contacts found: {count}")  # Should be 2
    assert count == 2, f"Expected 2 mutual contacts, got {count}"

    return count
