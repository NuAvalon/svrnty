#!/usr/bin/env python3
"""Independent reference for the PSI epoch note (src/lib/trust/psi-epoch-note.ts).

Standard library only: HKDF-SHA256 (RFC 5869) and the framing are written out here and share no code with the
TypeScript, so the known-answer vectors pinned in psi-epoch-note.test.ts come from a second implementation.

    header   = 0x45 0x01
    wire     = header || u64be(e) || E_know(32) || E_trust(32) || tag(32)               (106 bytes)
    K_mac    = HKDF-SHA256(S_pair, salt = 'svrnty-psi-epoch-auth-v1',
                           info = 'psi-epoch-mac' || LP(fp_sender) || LP(fp_receiver), 32)
    tag      = HMAC-SHA256(K_mac, header || fp_sender(32 raw) || fp_receiver(32 raw) || u64be(e)
                                  || 'know' || E_know || 'trust' || E_trust)
    LP(x)    = uint32_be(len(x)) || x      (src/lib/crypto/lp-tlv.ts)

Run: python3 scripts/psi-epoch-note-kat.py        (prints the vectors as JSON)
"""
import hashlib
import hmac
import json
import struct

HEADER = bytes([0x45, 0x01])


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def lp(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def k_mac(s_pair: bytes, fp_s: str, fp_r: str) -> bytes:
    info = b"psi-epoch-mac" + lp(fp_s.encode()) + lp(fp_r.encode())
    return hkdf_sha256(s_pair, b"svrnty-psi-epoch-auth-v1", info, 32)


def preimage(fp_s: str, fp_r: str, e: int, know: bytes, trust: bytes) -> bytes:
    return (HEADER + bytes.fromhex(fp_s) + bytes.fromhex(fp_r) + struct.pack(">Q", e)
            + b"know" + know + b"trust" + trust)


def note(s_pair: bytes, fp_s: str, fp_r: str, e: int, know: bytes, trust: bytes) -> dict:
    km = k_mac(s_pair, fp_s, fp_r)
    pre = preimage(fp_s, fp_r, e, know, trust)
    tag = hmac.new(km, pre, hashlib.sha256).digest()
    wire = HEADER + struct.pack(">Q", e) + know + trust + tag
    assert len(wire) == 106
    return {"k_mac": km.hex(), "preimage": pre.hex(), "tag": tag.hex(), "wire": wire.hex()}


FP_A = hashlib.sha256(b"kat-fp-A").hexdigest()
FP_B = hashlib.sha256(b"kat-fp-B").hexdigest()
S_PAIR = bytes(range(64, 96))
KNOW = bytes(range(0, 32))
TRUST = bytes(range(32, 64))
DECOY = bytes(range(200, 232))

CASES = [
    ("A to B, e=1, both real", FP_A, FP_B, 1, KNOW, TRUST),
    ("A to B, e=2^40+7, both real", FP_A, FP_B, 2**40 + 7, KNOW, TRUST),
    ("A to B, e=1, know real + trust decoy", FP_A, FP_B, 1, KNOW, DECOY),
    ("B to A, e=1, both real (the other direction)", FP_B, FP_A, 1, KNOW, TRUST),
]

if __name__ == "__main__":
    out = {"fpA": FP_A, "fpB": FP_B, "sPair": S_PAIR.hex(), "know": KNOW.hex(), "trust": TRUST.hex(), "decoy": DECOY.hex(),
           "cases": [dict(name=n, fpSender=s, fpReceiver=r, epoch=e, knowField=k.hex(), trustField=t.hex(), **note(S_PAIR, s, r, e, k, t))
                     for n, s, r, e, k, t in CASES]}
    print(json.dumps(out, indent=2))
