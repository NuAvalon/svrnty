#!/usr/bin/env python3
"""Independent reference for the PSI per-epoch element (src/lib/trust/psi-epoch-element.ts).

Standard library only: HKDF-SHA256 (RFC 5869) is written out here and shares no code with the TypeScript, so the
known-answer vectors pinned in psi-epoch-element.test.ts come from a second implementation.

    element = HKDF-SHA256(ikm  = LP('svrnty/psi-elem/v2') || LP(fp) || LP(layer) || u64be(epoch) || secret,
                          salt = 'svrnty-psi-v2', info = 'svrnty-psi-elem-point-v2', L = 32)
    LP(x)   = uint32_be(len(x)) || x      (src/lib/crypto/lp-tlv.ts)

Run: python3 scripts/psi-epoch-element-kat.py        (prints the vectors as JSON)
"""
import hashlib
import hmac
import json
import struct


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


def element(fp: str, layer: str, epoch: int, secret: bytes) -> bytes:
    ikm = lp(b"svrnty/psi-elem/v2") + lp(fp.encode()) + lp(layer.encode()) + struct.pack(">Q", epoch) + secret
    return hkdf_sha256(ikm, b"svrnty-psi-v2", b"svrnty-psi-elem-point-v2", 32)


FP_A = hashlib.sha256(b"kat-fp-A").hexdigest()
FP_B = hashlib.sha256(b"kat-fp-B").hexdigest()
S1 = bytes(range(32))
S2 = bytes(range(32, 64))

VECTORS = [
    ("know e=0 S1", FP_A, "know", 0, S1),
    ("trust e=0 S1", FP_A, "trust", 0, S1),
    ("know e=1 S1", FP_A, "know", 1, S1),
    ("know e=2^40+7 S2", FP_A, "know", 2**40 + 7, S2),
    ("know e=0 S1 other fp", FP_B, "know", 0, S1),
]

# Framing vectors: LP counts BYTES (uint32 big-endian), so a u16 or a character-count implementation fails on these.
FRAMING = [
    ("empty", b""),
    ("one byte 0xab", b"\xab"),
    ("non-ascii string é€ (2 chars, 5 bytes)", "é€".encode()),
    ("256 bytes of 0xab (prefix 00000100)", b"\xab" * 256),
    ("65536 bytes of 0x01 (prefix 00010000, past any u16)", b"\x01" * 65536),
]

if __name__ == "__main__":
    out = {"fpA": FP_A, "fpB": FP_B, "S1": S1.hex(), "S2": S2.hex(),
           "framing": [{"name": n, "len": len(b), "prefix": lp(b)[:4].hex(), "sha256_of_lp": hashlib.sha256(lp(b)).hexdigest()}
                       for n, b in FRAMING],
           "vectors": [{"name": n, "fp": f, "layer": l, "epoch": e, "secret": s.hex(), "element": element(f, l, e, s).hex()}
                       for n, f, l, e, s in VECTORS]}
    print(json.dumps(out, indent=2))
