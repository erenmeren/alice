#!/usr/bin/env python3
"""Independent known-answer check of the Alice backup container v2 (contract C7, R43 row 41).

It rebuilds the TestKnownAnswer file from the C7 text with pyca/cryptography and Python's json, sharing no code with
the Go package (in particular not Go's encoding/json), and compares its SHA-256 with testdata/kat-v2.json. Use it when
a change to format.go makes TestKnownAnswer fail, to decide whether the file bytes really changed (a format change
then needs Version 3) or only the Go reference did.

Run (not run by CI):
    python3 -m venv /tmp/katvenv && /tmp/katvenv/bin/pip install cryptography
    /tmp/katvenv/bin/python internal/backup/format/testdata/kat_check.py
It prints the file size, chunk count and SHA-256, and exits 0 when the hash equals kat-v2.json (tested with
cryptography 50.0.2).

Inputs, as TestKnownAnswer sets them:
- recipient private key R = 32 x 0x42, sender private key S = 32 x 0x43 (X25519);
- wrapped key record: version 2, kdf {8192, 1, 1}, salt 16 x 0x01, nonce 12 x 0x02, ciphertext 48 x 0x03 (the writer
  only copies it, so it need not open);
- randomness: rand.NewChaCha8([32]byte{seed}) read for 32 bytes (the ephemeral private key) then 4 bytes (the nonce
  prefix). For seed 7 those 36 bytes are CHACHA8_SEED7 below, taken once from Go (ChaCha8 is not reimplemented here);
- payload: Go's payload(n): rand.New(rand.NewPCG(1, n)), byte(Uint32()) per byte; PCG-DXSM is reimplemented below;
- meta: alice_version "1.0.0", created_at "2026-10-10T02:30:00Z", kind "auto"; chunk size 65,536.
"""

import base64
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CHACHA8_SEED7 = bytes.fromhex("0e42d4cae8864908e0b8c7520e360aa404427c9053d9a667be544c14e69fa48233703b71")
CHUNK = 65536
M64 = (1 << 64) - 1


def pcg_payload(n):
    """Go math/rand/v2: rand.New(rand.NewPCG(1, n)); byte(r.Uint32()) for each of n bytes."""
    mul = (2549297995355413924 << 64) | 4865540595714422341
    inc = (6364136223846793005 << 64) | 1442695040888963407
    state = (1 << 64) | n
    out = bytearray(n)
    for i in range(n):
        state = (state * mul + inc) & ((1 << 128) - 1)
        hi, lo = state >> 64, state & M64
        hi ^= hi >> 32
        hi = (hi * 0xDA942042E4DD58B5) & M64
        hi ^= hi >> 48
        hi = (hi * (lo | 1)) & M64
        out[i] = (hi >> 32) & 0xFF  # Uint32 is the high half of Uint64; byte() keeps its low 8 bits
    return bytes(out)


def pub(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64(b):
    return base64.b64encode(b).decode()


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "kat-v2.json")) as f:
        kat = json.load(f)
    if kat["seed"] != 7:
        sys.exit("kat_check.py carries the ChaCha8 bytes for seed 7 only")

    r = X25519PrivateKey.from_private_bytes(b"\x42" * 32)
    s = X25519PrivateKey.from_private_bytes(b"\x43" * 32)
    e = X25519PrivateKey.from_private_bytes(CHACHA8_SEED7[:32])
    prefix = CHACHA8_SEED7[32:36]
    r_pub, s_pub, e_pub = pub(r), pub(s), pub(e)

    ikm = e.exchange(X25519PublicKey.from_public_bytes(r_pub)) + s.exchange(X25519PublicKey.from_public_bytes(r_pub))
    reader = r.exchange(X25519PublicKey.from_public_bytes(e_pub)) + r.exchange(X25519PublicKey.from_public_bytes(s_pub))
    assert ikm == reader, "the reader-side Diffie-Hellman pair differs from the writer side"
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=e_pub + r_pub + s_pub, info=b"alice/backup/v2").derive(ikm)

    wrapped = {"version": 2, "public_key": b64(r_pub), "kdf": {"memory_kib": 8192, "time": 1, "threads": 1},
               "salt": b64(b"\x01" * 16), "nonce": b64(b"\x02" * 12), "ciphertext": b64(b"\x03" * 48),
               "sender_public_key": b64(s_pub)}
    header = {"alice_version": "1.0.0", "created_at": "2026-10-10T02:30:00Z", "kind": "auto",
              "recipient": b64(r_pub), "ephemeral": b64(e_pub), "wrapped_key": wrapped,
              "chunk_size": CHUNK, "nonce_prefix": b64(prefix)}
    hj = json.dumps(header, separators=(",", ":")).encode()  # key order as written; no spaces, as Go writes it
    out = bytearray(b"ALICEBK1" + struct.pack(">HI", 2, len(hj)) + hj)
    aad_base = hashlib.sha256(out).digest()

    plain = pcg_payload(kat["plain_size"])
    gcm = AESGCM(key)
    i = 0
    while True:
        final = len(plain) < CHUNK  # a payload ending on a boundary gets an empty final chunk
        n = min(CHUNK, len(plain))
        out += gcm.encrypt(prefix + struct.pack(">Q", i), plain[:n], aad_base + (b"\x01" if final else b"\x00"))
        plain = plain[n:]
        i += 1
        if final:
            break

    got = hashlib.sha256(out).hexdigest()
    print(f"{len(out)} bytes, {i} chunks, sha256 {got}")
    if got != kat["file_sha256"]:
        print(f"MISMATCH: kat-v2.json says {kat['file_sha256']}")
        return 1
    print("OK: equals kat-v2.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
