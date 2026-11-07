"""
Key set: one ECDSA-P384 key plus one post-quantum key (ML-DSA-87 and/or
LMS). The device trusts SHA-384(classic_pk || pq_pk), the "key manifest
hash", which is what would be burned into OTP / eFUSE.

Directory layout produced by `pqsign keygen`:
    ecdsa_p384.pem     classic private key (PEM, unencrypted - demo only!)
    mldsa87.seed       32-byte ML-DSA-87 seed (FIPS 204 xi)
    lms.json           LMS private state (types, I, SEED, next q)
"""
from __future__ import annotations

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed, decode_dss_signature)

from . import lms as lmsmod
from .image import MLDSA_CTX, PQ_LMS, PQ_MLDSA87


class KeySet:
    def __init__(self, path: str):
        self.path = path
        with open(os.path.join(path, "ecdsa_p384.pem"), "rb") as f:
            self.ecdsa = serialization.load_pem_private_key(f.read(), None)
        seed_path = os.path.join(path, "mldsa87.seed")
        self.mldsa = None
        if os.path.exists(seed_path):
            with open(seed_path, "rb") as f:
                self.mldsa = mldsa.MLDSA87PrivateKey.from_seed_bytes(f.read())
        lms_path = os.path.join(path, "lms.json")
        self.lms = lmsmod.LmsSigner(lms_path) if os.path.exists(lms_path) else None

    # ---- classical ----
    def classic_public(self) -> bytes:
        return self.ecdsa.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    def classic_sign(self, header: bytes) -> bytes:
        digest = hashlib.sha384(header).digest()
        der = self.ecdsa.sign(digest, ec.ECDSA(Prehashed(hashes.SHA384())))
        r, s = decode_dss_signature(der)
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")

    # ---- post-quantum ----
    def pq_public(self, alg: int) -> bytes:
        if alg == PQ_MLDSA87:
            if not self.mldsa:
                raise ValueError("no ML-DSA-87 key in key set")
            return self.mldsa.public_key().public_bytes_raw()
        if alg == PQ_LMS:
            if not self.lms:
                raise ValueError("no LMS key in key set")
            return self.lms.key.public_key()
        raise ValueError("unknown PQ algorithm")

    def pq_sig_len(self, alg: int) -> int:
        if alg == PQ_MLDSA87:
            return 4627
        k = self.lms.key
        w, p, ls = k.ots
        return 4 + (4 + 32 + p * 32) + 4 + k.h * 32

    def pq_sign(self, alg: int, header: bytes) -> bytes:
        if alg == PQ_MLDSA87:
            return self.mldsa.sign(header, MLDSA_CTX)
        return self.lms.sign(header)

    def key_hash(self, alg: int) -> bytes:
        return hashlib.sha384(self.classic_public() + self.pq_public(alg)).digest()


def generate(path: str, lms_type: int = 0x05, ots_type: int = 0x03) -> None:
    os.makedirs(path, exist_ok=True)
    k = ec.generate_private_key(ec.SECP384R1())
    with open(os.path.join(path, "ecdsa_p384.pem"), "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    with open(os.path.join(path, "mldsa87.seed"), "wb") as f:
        f.write(os.urandom(32))
    with open(os.path.join(path, "lms.json"), "w") as f:
        json.dump(lmsmod.generate(lms_type, ots_type).to_json(), f, indent=2)
    for name in ("ecdsa_p384.pem", "mldsa87.seed", "lms.json"):
        os.chmod(os.path.join(path, name), 0o600)
