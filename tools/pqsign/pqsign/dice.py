"""
Host-side model of the device's DICE chain (mirrors lib/src/dice.c) and
the alias-key derivation (mirrors ports/host_openssl.c key_from_seed).
The attestation verifier uses this to compute what an honest device with
known-good images must report.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

CDI_LABEL = b"PQB-CDI-v1"
ALIAS_LABEL = b"PQB-ALIAS-ECDSA-P384"
P384_N = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf"
             "581a0db248b0a77aecec196accc52973", 16)


def extend_cdi(cdi: bytes, measurement: bytes) -> bytes:
    return hmac.new(cdi, CDI_LABEL + measurement, "sha384").digest()


def extend_pcr(pcr: bytes, measurement: bytes) -> bytes:
    return hashlib.sha384(pcr + measurement).digest()


def replay_pcr(measurements: list[bytes]) -> bytes:
    pcr = bytes(48)
    for m in measurements:
        pcr = extend_pcr(pcr, m)
    return pcr


def final_cdi(uds: bytes, measurements: list[bytes]) -> bytes:
    cdi = uds
    for m in measurements:
        cdi = extend_cdi(cdi, m)
    return cdi


def alias_private(cdi: bytes) -> ec.EllipticCurvePrivateKey:
    seed = hmac.new(cdi, ALIAS_LABEL, "sha384").digest()
    d = int.from_bytes(seed, "big") % (P384_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP384R1())


def alias_public_bytes(cdi: bytes) -> bytes:
    return alias_private(cdi).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
