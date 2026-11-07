"""
Attestation quote verifier (the "relying party" side).

Checks, in order:
  1. structure and version
  2. the nonce is the one we sent (freshness, no replay)
  3. ECDSA-P384 signature by the alias key in the quote
  4. the alias key is the one we enrolled for this device (pinning)
  5. replaying the event log reproduces the reported PCR
  6. every event matches a golden measurement (and minimum version)
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed, encode_dss_signature)

from .dice import replay_pcr

HDR = 92
EVT = 56


@dataclass
class Event:
    image_type: int
    security_version: int
    measurement: bytes


@dataclass
class Quote:
    nonce: bytes
    pcr: bytes
    events: list[Event]
    alias_pub: bytes
    signature: bytes
    tbs: bytes


@dataclass
class Result:
    ok: bool
    reasons: list[str] = field(default_factory=list)


def parse(q: bytes) -> Quote:
    if len(q) < HDR or q[:4] != b"PQBQ":
        raise ValueError("not a PQBQ quote")
    ver, = struct.unpack("<I", q[4:8])
    if ver != 1:
        raise ValueError(f"unsupported quote version {ver}")
    nonce, pcr = q[8:40], q[40:88]
    count, = struct.unpack("<I", q[88:92])
    if count > 8:
        raise ValueError("too many events")
    need = HDR + count * EVT + 97 + 96
    if len(q) != need:
        raise ValueError(f"quote length {len(q)} != expected {need}")
    events = []
    off = HDR
    for _ in range(count):
        t, v = struct.unpack("<II", q[off:off + 8])
        events.append(Event(t, v, q[off + 8:off + 56]))
        off += EVT
    alias = q[off:off + 97]
    sig = q[off + 97:off + 193]
    return Quote(nonce, pcr, events, alias, sig, q[:off + 97])


def verify(quote: bytes, nonce: bytes, golden: dict[int, bytes],
           enrolled_alias: bytes | None = None,
           min_versions: dict[int, int] | None = None) -> Result:
    r = Result(ok=True)

    def fail(msg: str) -> None:
        r.ok = False
        r.reasons.append(msg)

    try:
        q = parse(quote)
    except ValueError as e:
        return Result(False, [str(e)])

    if q.nonce != nonce:
        fail("nonce mismatch (stale or replayed quote)")

    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), q.alias_pub)
        der = encode_dss_signature(int.from_bytes(q.signature[:48], "big"),
                                   int.from_bytes(q.signature[48:], "big"))
        pub.verify(der, hashlib.sha384(q.tbs).digest(), ec.ECDSA(Prehashed(hashes.SHA384())))
    except (InvalidSignature, ValueError):
        fail("quote signature invalid")

    if enrolled_alias is not None and q.alias_pub != enrolled_alias:
        fail("alias key differs from enrolment: device firmware or UDS changed")

    if replay_pcr([e.measurement for e in q.events]) != q.pcr:
        fail("event log does not reproduce PCR (log tampered)")

    for e in q.events:
        want = golden.get(e.image_type)
        if want is None:
            fail(f"no golden value for image type {e.image_type}")
        elif want != e.measurement:
            fail(f"image type {e.image_type}: measurement not in golden set")
        if min_versions and e.security_version < min_versions.get(e.image_type, 0):
            fail(f"image type {e.image_type}: version {e.security_version} below policy")
    return r
