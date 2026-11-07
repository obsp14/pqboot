"""
PQB1 image builder / parser. Layout documented in lib/include/pqb/image.h.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

HDR_SIZE = 256
MAGIC = b"PQB1"
MLDSA_CTX = b"pqboot-image-v1"

IMG_TYPES = {"bl2": 1, "bl31": 2, "bl32": 3, "bl33": 4, "kernel": 5, "test": 0xFF}
PQ_MLDSA87, PQ_LMS = 1, 2
CLASSIC_ECDSA_P384 = 1

# offsets
_FMT = "<4sHHIHHIQQI48sHHHH"          # up to offset 96
assert struct.calcsize(_FMT) == 96


@dataclass
class Header:
    image_type: int
    pq_alg: int
    security_version: int
    load_addr: int
    entry_point: int
    payload_size: int
    payload_digest: bytes
    classic_pk_len: int
    pq_pk_len: int
    classic_sig_len: int
    pq_sig_len: int
    classic_alg: int = CLASSIC_ECDSA_P384

    def pack(self) -> bytes:
        raw = struct.pack(_FMT, MAGIC, 1, HDR_SIZE, self.image_type, self.pq_alg,
                          self.classic_alg, self.security_version, self.load_addr,
                          self.entry_point, self.payload_size, self.payload_digest,
                          self.classic_pk_len, self.pq_pk_len, self.classic_sig_len,
                          self.pq_sig_len)
        return raw + bytes(HDR_SIZE - len(raw))

    @classmethod
    def unpack(cls, b: bytes) -> "Header":
        if len(b) < HDR_SIZE:
            raise ValueError("image shorter than header")
        f = struct.unpack(_FMT, b[:96])
        if f[0] != MAGIC:
            raise ValueError("bad magic")
        return cls(image_type=f[3], pq_alg=f[4], classic_alg=f[5],
                   security_version=f[6], load_addr=f[7], entry_point=f[8],
                   payload_size=f[9], payload_digest=f[10], classic_pk_len=f[11],
                   pq_pk_len=f[12], classic_sig_len=f[13], pq_sig_len=f[14])


def build(payload: bytes, image_type: int, version: int, load: int, entry: int,
          keyset, pq_alg: int) -> bytes:
    """keyset: pqsign.keys.KeySet. Returns the complete signed image."""
    cpk = keyset.classic_public()
    pqpk = keyset.pq_public(pq_alg)
    hdr = Header(image_type=image_type, pq_alg=pq_alg, security_version=version,
                 load_addr=load, entry_point=entry, payload_size=len(payload),
                 payload_digest=hashlib.sha384(payload).digest(),
                 classic_pk_len=len(cpk), pq_pk_len=len(pqpk),
                 classic_sig_len=96, pq_sig_len=keyset.pq_sig_len(pq_alg)).pack()
    csig = keyset.classic_sign(hdr)
    pqsig = keyset.pq_sign(pq_alg, hdr)
    assert len(pqsig) == keyset.pq_sig_len(pq_alg)
    return hdr + payload + cpk + pqpk + csig + pqsig


def split(img: bytes) -> dict:
    h = Header.unpack(img)
    off = HDR_SIZE
    parts = {"header": img[:HDR_SIZE], "hdr": h}
    for name, n in (("payload", h.payload_size), ("classic_pk", h.classic_pk_len),
                    ("pq_pk", h.pq_pk_len), ("classic_sig", h.classic_sig_len),
                    ("pq_sig", h.pq_sig_len)):
        parts[name] = img[off:off + n]
        off += n
    parts["trailing"] = len(img) - off
    return parts


def measurement(img: bytes) -> bytes:
    return hashlib.sha384(img[:HDR_SIZE]).digest()


TRAILER_MAGIC = b"PQBT"


def to_trailer(img: bytes) -> bytes:
    """Convert a PQB1 image into the TF-A friendly trailer form:
    payload || (header + keys + sigs) || "PQBT" || u32 blob_len."""
    p = split(img)
    blob = p["header"] + p["classic_pk"] + p["pq_pk"] + p["classic_sig"] + p["pq_sig"]
    return p["payload"] + blob + TRAILER_MAGIC + struct.pack("<I", len(blob))
