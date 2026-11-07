"""
LMS / LM-OTS signing (RFC 8554), SHA-256, n = m = 32.

This is the *stateful* half of LMS. Every leaf (one-time key) q may sign
exactly one message. Re-using q leaks enough of the one-time private key
to forge signatures, so the signer persists the next unused q to disk
BEFORE it releases a signature (see LmsSigner.sign).

Private-key derivation follows RFC 8554 Appendix A (pseudo-random from a
32-byte SEED), so a key is fully described by (types, I, SEED, next q).
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass

D_PBLC = 0x8080
D_MESG = 0x8181
D_LEAF = 0x8282
D_INTR = 0x8383

LMS_TYPES = {0x05: 5, 0x06: 10}          # LMS_SHA256_M32_H5 / _H10 -> h
OTS_TYPES = {0x03: (4, 67, 4),            # LMOTS_SHA256_N32_W4 -> (w, p, ls)
             0x04: (8, 34, 0)}            # LMOTS_SHA256_N32_W8
N = 32


def _H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def coef(S: bytes, i: int, w: int) -> int:
    return ((1 << w) - 1) & (S[(i * w) // 8] >> (8 - (w * (i % (8 // w)) + w)))


def checksum(Q: bytes, w: int, ls: int) -> int:
    total = 0
    for i in range((N * 8) // w):
        total += (1 << w) - 1 - coef(Q, i, w)
    return (total << ls) & 0xFFFF


@dataclass
class LmsKey:
    lms_type: int
    ots_type: int
    I: bytes
    seed: bytes
    next_q: int = 0

    @property
    def h(self) -> int:
        return LMS_TYPES[self.lms_type]

    @property
    def ots(self):
        return OTS_TYPES[self.ots_type]

    # --- one-time keys -------------------------------------------------
    def _x(self, q: int, i: int) -> bytes:
        # RFC 8554 Appendix A: x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)
        return _H(self.I, u32(q), u16(i), u8(0xFF), self.seed)

    def _chain(self, q: int, i: int, start: int, steps: int, tmp: bytes) -> bytes:
        for j in range(start, start + steps):
            tmp = _H(self.I, u32(q), u16(i), u8(j), tmp)
        return tmp

    def ots_public(self, q: int) -> bytes:
        w, p, _ = self.ots
        top = (1 << w) - 1
        ys = [self._chain(q, i, 0, top, self._x(q, i)) for i in range(p)]
        return _H(self.I, u32(q), u16(D_PBLC), *ys)

    # --- Merkle tree ---------------------------------------------------
    def _tree(self) -> dict[int, bytes]:
        if hasattr(self, "_cache"):
            return self._cache  # type: ignore[attr-defined]
        leaves = 1 << self.h
        T: dict[int, bytes] = {}
        for q in range(leaves):
            r = leaves + q
            T[r] = _H(self.I, u32(r), u16(D_LEAF), self.ots_public(q))
        for r in range(leaves - 1, 0, -1):
            T[r] = _H(self.I, u32(r), u16(D_INTR), T[2 * r], T[2 * r + 1])
        self._cache = T  # type: ignore[attr-defined]
        return T

    def public_key(self) -> bytes:
        return u32(self.lms_type) + u32(self.ots_type) + self.I + self._tree()[1]

    def remaining(self) -> int:
        return (1 << self.h) - self.next_q

    def sign_with_q(self, msg: bytes, q: int, C: bytes | None = None) -> bytes:
        w, p, ls = self.ots
        if C is None:
            C = os.urandom(N)
        Q = _H(self.I, u32(q), u16(D_MESG), C, msg)
        Qc = Q + u16(checksum(Q, w, ls))
        y = b"".join(self._chain(q, i, 0, coef(Qc, i, w), self._x(q, i)) for i in range(p))
        ots_sig = u32(self.ots_type) + C + y
        T = self._tree()
        node = (1 << self.h) + q
        path = []
        while node > 1:
            path.append(T[node ^ 1])
            node >>= 1
        return u32(q) + ots_sig + u32(self.lms_type) + b"".join(path)

    # --- persistence -----------------------------------------------------
    def to_json(self) -> dict:
        return {"lms_type": self.lms_type, "ots_type": self.ots_type,
                "I": self.I.hex(), "seed": self.seed.hex(), "next_q": self.next_q}

    @classmethod
    def from_json(cls, d: dict) -> "LmsKey":
        return cls(d["lms_type"], d["ots_type"], bytes.fromhex(d["I"]),
                   bytes.fromhex(d["seed"]), d["next_q"])


def generate(lms_type: int = 0x05, ots_type: int = 0x03) -> LmsKey:
    if lms_type not in LMS_TYPES or ots_type not in OTS_TYPES:
        raise ValueError("unsupported LMS/LM-OTS type")
    return LmsKey(lms_type, ots_type, os.urandom(16), os.urandom(32), 0)


class LmsSigner:
    """File-backed stateful signer. The state file is updated (fsync'd)
    before a signature is returned, so a crash can waste a leaf but can
    never re-use one."""

    def __init__(self, path: str):
        self.path = path
        with open(path) as f:
            self.key = LmsKey.from_json(json.load(f))

    def _persist(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.key.to_json(), f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def sign(self, msg: bytes) -> bytes:
        q = self.key.next_q
        if q >= (1 << self.key.h):
            raise RuntimeError("LMS key exhausted: all one-time keys used")
        self.key.next_q = q + 1
        self._persist()                       # reserve the leaf first
        return self.key.sign_with_q(msg, q)


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Independent Python verifier (mirrors lib/src/lms.c)."""
    lms_type, ots_type = struct.unpack(">II", pub[:8])
    I, T1 = pub[8:24], pub[24:56]
    h = LMS_TYPES[lms_type]
    w, p, ls = OTS_TYPES[ots_type]
    q = struct.unpack(">I", sig[:4])[0]
    if struct.unpack(">I", sig[4:8])[0] != ots_type or q >= (1 << h):
        return False
    C = sig[8:40]
    y = [sig[40 + i * N:40 + (i + 1) * N] for i in range(p)]
    off = 40 + p * N
    if struct.unpack(">I", sig[off:off + 4])[0] != lms_type:
        return False
    path = [sig[off + 4 + i * N: off + 4 + (i + 1) * N] for i in range(h)]
    Q = _H(I, u32(q), u16(D_MESG), C, msg)
    Qc = Q + u16(checksum(Q, w, ls))
    z = []
    for i in range(p):
        tmp = y[i]
        for j in range(coef(Qc, i, w), (1 << w) - 1):
            tmp = _H(I, u32(q), u16(i), u8(j), tmp)
        z.append(tmp)
    Kc = _H(I, u32(q), u16(D_PBLC), *z)
    node = (1 << h) + q
    tmp = _H(I, u32(node), u16(D_LEAF), Kc)
    i = 0
    while node > 1:
        if node & 1:
            tmp = _H(I, u32(node >> 1), u16(D_INTR), path[i], tmp)
        else:
            tmp = _H(I, u32(node >> 1), u16(D_INTR), tmp, path[i])
        node >>= 1
        i += 1
    return tmp == T1
