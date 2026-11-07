#!/usr/bin/env python3
"""
Generate test vectors for the C tests, fuzzer, fault harness and benchmark.

Reference implementations used to produce expected values:
  hashes   -> Python hashlib (OpenSSL)
  ML-DSA   -> pyca/cryptography (OpenSSL 3.5+/4.x ML-DSA-87)  <- independent
  ECDSA    -> pyca/cryptography                                <- independent
  LMS      -> tools/pqsign/pqsign/lms.py (our own Python implementation)
  DICE     -> tools/pqsign/pqsign/dice.py
"""
import hashlib
import hmac
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools", "pqsign"))

from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: E402

from pqsign import dice, image, keys, lms  # noqa: E402


def w(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main(out):
    if os.path.exists(out):
        shutil.rmtree(out)
    os.makedirs(os.path.join(out, "corpus"))
    rnd = bytes((i * 131 + 7) & 0xFF for i in range(3000))

    # ---- hash vectors: "alg msg_hex digest_hex" per line ----
    lines = []
    for n in (0, 1, 3, 55, 56, 64, 111, 112, 128, 135, 136, 168, 1000, 3000):
        m = rnd[:n]
        lines.append(f"sha256 {m.hex() or '-'} {hashlib.sha256(m).hexdigest()}")
        lines.append(f"sha384 {m.hex() or '-'} {hashlib.sha384(m).hexdigest()}")
        lines.append(f"sha3_256 {m.hex() or '-'} {hashlib.sha3_256(m).hexdigest()}")
        lines.append(f"sha3_384 {m.hex() or '-'} {hashlib.sha3_384(m).hexdigest()}")
        lines.append(f"shake256 {m.hex() or '-'} {hashlib.shake_256(m).hexdigest(200)}")
        key = rnd[n % 7: n % 7 + (n % 150)]
        lines.append(f"hmac384:{key.hex() or '-'} {m.hex() or '-'} "
                     f"{hmac.new(key, m, 'sha384').hexdigest()}")
    with open(os.path.join(out, "hash_vectors.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")

    # ---- ML-DSA-87 vectors (signed by OpenSSL, verified by our C) ----
    sk = mldsa.MLDSA87PrivateKey.from_seed_bytes(bytes(range(32)))
    w(os.path.join(out, "mldsa.pk"), sk.public_key().public_bytes_raw())
    msgs = [b"", b"abc", rnd[:256], rnd]
    ctxs = [b"", b"pqboot-image-v1", b"x" * 255, b"ctx"]
    with open(os.path.join(out, "mldsa_count"), "w") as f:
        f.write(str(len(msgs)))
    for i, (m, c) in enumerate(zip(msgs, ctxs)):
        w(os.path.join(out, f"mldsa_{i}.msg"), m)
        w(os.path.join(out, f"mldsa_{i}.ctx"), c)
        w(os.path.join(out, f"mldsa_{i}.sig"), sk.sign(m, c if c else None))

    # ---- LMS vectors (our Python signer; C verifier is independent code) ----
    for name, lt, ot in (("h5w4", 0x05, 0x03), ("h5w8", 0x05, 0x04)):
        k = lms.LmsKey(lt, ot, bytes(range(16)), bytes(range(32, 64)), 0)
        msg = b"pqboot lms vector " + name.encode()
        sig = k.sign_with_q(msg, 7, C=bytes(32))
        assert lms.verify(k.public_key(), msg, sig)
        w(os.path.join(out, f"lms_{name}.pk"), k.public_key())
        w(os.path.join(out, f"lms_{name}.msg"), msg)
        w(os.path.join(out, f"lms_{name}.sig"), sig)

    # ---- key set + signed images ----
    kdir = os.path.join(out, "keys")
    keys.generate(kdir)
    ks = keys.KeySet(kdir)
    payloads = {
        "bl2": (1, 2, 0x0E01B000, b"BL2 trusted boot firmware " * 200),
        "bl31": (2, 3, 0x0E060000, b"BL31 EL3 runtime " * 400),
        "bl32": (3, 1, 0x0E100000, b"OP-TEE OS " * 800),
        "bl33": (4, 5, 0x60000000, b"U-Boot " * 1500),
    }
    imgs = {}
    for name, (t, ver, addr, pl) in payloads.items():
        imgs[name] = image.build(pl, t, ver, addr, addr, ks, image.PQ_MLDSA87)
        w(os.path.join(out, f"{name}.pqb"), imgs[name])
    w(os.path.join(out, "bl31_trailer.bin"), image.to_trailer(imgs["bl31"]))
    lms_img = image.build(b"LMS-signed test payload" * 50, 0xFF, 1, 0, 0, ks, image.PQ_LMS)
    w(os.path.join(out, "test_lms.pqb"), lms_img)

    with open(os.path.join(out, "anchor_mldsa.hex"), "w") as f:
        f.write(ks.key_hash(image.PQ_MLDSA87).hex())
    with open(os.path.join(out, "anchor_lms.hex"), "w") as f:
        f.write(ks.key_hash(image.PQ_LMS).hex())

    # ---- DICE expected values for UDS = 0xA5 * 48 and the 4-image chain ----
    uds = bytes([0xA5]) * 48
    ms = [image.measurement(imgs[n]) for n in ("bl2", "bl31", "bl32", "bl33")]
    cdi = dice.final_cdi(uds, ms)
    with open(os.path.join(out, "dice_expected.txt"), "w") as f:
        f.write(f"pcr {dice.replay_pcr(ms).hex()}\n")
        f.write(f"alias {dice.alias_public_bytes(cdi).hex()}\n")

    # ---- fuzz corpus ----
    for name, img in list(imgs.items())[:2]:
        w(os.path.join(out, "corpus", f"{name}.pqb"), img)
    w(os.path.join(out, "corpus", "lms.pqb"), lms_img)
    w(os.path.join(out, "corpus", "hdr_only.bin"), imgs["bl2"][:256])
    w(os.path.join(out, "corpus", "trailer.bin"), image.to_trailer(imgs["bl2"]))
    print(f"vectors written to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "build/vectors")
