import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SIM = os.path.join(ROOT, "build", "pqboot-sim")

from pqsign import attest, dice, image, keys, lms  # noqa: E402


@pytest.fixture(scope="module")
def ks(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    keys.generate(str(d))
    return keys.KeySet(str(d))


# ---------------- LMS ----------------
def test_lms_sign_verify_all_params():
    for lt, ot in ((0x05, 0x03), (0x05, 0x04)):
        k = lms.generate(lt, ot)
        for q in (0, 1, 31):
            sig = k.sign_with_q(b"msg", q)
            assert lms.verify(k.public_key(), b"msg", sig)
            assert not lms.verify(k.public_key(), b"msh", sig)


def test_lms_state_never_reuses_leaf(tmp_path):
    p = tmp_path / "lms.json"
    p.write_text(json.dumps(lms.generate().to_json()))
    s = lms.LmsSigner(str(p))
    qs = [int.from_bytes(s.sign(b"x")[:4], "big") for _ in range(3)]
    assert qs == [0, 1, 2]
    # a new signer instance (e.g. after a crash) continues after the last leaf
    s2 = lms.LmsSigner(str(p))
    assert int.from_bytes(s2.sign(b"y")[:4], "big") == 3


def test_lms_exhaustion(tmp_path):
    k = lms.generate()
    k.next_q = 32
    p = tmp_path / "lms.json"
    p.write_text(json.dumps(k.to_json()))
    with pytest.raises(RuntimeError):
        lms.LmsSigner(str(p)).sign(b"x")


# ---------------- image ----------------
def test_image_roundtrip(ks):
    img = image.build(b"hello" * 100, 2, 7, 0x1000, 0x1004, ks, image.PQ_MLDSA87)
    p = image.split(img)
    h = p["hdr"]
    assert (h.image_type, h.security_version, h.load_addr, h.entry_point) == (2, 7, 0x1000, 0x1004)
    assert p["payload"] == b"hello" * 100
    assert p["trailing"] == 0
    assert len(p["pq_sig"]) == 4627 and len(p["classic_sig"]) == 96
    assert p["header"][96:] == bytes(160)


def test_image_lms(ks):
    img = image.build(b"x" * 10, 0xFF, 1, 0, 0, ks, image.PQ_LMS)
    p = image.split(img)
    assert lms.verify(p["pq_pk"], p["header"], p["pq_sig"])


# ---------------- DICE model ----------------
def test_dice_model_properties():
    uds = bytes(48)
    m = [bytes([i]) * 48 for i in range(3)]
    a = dice.final_cdi(uds, m)
    b = dice.final_cdi(uds, [m[0], m[1], bytes(48)])
    assert a != b                     # any changed image changes the CDI
    assert dice.alias_public_bytes(a) != dice.alias_public_bytes(b)
    assert dice.replay_pcr(m) == dice.replay_pcr(list(m))


# ---------------- attestation (needs the C simulator) ----------------
@pytest.mark.skipif(not os.path.exists(SIM), reason="build/pqboot-sim not built")
def test_attestation_end_to_end(ks, tmp_path):
    imgs = []
    for t, name in ((1, "bl2"), (2, "bl31"), (3, "bl32"), (4, "bl33")):
        path = tmp_path / f"{name}.pqb"
        path.write_bytes(image.build(name.encode() * 50, t, 1, 0, 0, ks, image.PQ_MLDSA87))
        imgs.append(str(path))
    nonce = os.urandom(32)
    qpath, apath = tmp_path / "q.bin", tmp_path / "alias.pub"
    r = subprocess.run([SIM, "--key-hash", ks.key_hash(1).hex(), "--allowed", "2",
                        "--nonce", nonce.hex(), "--quote", str(qpath),
                        "--alias-out", str(apath), *imgs], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    golden = {t: image.measurement(open(p, "rb").read()) for t, p in zip((1, 2, 3, 4), imgs)}
    q = qpath.read_bytes()

    # honest device
    expected_alias = dice.alias_public_bytes(
        dice.final_cdi(bytes([0xA5]) * 48, [golden[t] for t in (1, 2, 3, 4)]))
    assert apath.read_bytes() == expected_alias
    assert attest.verify(q, nonce, golden, expected_alias).ok

    # replayed quote (old nonce)
    assert not attest.verify(q, os.urandom(32), golden).ok
    # golden set does not contain this BL33
    bad = dict(golden)
    bad[4] = bytes(48)
    res = attest.verify(q, nonce, bad)
    assert not res.ok and any("type 4" in x for x in res.reasons)
    # tampered event log: signature breaks
    t = bytearray(q)
    t[100] ^= 1
    assert not attest.verify(bytes(t), nonce, golden).ok
