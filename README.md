# pqboot — post-quantum secure & measured boot

A secure-boot verifier and measured-boot chain for Arm platforms that signs
every boot image twice, with **ECDSA-P384 and ML-DSA-87** (or **LMS**). An
image boots only if *both* signatures hold. Each stage measures the next into
a **DICE-style** chain, and the device proves what it booted through a signed
**attestation quote**. The verifier is hardened against **single-fault
(glitch) attacks**, fuzzed under ASan/UBSan, and small enough for TF-A BL1/BL2.

```
 BL1 (ROM)          BL2               BL31          BL32 (OP-TEE)        BL33 (U-Boot) -> Linux
 trust anchor  -->  verify+measure -> verify+meas -> verify+measure  ->  verify+measure
 UDS -> CDI0        CDI1              CDI2          CDI3 -> alias key -> signed quote
                                                     ^
                          remote verifier: nonce --> | <-- quote (PCR, event log, ECDSA sig)
```

## Why

* **CNSA 2.0** makes firmware signing the *first* system that must move to
  post-quantum signatures (support and prefer LMS/XMSS or ML-DSA from 2025,
  mandatory by 2030). Firmware roots of trust are the hardest thing to change
  after shipping.
* **Caliptra 2.x**, the open-source silicon root of trust from AMD, Google,
  Microsoft and NVIDIA, verifies firmware with ML-DSA-87 alongside ECDSA and
  provides DICE identity and attestation. pqboot is a small software model of
  those ideas that you can read in an afternoon.
* **Hybrid** signing: if a quantum computer breaks ECDSA, ML-DSA still holds.
  If a flaw shows up in the young PQ scheme or its implementation, ECDSA still
  holds.

## What's in the box

| Path | What | Status |
|---|---|---|
| `lib/` | Freestanding C99 library: SHA-256/384, SHA-3/SHAKE, HMAC, **ML-DSA-87 verify (FIPS 204)**, **LMS verify (RFC 8554)**, PQB1 image format, hardened hybrid verifier, anti-rollback, DICE chain, quote format | ✅ tested here |
| `ports/host_openssl.c` | Host port: ECDSA-P384 via OpenSSL, rollback counters, fault hook | ✅ tested |
| `sim/` | `pqboot-sim`: runs the whole BL1→BL33 policy + attestation on a laptop | ✅ tested |
| `tools/pqsign/` | Python: keygen, image signing (ECDSA + ML-DSA-87 / stateful LMS), inspect, trust-anchor export, golden values, quote verification | ✅ tested |
| `tests/` | 412 C checks (incl. the TF-A-style static-workspace build) + 7 pytest tests; vectors from independent implementations | ✅ passing |
| `fuzz/` | libFuzzer target + standalone ASan/UBSan mutation driver | ✅ 240k execs, clean |
| `faultinj/` | Single-fault sweep (hardened vs. unhardened) + QEMU/GDB instruction-skip script | ✅ sweep / ⚠️ GDB script untested |
| `bench/` | Verification timing | ✅ |
| `integration/tf-a/` | TF-A port (mbedTLS ECDSA), BL1/BL2 hooks, makefile fragment, patch guide | ⚠️ **untested** |
| `integration/optee/` | OP-TEE pseudo-TA that signs quotes with the DICE alias key + Linux client | ⚠️ **untested** |
| `integration/qemu/` | Fetch/build OP-TEE QEMU v8, sign FIP images | ⚠️ **untested** |

"Untested" means these files were written against the public TF-A / OP-TEE /
mbedTLS APIs but never compiled here: this machine has no AArch64 toolchain,
no QEMU and no network. Getting them to build and boot is the integration
work in `docs/INTEGRATION.md`, and it's where most of the learning is.

## Quick start (host only, ~1 minute)

```sh
sudo apt install build-essential libssl-dev python3-pip
pip install "cryptography>=45" pytest     # needs ML-DSA support (OpenSSL 3.5+ backend)
make test        # C unit tests + pytest + end-to-end demo with five attacks
make faultinj    # glitch sweep: unhardened vs hardened
make fuzz FUZZ_SECONDS=120
make bench
```

## Measured results (x86-64 host, single core, -O2/-O3)

| | Size | Verify time |
|---|---|---|
| ECDSA-P384 (OpenSSL 3.0, incl. key decode + point check) | sig 96 B, pk 97 B | ~0.9 ms |
| **ML-DSA-87** (pqboot, plain modular arithmetic) | sig 4,627 B, pk 2,592 B | ~0.4 ms |
| **LMS** SHA-256 H5/W4 | sig 2,348 B, pk 56 B | ~0.16 ms |
| LMS SHA-256 H5/W8 | sig 1,292 B, pk 56 B | ~1.4 ms |
| Full hardened verify (every check done twice) | — | ~2.7 ms |

Stack use of ML-DSA-87 verification is 13 KiB by default, or **1 KiB** with
`-DPQB_MLDSA_STATIC_WS` (buffers moved to .bss for TF-A's 4–8 KiB stacks).

Fault-injection sweep (`make faultinj`), one inverted security decision per run:

| Build | Faults injected | Single-fault bypasses | Redundancy alarms |
|---|---|---|---|
| `PQB_HARDEN=0` | 54 | **5** (key hash, ECDSA, ML-DSA, digest, rollback) | 0 |
| `PQB_HARDEN=1` | 64 | **0** | 15 |

## How verification works

`pqb_image_verify()` (lib/src/image.c) accepts an image only if **all** of
these hold:

1. The header is well-formed: magic, version, size, zero reserved bytes, and
   exact lengths with no trailing bytes. Every offset is checked with
   overflow-safe arithmetic, because the header is attacker-controlled.
2. SHA-384(classic_pk ‖ pq_pk) equals the 48-byte trust anchor in OTP, so the
   ~2.7 KiB of keys travel with the image while the device stores 48 bytes.
3. ECDSA-P384 over SHA-384(header) is valid.
4. ML-DSA-87 (context `pqboot-image-v1`) or LMS over the header is valid.
5. SHA-384(payload) equals the digest in the header.
6. `security_version` ≥ the rollback counter for that image type.
7. With `PQB_HARDEN=1`, steps 2–6 run twice from recomputed inputs and a
   flow counter must equal the exact sum of all mandatory steps.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Credits and scope

pqboot's own code is the library, tools, tests, simulator and integration
glue in this repo. It is designed to plug into **TF-A, OP-TEE, U-Boot, Linux
and QEMU**, which are separate open-source projects and not part of this
repository. Verification is implemented from FIPS 204 and RFC 8554 and
checked against OpenSSL's ML-DSA. It has **not** been certified or
side-channel evaluated; don't ship it.
