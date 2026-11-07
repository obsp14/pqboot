# Architecture

## Layers

```
+-------------------------------------------------------------+
| tools/pqsign (Python, host)                                 |
|   keygen | sign (ECDSA + ML-DSA / LMS) | anchor | golden     |
|   verify-quote (relying party)                              |
+-------------------------------------------------------------+
                 | signed images, pqb_rotpk.h, golden.json
                 v
+-------------------------------------------------------------+
| lib/ (freestanding C99, no malloc, no global mutable state*)|
|   image.c   parse + hardened hybrid policy + rollback       |
|   mldsa87.c FIPS 204 verify     lms.c  RFC 8554 verify      |
|   sha256/sha384/keccak/hmac     dice.c attest.c             |
+-------------------------------------------------------------+
                 | port.h (3 hooks)
     +-----------+------------+----------------------------+
     | ports/host_openssl.c   | integration/tf-a/           |
     | (tests, sim, fuzz)     | pqb_tfa_port.c (mbedTLS)    |
     +------------------------+----------------------------+
```
`*` except the optional static ML-DSA workspace (`PQB_MLDSA_STATIC_WS`).

The port interface is deliberately tiny:

| Hook | Host | TF-A |
|---|---|---|
| `pqb_port_ecdsa_p384_verify` | OpenSSL EC_KEY/ECDSA | mbedTLS ecdsa_verify |
| `pqb_port_rollback_read` | table / file | OTP / NV counter (constants on QEMU) |
| `pqb_port_fault_detected` | counts events | `panic()` |

ECDSA comes from the platform because every boot ROM already ships a
P-384 implementation (often hardware-accelerated). ML-DSA and LMS are
in the library because platforms mostly don't have them yet, which is
the whole migration problem.

## Image format (PQB1)

See `lib/include/pqb/image.h` for byte offsets.

* **One signed object: the 256-byte header.** It carries the payload digest,
  versions, addresses and every length, so signing the header binds
  everything. Both signatures cover the identical bytes.
* **Keys in the image, hash in OTP.** ML-DSA-87 public keys are 2,592 bytes,
  and OTP is expensive. This is the same idea as Versal's PPK hash in eFUSE
  and TF-A's ROTPK hash.
* **Exact length.** No trailing bytes are allowed, because unsigned slack
  after a signed image has hidden bootkits before.
* **Three forms** with identical security:
  * contiguous: `header | payload | keys | sigs`
  * detached: the payload is already in memory
  * trailer: `payload | blob | "PQBT" | len`. TF-A loads this unchanged, so
    code still starts at offset 0.

## ML-DSA-87 verification (lib/src/mldsa87.c)

Written straight from FIPS 204, Algorithms 3, 8, 21, 29, 30, 36, 40, 41 and
42, with plain `% q` arithmetic so every line can be checked against the
standard. Implementation notes:

* **The matrix Â is never stored.** It would be 8×7×256 coefficients. Each
  row is regenerated with SHAKE128 while accumulating Â·NTT(z), which cuts
  memory from ~224 KiB to ~13 KiB.
* `w1Encode(w1')` is absorbed into SHAKE256 row by row, so the whole w1
  vector is never held in memory either.
* The hint is decoded and checked strictly: positions increasing, unused
  slots zero. Malformed signatures are rejected before any heavy maths.
* Verification touches only public data, so constant-time code isn't
  required. A constant-time compare is still used out of habit.

## LMS (lib/src/lms.c, tools/pqsign/pqsign/lms.py)

* Supports LMS SHA-256 M32 with H5 or H10, and LM-OTS W4 or W8.
* **Stateful signing.** The Python signer writes the next unused leaf index
  to disk with fsync *before* it releases a signature. A crash can waste a
  leaf but can never reuse one. Leaf reuse breaks LMS completely.
* H5 gives 32 signatures, which is fine for a demo. Real firmware signing
  uses HSS (multi-level trees) or H20+ inside an HSM that owns the state.

## DICE measured boot (lib/src/dice.c)

```
CDI_0 = HMAC(UDS,     "PQB-CDI-v1" || M_BL2)
CDI_1 = HMAC(CDI_0,   "PQB-CDI-v1" || M_BL31)   ... and so on
PCR   = SHA-384(PCR || M_n)                     (TPM-style extend)
alias = ECDSA-P384 key with d = HMAC(CDI_last, "PQB-ALIAS-ECDSA-P384") mod (n-1) + 1
```

Each stage wipes the previous CDI before handing off. Changing any image
changes every later CDI and therefore the alias key. A verifier who pinned the
alias key at enrolment notices that even without trusting the event log.

**Simplifications** compared with TCG DICE and Caliptra:

* There are no per-layer X.509 certificates (DeviceID / Alias certs).
* The alias key is ECDSA only, not ML-DSA. A PQ attestation key would need
  ML-DSA key generation and signing on the device. That's listed as a
  next step in LEARNING_PATH.md.

## Attestation

1. The relying party sends a 32-byte nonce.
2. The device returns a quote containing the nonce, the PCR, the event log,
   the alias public key, and an ECDSA-P384 signature over all of it.
3. `pqsign verify-quote` checks, in order:
   * the format
   * the nonce (freshness)
   * the signature
   * the alias key against the enrolled one
   * that replaying the log reproduces the PCR
   * that every event is in the golden set and meets the minimum version.

On QEMU the quote is produced by an OP-TEE **pseudo-TA**, so the CDI never
leaves OP-TEE core. On the host, `pqboot-sim` produces it.
