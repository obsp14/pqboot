# Threat model

## Assets
* **Integrity of the boot chain.** Only images signed by the vendor keys,
  and not older than the rollback floor, may execute.
* **The device secret (UDS) and the derived CDIs.** These are the root of the
  device's identity.
* **Honest attestation.** A quote must reflect what actually booted, and it
  must be fresh.

## Attackers and what stops them

| # | Attacker capability | Attack | Mitigation | Where |
|---|---|---|---|---|
| A1 | Writes flash / FIP | Modify payload | Payload digest bound in signed header | image.c step 5 |
| A2 | Writes flash | Modify header (load address, version, type) | Header signed by both algorithms | steps 3–4 |
| A3 | Writes flash | Sign with own keys | Key hash vs OTP anchor | step 2 |
| A4 | Writes flash | Re-flash an old, validly signed, vulnerable image | Rollback counter | step 6 |
| A5 | Writes flash | Put a validly signed BL33 into the BL31 slot | Image type checked against the slot | pqb_tfa_stage.c |
| A6 | Malformed input | Overflow lengths or offsets to read out of bounds | Overflow-safe parsing, exact length; fuzzed with ASan/UBSan | image.c parse() |
| A7 | Future quantum computer | Forge ECDSA | ML-DSA-87 / LMS must also verify | hybrid policy |
| A8 | Cryptanalysis of the young PQ scheme | Forge ML-DSA | ECDSA must also verify | hybrid policy |
| A9 | Physical glitching (one fault) | Skip or invert one check | Redundant checks, flow counter, non-trivial status values | harden.h, faultinj/ |
| A10 | Network | Replay an old quote | Verifier nonce inside the signed quote | attest.py |
| A11 | Compromised later stage (e.g. Linux) | Steal an earlier CDI | CDIs wiped before hand-off; PTA keeps the last CDI in OP-TEE core | dice.c, PTA |
| A12 | Signing infrastructure | Reuse an LMS leaf | State persisted before a signature is released | lms.py |

## Out of scope / known limitations
* **Side channels on signing keys.** These live on the host. The device
  holds only the CDI and alias key, and the HMAC / P-384 code there is not
  hardened against power analysis.
* **Multiple faults.** Two well-timed glitches can defeat a duplicated
  check. Real silicon adds glitch detectors, random delays and
  instruction-level duplication.
* **The QEMU demo stores the UDS in BL1 code.** On silicon it must come from
  OTP, with the read port locked after BL1.
* **Rollback counters are constants on QEMU.** They need monotonic hardware
  storage, plus a policy for when to bump them (only after the new version
  boots successfully).
* **TOCTOU:** the image is verified in the memory it executes from, after
  loading, so it can't change between the check and the use, *as long as no
  DMA-capable master can write that memory*. On real silicon, configure the
  memory firewalls (TZASC, XPPU/XMPU-like units) before verification.
* **No certification.** FIPS 204 conformance is tested only against OpenSSL
  for a few vectors. The LMS code is checked only against our own signer;
  validating it against the RFC 8554 Appendix F vectors is an exercise in
  LEARNING_PATH.md.
