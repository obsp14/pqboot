# Learning path

This repo was scaffolded quickly so you have something working to study.
It only counts as **your** project after you understand every line, have
rebuilt the parts listed under "do it yourself", and have done the QEMU
integration. An interviewer can tell within two questions.

## Week 1: hashes, the image format, the policy
* Read `lib/include/pqb/image.h`, then `lib/src/image.c` top to bottom.
* Run `make test`, then break things on purpose. Remove the
  `off == len` check and see which test catches it.
* Read FIPS 180-4 sections 5–6 alongside `sha384.c`.
* **Do it yourself:** add a `--max-payload` policy option and a test for it.

**Questions you should be able to answer:**
* Why sign the header and not the whole image?
* Why are the keys in the image but only their hash in OTP?
* What breaks if trailing bytes are allowed?

## Week 2: ML-DSA-87
* Read FIPS 204 sections 3, 6.3 (Verify) and 7 (Algorithms 21, 29–30,
  36–42) with `mldsa87.c` open next to it.
* Draw the data flow: pk → (ρ, t1); sig → (c̃, z, h); Â from ρ;
  w' = Â·z − c·t1·2^d; w1 = UseHint(h, w'); compare H(μ ‖ w1Encode) with c̃.
* **Do it yourself:** implement `Power2Round`/`Decompose` tests that compare
  against a Python version you write. Then rewrite `ntt()` with Montgomery
  multiplication like the reference implementation and benchmark it.

**Questions you should be able to answer:**
* Why does the verifier recompute c̃ instead of checking an equation?
* What is the hint for?
* Why can verification skip constant-time care while signing can't?

## Week 3: LMS and statefulness
* Read RFC 8554 sections 4–5 and SP 800-208 section 1.
* **Do it yourself:**
  * Validate `lib/src/lms.c` against the **RFC 8554 Appendix F test
    vectors**. Right now it's only checked against our own Python signer.
  * Add LMS_SHA256_M24 (SHA-256/192, the parameter set NSA prefers), using
    the IANA type codes.
* Explain why `LmsSigner.sign()` persists state before returning.

## Week 4: hybrid policy, fault injection, fuzzing
* `make faultinj`, then read `faultinj/faultinj.c` and `harden.h`.
* Find the 5 bypasses in the unhardened build in the source, and explain
  why the reserved-byte attack is *not* bypassable even unhardened. (The
  header is signed.)
* `make fuzz FUZZ_SECONDS=600`. Then install clang's libFuzzer runtime and
  run the real libFuzzer target with coverage.
* **Do it yourself:**
  * Add a random-delay countermeasure before each check.
  * Add a fault model that skips the *assignment* of `st` rather than the
    branch. Does the hardening still hold?

## Week 5: DICE and attestation
* Read the TCG "DICE Layering Architecture" overview and Caliptra's
  measured-boot section.
* Trace `pqboot-sim` with `--nonce`/`--quote`, and check the quote by hand
  with `pqsign verify-quote`.
* **Do it yourself:** make the alias key ML-DSA-87 instead of ECDSA. This
  needs ML-DSA key generation and signing from a seed. Use
  `MLDSA87PrivateKey.from_seed_bytes` on the host as the reference.

## Weeks 6–8: QEMU integration
Work through `docs/INTEGRATION.md`. This is the part that makes the
project yours: getting TF-A to link, mapping memory, debugging aborts.

## Interview questions this project prepares you for
* Walk me through a secure-boot chain from ROM to Linux.
* How would you protect a signature check against glitching?
* What is measured boot, and how does it differ from verified boot?
* Why hybrid signatures? What does CNSA 2.0 require for firmware?
* ML-DSA vs LMS for firmware: trade-offs in size, speed and state?
* How do you stop rollback, and where does the counter live?
* What is a TOCTOU in boot, and how did you avoid it?
* How did you test the parser? What did fuzzing find?
