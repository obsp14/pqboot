# Integrating pqboot into TF-A + OP-TEE on QEMU

Everything under `integration/` is **untested**. It was written against
public APIs but has never been compiled. Expect to fix compile errors, adjust
memory maps and read TF-A source. Each step below says how to tell it worked.

## 0. Prerequisites
* Ubuntu 22.04/24.04, 16 GB RAM (8 is slow), ~50 GB free disk
* Run `make test` in this repo first: all green

## 1. Stock build, no changes
```sh
integration/qemu/setup.sh          # repo sync + toolchains + full build
cd ~/pqboot-qemu/build && make run
```
✅ Linux boots, and `xtest -l 0` passes in the normal-world console. Don't go
further until this works. Every later problem is easier when you know the
baseline was fine.

## 2. Learn the boot flow you're about to modify
* Read `trusted-firmware-a/plat/qemu/common/qemu_bl2_setup.c` and
  `common/desc_image_load.c`.
* In `make run`, watch BL1 → BL2 → BL31 → OP-TEE → U-Boot logs.
* Write down the load address of each image from
  `plat/qemu/qemu/include/platform_def.h`. You'll need them for signing.

## 3. Sign the images
```sh
WORK=~/pqboot-qemu integration/qemu/sign_fip_images.sh
```
Produces `*.signed` (trailer form) and `pqb_rotpk.h` in `~/pqboot-qemu/pqboot-signed/`.
✅ `python3 -m pqsign inspect` works on a PQB1 copy, and each `.signed` ends
with `PQBT` (`tail -c 8 file | xxd`).

## 4. Patch TF-A
Follow `integration/tf-a/qemu_hooks.patch.md`:
1. BL2 post-load hook
2. BL1 post-load hook
3. `platform.mk` include
4. map the hand-off page

Build:
```sh
cd ~/pqboot-qemu/build
make arm-tf PQBOOT_DIR=/path/to/pqboot PQB_ROTPK_DIR=~/pqboot-qemu/pqboot-signed
```
Make `build/` use the `.signed` files for BL2/BL31/BL32/BL33 when it builds
the FIP. Look at how `build/qemu_v8.mk` passes `BL32=`, `BL33=` to TF-A.

✅ The boot log shows `pqboot: image 3 verified (v1, ECDSA-P384+ML-DSA-87)` for
BL2/BL31/BL32/BL33 and Linux still boots.

Likely problems:
* "region overflowed": raise BL1/BL2 size limits.
* Undefined `mbedtls_*`: check that MBEDTLS_DIR is set and P-384 is enabled.
* Data abort when writing the hand-off page: it's not mapped (step 4 of
  the patch guide).
* BL32 rejected: the OP-TEE pager/pageable split. Build OP-TEE with
  `CFG_WITH_PAGER=n`, or handle the extra image IDs.

## 5. Prove it rejects things
| Test | How | Expected |
|---|---|---|
| Tampered BL33 | Flip a byte in `u-boot.bin.signed`, rebuild the FIP | BL2 prints REJECTED, panics |
| Foreign key | Sign BL31 with `pqsign keygen --out evil` keys | REJECTED (key not trusted) |
| Rollback | Set `PQB_TFA_ROLLBACK_COUNTERS` BL31 slot to 2, keep v1 image | REJECTED (rollback) |
| Glitch | `faultinj/qemu_gdb_skip.py` on the branch after the PQ check | `PQB_HARDEN=0`: boots; `=1`: panics |

Record a short screen capture of each for the README.

## 6. OP-TEE attestation PTA
1. Rebuild OP-TEE with `CFG_TZDRAM_SIZE=0x00eff000` and
   `CFG_CRYPTOLIB_NAME=mbedtls CFG_CRYPTOLIB_DIR=lib/libmbedtls`.
2. Copy `integration/optee/pta_pqb_attest.c` to `optee_os/core/pta/`, add it to
   `core/pta/sub.mk`, and add `lib/src/{sha384,dice,attest}.c` plus the include path.
3. Build `integration/optee/host/pqb_attest.c` for the normal world and add it
   to the Buildroot overlay, or copy it in through the 9p shared folder.

✅ In Linux run `pqb_attest $(head -c32 /dev/urandom | xxd -p -c64) /mnt/host/quote.bin`,
then on the host:
```sh
python3 -m pqsign verify-quote --quote quote.bin --nonce <same hex> --golden golden.json
```
→ `ATTESTATION OK`. Boot a modified BL33 that is still validly signed, and the
same command must fail with "measurement not in golden set".

## 7. Write it up
* Measure boot time with and without pqboot (TF-A `PLAT_LOG_LEVEL_ASSERT`
  timestamps, or QEMU `-d` timing). QEMU timing isn't representative of
  silicon, so say so.
* Write a one-page comparison of this chain with Versal's PLM boot, using
  **public AMD documentation only** (UG1304 / the open-source `embeddedsw`
  repository).
