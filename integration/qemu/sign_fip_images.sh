#!/usr/bin/env bash
# Sign the images the OP-TEE QEMU build produced, in trailer form, so the
# patched TF-A (docs/INTEGRATION.md) can verify them. Then rebuild the FIP
# with these files instead of the unsigned ones.
#
# STATUS: UNTESTED - output paths match OP-TEE's qemu_v8 build tree as of
# 4.x; adjust if your tree differs.
set -euo pipefail
PQBOOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${WORK:-$HOME/pqboot-qemu}
OUT=${OUT:-$WORK/pqboot-signed}
KEYS=${KEYS:-$PQBOOT/build/qemu-keys}
export PYTHONPATH=$PQBOOT/tools/pqsign
PQ="python3 -m pqsign"

mkdir -p "$OUT"
[ -d "$KEYS" ] || $PQ keygen --out "$KEYS"
$PQ anchor --keys "$KEYS" --pq mldsa87 --c-header "$OUT/pqb_rotpk.h" --json "$OUT/ta.json"

# addresses from plat/qemu/qemu/include/platform_def.h (check your tree)
sign() { $PQ sign --keys "$KEYS" --trailer --pq mldsa87 --type "$1" --version "$2" \
		--load "$3" --entry "$3" --in "$4" --out "$OUT/$(basename "$4").signed"; }

sign bl2  1 0x0e01b000 "$WORK/trusted-firmware-a/build/qemu/release/bl2.bin"
sign bl31 1 0x0e040000 "$WORK/trusted-firmware-a/build/qemu/release/bl31.bin"
sign bl32 1 0x0e100000 "$WORK/optee_os/out/arm/core/tee-pager_v2.bin"
sign bl33 1 0x60000000 "$WORK/u-boot/u-boot.bin"

$PQ golden --out "$OUT/golden.json" "$OUT"/*.signed 2>/dev/null || true
echo "signed images and pqb_rotpk.h in $OUT"
echo "rebuild TF-A with PQB_ROTPK_DIR=$OUT and point BL2/BL31/BL32/BL33 at the .signed files"
