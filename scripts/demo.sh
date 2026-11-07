#!/usr/bin/env bash
# End-to-end demo on the host (no QEMU needed):
#   1. generate keys, sign BL2/BL31/BL32/BL33 with ECDSA-P384 + ML-DSA-87
#   2. boot the chain in the simulator, produce an attestation quote
#   3. verify the quote as a remote relying party
#   4. attacks: tampered image, rollback, foreign key, replayed quote
set -euo pipefail
cd "$(dirname "$0")/.."
B=build/demo
SIM=build/pqboot-sim
export PYTHONPATH=tools/pqsign
PQ="python3 -m pqsign"

[ -x "$SIM" ] || make -s build/pqboot-sim
rm -rf "$B"; mkdir -p "$B"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
expect_fail() { if "$@"; then echo "!! expected failure but it passed"; exit 1; fi; }

step "1. keys and signed images"
$PQ keygen --out "$B/keys" >/dev/null
for spec in "bl2 1 0x0e01b000" "bl31 3 0x0e060000" "bl32 1 0x0e100000" "bl33 5 0x60000000"; do
	set -- $spec
	head -c 65536 /dev/urandom > "$B/$1.bin"
	$PQ sign --keys "$B/keys" --type "$1" --version "$2" --load "$3" --entry "$3" \
		--pq mldsa87 --in "$B/$1.bin" --out "$B/$1.pqb"
done
KH=$($PQ anchor --keys "$B/keys" --pq mldsa87 --json "$B/ta.json" --c-header "$B/pqb_rotpk.h")
$PQ golden --out "$B/golden.json" "$B"/bl2.pqb "$B"/bl31.pqb "$B"/bl32.pqb "$B"/bl33.pqb
$PQ inspect "$B/bl31.pqb"
IMGS=("$B/bl2.pqb" "$B/bl31.pqb" "$B/bl32.pqb" "$B/bl33.pqb")

step "2. honest boot + attestation"
NONCE=$(python3 -c 'import os;print(os.urandom(32).hex())')
printf '1 0\n2 3\n3 0\n4 0\n' > "$B/rollback.txt"
$SIM --key-hash "$KH" --allowed 2 --rollback "$B/rollback.txt" \
     --nonce "$NONCE" --quote "$B/quote.bin" --alias-out "$B/alias.pub" "${IMGS[@]}"
$PQ verify-quote --quote "$B/quote.bin" --nonce "$NONCE" --golden "$B/golden.json" \
     --alias "$B/alias.pub"

step "3a. attack: one byte of BL32 payload modified"
cp "$B/bl32.pqb" "$B/bl32_evil.pqb"
python3 -c "import sys;p=sys.argv[1];b=bytearray(open(p,'rb').read());b[4000]^=0xFF;open(p,'wb').write(b)" "$B/bl32_evil.pqb"
expect_fail $SIM --key-hash "$KH" --allowed 2 "$B/bl2.pqb" "$B/bl31.pqb" "$B/bl32_evil.pqb" "$B/bl33.pqb"

step "3b. attack: rollback to an old, validly signed BL31 (v1 < counter 3)"
$PQ sign --keys "$B/keys" --type bl31 --version 1 --load 0x0e060000 --entry 0x0e060000 \
	--in "$B/bl31.bin" --out "$B/bl31_old.pqb" >/dev/null
expect_fail $SIM --key-hash "$KH" --allowed 2 --rollback "$B/rollback.txt" \
	"$B/bl2.pqb" "$B/bl31_old.pqb"

step "3c. attack: image signed with the attacker's own keys"
$PQ keygen --out "$B/evil_keys" >/dev/null
$PQ sign --keys "$B/evil_keys" --type bl33 --version 9 --in "$B/bl33.bin" --out "$B/bl33_evil.pqb" >/dev/null
expect_fail $SIM --key-hash "$KH" --allowed 2 "$B/bl2.pqb" "$B/bl33_evil.pqb"

step "3d. attack: replay the old quote against a new challenge"
NEW=$(python3 -c 'import os;print(os.urandom(32).hex())')
expect_fail $PQ verify-quote --quote "$B/quote.bin" --nonce "$NEW" --golden "$B/golden.json"

step "3e. attack: device boots a validly signed but non-golden BL33"
$PQ sign --keys "$B/keys" --type bl33 --version 6 --load 0x60000000 --entry 0x60000000 \
	--in "$B/bl2.bin" --out "$B/bl33_other.pqb" >/dev/null
$SIM --key-hash "$KH" --allowed 2 --nonce "$NEW" --quote "$B/quote2.bin" \
	"$B/bl2.pqb" "$B/bl31.pqb" "$B/bl32.pqb" "$B/bl33_other.pqb" >/dev/null
expect_fail $PQ verify-quote --quote "$B/quote2.bin" --nonce "$NEW" --golden "$B/golden.json" \
	--alias "$B/alias.pub"

step "demo complete: honest boot attests, every attack is rejected"
