# pqboot - host build (library, tests, simulator, fuzzers, fault-injection)
#
#   make            build everything into build/
#   make test       C unit tests + Python tests + end-to-end demo
#   make fuzz       run the fuzz harness for FUZZ_SECONDS (default 60)
#   make faultinj   single-fault sweep, hardened vs. unhardened build
#   make bench      verification timing
#   make clean

CC      ?= gcc
PY      ?= python3
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c99 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
           -Wno-sign-conversion -Ilib/include -Iports
LDLIBS  := -lcrypto
B       := build

LIB_SRC := lib/src/sha256.c lib/src/sha384.c lib/src/keccak.c \
           lib/src/mldsa87.c lib/src/lms.c lib/src/image.c \
           lib/src/dice.c lib/src/attest.c
PORT    := ports/host_openssl.c

all: $(B)/pqboot-sim $(B)/test_crypto $(B)/test_crypto_static $(B)/test_image $(B)/fuzz_image \
     $(B)/faultinj_hard $(B)/faultinj_soft $(B)/bench

$(B):
	@mkdir -p $@

$(B)/pqboot-sim: sim/pqboot_sim.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(B)/test_crypto: tests/test_crypto.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# same tests with the ML-DSA workspace in .bss (the TF-A configuration)
$(B)/test_crypto_static: tests/test_crypto.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) -DPQB_MLDSA_STATIC_WS $^ -o $@ $(LDLIBS)

$(B)/test_image: tests/test_image.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# Fuzz driver: libFuzzer entry point + a standalone mutation loop, built
# with AddressSanitizer + UndefinedBehaviourSanitizer.
$(B)/fuzz_image: fuzz/fuzz_image.c fuzz/standalone_driver.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
	      $^ -o $@ $(LDLIBS)

$(B)/faultinj_hard: faultinj/faultinj.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) -DPQB_FAULT_SIM -DPQB_HARDEN=1 $^ -o $@ $(LDLIBS)

$(B)/faultinj_soft: faultinj/faultinj.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) -DPQB_FAULT_SIM -DPQB_HARDEN=0 $^ -o $@ $(LDLIBS)

$(B)/bench: bench/bench.c $(LIB_SRC) $(PORT) | $(B)
	$(CC) $(CFLAGS) -O3 $^ -o $@ $(LDLIBS)

vectors: | $(B)
	$(PY) tests/gen_vectors.py $(B)/vectors

test: all vectors
	$(B)/test_crypto $(B)/vectors
	$(B)/test_crypto_static $(B)/vectors
	$(B)/test_image $(B)/vectors
	cd tools/pqsign && $(PY) -m pytest -q tests
	./scripts/demo.sh

FUZZ_SECONDS ?= 60
fuzz: $(B)/fuzz_image vectors
	$(B)/fuzz_image -seconds=$(FUZZ_SECONDS) $(B)/vectors/corpus

faultinj: $(B)/faultinj_hard $(B)/faultinj_soft vectors
	@echo "=== UNHARDENED build (PQB_HARDEN=0) ==="
	-$(B)/faultinj_soft $(B)/vectors
	@echo
	@echo "=== HARDENED build (PQB_HARDEN=1) ==="
	$(B)/faultinj_hard $(B)/vectors

bench: $(B)/bench vectors
	$(B)/bench $(B)/vectors

clean:
	rm -rf $(B)

.PHONY: all test vectors fuzz faultinj bench clean
