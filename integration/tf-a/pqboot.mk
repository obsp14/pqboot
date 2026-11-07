# pqboot.mk - include from plat/qemu/qemu/platform.mk (UNTESTED)
#
#   PQBOOT_DIR  := /path/to/pqboot
#   include $(PQBOOT_DIR)/integration/tf-a/pqboot.mk
#
# and build TF-A with e.g.
#   make PLAT=qemu BL32=... BL33=... SPD=opteed \
#        MBEDTLS_DIR=/path/to/mbedtls PQBOOT_DIR=/path/to/pqboot \
#        PQB_ROTPK_DIR=/path/to/dir/with/pqb_rotpk.h all fip

PQBOOT_DIR      ?= $(error set PQBOOT_DIR)
PQB_ROTPK_DIR   ?= $(PQBOOT_DIR)/build/demo

PQB_LIB_SOURCES := $(PQBOOT_DIR)/lib/src/sha256.c   \
                   $(PQBOOT_DIR)/lib/src/sha384.c   \
                   $(PQBOOT_DIR)/lib/src/keccak.c   \
                   $(PQBOOT_DIR)/lib/src/mldsa87.c  \
                   $(PQBOOT_DIR)/lib/src/lms.c      \
                   $(PQBOOT_DIR)/lib/src/image.c    \
                   $(PQBOOT_DIR)/lib/src/dice.c     \
                   $(PQBOOT_DIR)/integration/tf-a/pqb_tfa_port.c \
                   $(PQBOOT_DIR)/integration/tf-a/pqb_tfa_stage.c

PLAT_INCLUDES   += -I$(PQBOOT_DIR)/lib/include -I$(PQB_ROTPK_DIR)

# Big ML-DSA buffers in .bss, not on TF-A's small stacks
$(eval $(call add_define_val,PQB_MLDSA_STATIC_WS,1))

BL1_SOURCES     += $(PQB_LIB_SOURCES) $(MBEDTLS_SOURCES)
BL2_SOURCES     += $(PQB_LIB_SOURCES) $(MBEDTLS_SOURCES)

# TF-A's mbedTLS glue (heap, init) - normally pulled in by TRUSTED_BOARD_BOOT
include drivers/auth/mbedtls/mbedtls_common.mk
