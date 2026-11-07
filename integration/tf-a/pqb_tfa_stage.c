/*
 * pqb_tfa_stage.c - glue that TF-A's load hooks call for every image.
 *
 * STATUS: UNTESTED (see pqb_tfa_port.c header).
 *
 * Flow on QEMU (qemu_v8, BL1 in ROM, everything else in FIP):
 *
 *   BL1  bl1_plat_handle_post_image_load(BL2_IMAGE_ID)
 *          -> pqb_tfa_dice_begin()           UDS -> DICE state in hand-off RAM
 *          -> pqb_tfa_verify_loaded(BL2)     verify + measure BL2
 *   BL2  bl2_plat_handle_post_image_load(BL31/BL32/BL33)
 *          -> pqb_tfa_verify_loaded(id)      verify + measure each image
 *   OP-TEE PTA reads the DICE state from the same hand-off RAM and answers
 *   attestation requests (integration/optee/pta_pqb_attest.c).
 *
 * Images in the FIP are in "trailer" form: payload || sigblob || PQBT || len
 * (`pqsign sign --trailer`), so TF-A loads them to their normal address and
 * code still starts at offset 0.
 */
#include <string.h>

#include <common/debug.h>
#include <common/desc_image_load.h>
#include <plat/common/platform.h>

#include "pqb/dice.h"
#include "pqb/image.h"
#include "pqb_rotpk.h"   /* generated: pqsign anchor --c-header pqb_rotpk.h */

/*
 * Hand-off region shared by BL1, BL2 and OP-TEE. On qemu_v8 we take the
 * last 4 KiB of secure DRAM and shrink OP-TEE's TZDRAM by the same amount
 * (CFG_TZDRAM_SIZE=0x00eff000). The region must be mapped in BL1's and
 * BL2's translation tables - see docs/INTEGRATION.md step 4.
 */
#ifndef PQB_DICE_HANDOFF_BASE
#define PQB_DICE_HANDOFF_BASE 0x0efff000UL
#endif

/* QEMU has no fuses: a fixed demo UDS. On silicon read it from OTP and
 * lock the OTP read port before leaving BL1. */
static const uint8_t demo_uds[48] = {
	0x51, 0x45, 0x4d, 0x55, 0x2d, 0x44, 0x45, 0x4d, 0x4f, 0x2d, 0x55, 0x44,
	0x53, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x2d, 0x72, 0x65, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2d, 0x6f, 0x6e, 0x2d,
	0x72, 0x65, 0x61, 0x6c, 0x2d, 0x68, 0x77, 0x21, 0x21, 0x21, 0x21, 0x21
};

static const pqb_trust_anchor anchor = {
	.key_hash = PQB_ROTPK_HASH,
	.allowed_pq_algs = PQB_ALLOWED_PQ_ALGS,
};

static uint32_t tfa_id_to_pqb_type(unsigned int image_id)
{
	switch (image_id) {
	case BL2_IMAGE_ID: return PQB_IMG_BL2;
	case BL31_IMAGE_ID: return PQB_IMG_BL31;
	case BL32_IMAGE_ID: return PQB_IMG_BL32;
	case BL33_IMAGE_ID: return PQB_IMG_BL33;
	default: return PQB_IMG_TYPE_MAX;
	}
}

void pqb_tfa_dice_begin(void)
{
	pqb_dice_state *s = (pqb_dice_state *)PQB_DICE_HANDOFF_BASE;
	pqb_dice_init(s, demo_uds);
}

/*
 * Verify the image TF-A just loaded. Panics on failure: a boot ROM / BL2
 * has nothing safe to fall back to except a recovery path, which QEMU
 * does not have.
 */
void pqb_tfa_verify_loaded(unsigned int image_id, uintptr_t base, size_t size)
{
	pqb_dice_state *s = (pqb_dice_state *)PQB_DICE_HANDOFF_BASE;
	pqb_image_info info;
	pqb_status_t st;
	uint32_t want = tfa_id_to_pqb_type(image_id);

	if (want == PQB_IMG_TYPE_MAX)
		return;              /* not an image we sign (e.g. BL32 extras) */

	st = pqb_image_verify_trailer((const uint8_t *)base, size, &anchor, &info);
	if (st != PQB_OK) {
		ERROR("pqboot: image %u REJECTED (status 0x%08x)\n", image_id, st);
		panic();
	}
	if (info.image_type != want) {
		/* a validly signed BL33 placed in the BL31 slot, etc. */
		ERROR("pqboot: image %u has type %u, expected %u\n",
		      image_id, info.image_type, want);
		panic();
	}
	if (info.load_addr != (uint64_t)base) {
		/* signed for a different address: refuse, the code may not be
		 * position independent and the signer meant somewhere else */
		ERROR("pqboot: image %u signed for 0x%llx, loaded at 0x%lx\n",
		      image_id, (unsigned long long)info.load_addr, (unsigned long)base);
		panic();
	}
	if (pqb_dice_extend(s, &info) != PQB_OK) {
		ERROR("pqboot: DICE extend failed\n");
		panic();
	}
	NOTICE("pqboot: image %u verified (v%u, %s), measured\n", image_id,
	       info.security_version,
	       info.pq_alg == PQB_PQ_MLDSA87 ? "ECDSA-P384+ML-DSA-87"
					     : "ECDSA-P384+LMS");
}
