// SPDX-License-Identifier: BSD-2-Clause
/*
 * pta_pqb_attest.c - OP-TEE pseudo-TA (runs in the OP-TEE core) that
 * answers attestation challenges using the DICE state left by TF-A.
 *
 * STATUS: UNTESTED - written against OP-TEE 4.x core APIs with
 * CFG_CRYPTOLIB_NAME=mbedtls. Drop into core/pta/, add
 * `srcs-$(CFG_PQB_ATTEST_PTA) += pta_pqb_attest.c` to core/pta/sub.mk and
 * the pqboot sources (sha384.c, dice.c, attest.c) to the core build.
 *
 * Why a PTA and not a normal TA: the CDI is the device's secret. It must
 * stay in the most privileged software that needs it (OP-TEE core); TAs
 * and Linux only ever see the signed quote and the alias PUBLIC key.
 *
 * Command PQB_CMD_GET_QUOTE:
 *   params[0] memref input  : 32-byte nonce from the verifier
 *   params[1] memref output : quote buffer (PQBQ format, lib/include/pqb/attest.h)
 */
#include <crypto/crypto.h>
#include <kernel/pseudo_ta.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee_api_types.h>
#include <trace.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>

#include "pqb/attest.h"
#include "pqb/dice.h"
#include "pqb/hash.h"

#define PTA_NAME "pqb_attest.pta"
/* 6f6e7f0c-9a1e-4c42-8d3a-7071623f4154 */
#define PTA_PQB_ATTEST_UUID { 0x6f6e7f0c, 0x9a1e, 0x4c42, \
	{ 0x8d, 0x3a, 0x70, 0x71, 0x62, 0x3f, 0x41, 0x54 } }
#define PQB_CMD_GET_QUOTE 0

#ifndef PQB_DICE_HANDOFF_BASE
#define PQB_DICE_HANDOFF_BASE 0x0efff000
#endif

register_phys_mem_pgdir(MEM_AREA_RAM_SEC, PQB_DICE_HANDOFF_BASE, SMALL_PAGE_SIZE);

static pqb_dice_state dice;       /* private copy, taken once at init */
static bool dice_ok;

static TEE_Result take_dice_state(void)
{
	pqb_dice_state *src = phys_to_virt(PQB_DICE_HANDOFF_BASE,
					   MEM_AREA_RAM_SEC, sizeof(*src));
	if (!src)
		return TEE_ERROR_ITEM_NOT_FOUND;
	memcpy(&dice, src, sizeof(dice));
	/* Wipe the shared copy: nothing that runs after OP-TEE's init
	 * (e.g. a compromised normal world with a DMA bug) should find it. */
	pqb_wipe(src, sizeof(*src));
	if (pqb_dice_validate(&dice) != PQB_OK) {
		EMSG("pqboot: no valid DICE hand-off found");
		return TEE_ERROR_BAD_STATE;
	}
	dice_ok = true;
	IMSG("pqboot: DICE state with %u measurements received", dice.count);
	return TEE_SUCCESS;
}

static int rng_cb(void *ctx __unused, unsigned char *buf, size_t len)
{
	return crypto_rng_read(buf, len) == TEE_SUCCESS ? 0 : -1;
}

/* d = seed mod (n - 1) + 1, Q = d*G  (same derivation as tools/pqsign/dice.py) */
static int alias_key(const uint8_t seed[48], mbedtls_ecp_group *grp,
		     mbedtls_mpi *d, uint8_t pub[97])
{
	mbedtls_ecp_point Q;
	mbedtls_mpi nm1;
	size_t olen = 0;
	int rc;

	mbedtls_ecp_point_init(&Q);
	mbedtls_mpi_init(&nm1);
	rc = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP384R1);
	if (!rc) rc = mbedtls_mpi_copy(&nm1, &grp->N);
	if (!rc) rc = mbedtls_mpi_sub_int(&nm1, &nm1, 1);
	if (!rc) rc = mbedtls_mpi_read_binary(d, seed, 48);
	if (!rc) rc = mbedtls_mpi_mod_mpi(d, d, &nm1);
	if (!rc) rc = mbedtls_mpi_add_int(d, d, 1);
	if (!rc) rc = mbedtls_ecp_mul(grp, &Q, d, &grp->G, rng_cb, NULL);
	if (!rc) rc = mbedtls_ecp_point_write_binary(grp, &Q,
				MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 97);
	if (!rc && olen != 97) rc = -1;
	mbedtls_mpi_free(&nm1);
	mbedtls_ecp_point_free(&Q);
	return rc;
}

static TEE_Result get_quote(uint32_t types, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	uint8_t seed[48], pub[97], digest[48];
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;
	size_t tbs, need;
	uint8_t *out;
	int rc;

	if (types != exp || p[0].memref.size != 32)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!dice_ok)
		return TEE_ERROR_BAD_STATE;

	need = pqb_quote_tbs_len(&dice) + 96;
	if (p[1].memref.size < need) {
		p[1].memref.size = need;
		return TEE_ERROR_SHORT_BUFFER;
	}
	out = p[1].memref.buffer;

	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	pqb_dice_derive(&dice, PQB_ALIAS_LABEL, seed);
	rc = alias_key(seed, &grp, &d, pub);
	pqb_wipe(seed, sizeof(seed));

	tbs = rc ? 0 : pqb_quote_build_tbs(&dice, p[0].memref.buffer, pub, out,
					   p[1].memref.size);
	if (!tbs)
		rc = -1;
	if (!rc) {
		pqb_sha384(out, tbs, digest);
		rc = mbedtls_ecdsa_sign(&grp, &r, &s, &d, digest, 48, rng_cb, NULL);
	}
	if (!rc) rc = mbedtls_mpi_write_binary(&r, out + tbs, 48);
	if (!rc) rc = mbedtls_mpi_write_binary(&s, out + tbs + 48, 48);

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&d);    /* mbedtls_mpi_free zeroises */
	mbedtls_ecp_group_free(&grp);
	if (rc)
		return TEE_ERROR_GENERIC;
	p[1].memref.size = tbs + 96;
	return TEE_SUCCESS;
}

static TEE_Result invoke(void *sess __unused, uint32_t cmd, uint32_t types,
			 TEE_Param p[TEE_NUM_PARAMS])
{
	if (cmd == PQB_CMD_GET_QUOTE)
		return get_quote(types, p);
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result create(void)
{
	return take_dice_state();
}

pseudo_ta_register(.uuid = PTA_PQB_ATTEST_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .create_entry_point = create,
		   .invoke_command_entry_point = invoke);
