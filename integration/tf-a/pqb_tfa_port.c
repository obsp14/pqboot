/*
 * pqb_tfa_port.c - pqboot port layer for Trusted Firmware-A (BL1 / BL2)
 *
 * STATUS: UNTESTED - written against TF-A v2.10+ and mbedTLS 3.x APIs but
 * never compiled in this repository's CI (no AArch64 toolchain there).
 * Expect to fix small API differences for your TF-A version. Read
 * docs/INTEGRATION.md first.
 *
 * Needs TF-A built with mbedTLS available (MBEDTLS_DIR=...), and P-384
 * enabled in the mbedTLS config TF-A uses (KEY_ALG=ecdsa KEY_SIZE=384, or
 * add MBEDTLS_ECP_DP_SECP384R1_ENABLED to your config).
 */
#include <string.h>

#include <common/debug.h>
#include <drivers/auth/mbedtls/mbedtls_common.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <plat/common/platform.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>

#include "pqb/port.h"
#include "pqb/image.h"

/*
 * Anti-rollback counters. On real silicon read these from OTP / eFUSE or
 * an RPMB-backed counter and bump them after a successful boot of a newer
 * version. QEMU has no OTP, so they are compile-time constants here.
 */
#ifndef PQB_TFA_ROLLBACK_COUNTERS
#define PQB_TFA_ROLLBACK_COUNTERS { 0, 0, 0, 0, 0, 0, 0, 0 }
#endif
static const uint32_t rollback_counters[PQB_IMG_TYPE_MAX] = PQB_TFA_ROLLBACK_COUNTERS;

pqb_status_t pqb_port_rollback_read(uint32_t image_type, uint32_t *counter)
{
	if (image_type >= PQB_IMG_TYPE_MAX)
		return PQB_ERR_PORT;
	*counter = rollback_counters[image_type];
	return PQB_OK;
}

void pqb_port_fault_detected(uint32_t site)
{
	/* A redundant check disagreed: assume a glitch attack. Do not try to
	 * continue or "retry" - stop the boot. */
	ERROR("pqboot: fault detected at check site %u, halting\n", site);
	panic();
}

pqb_status_t pqb_port_ecdsa_p384_verify(const uint8_t pub[97],
					const uint8_t digest[48],
					const uint8_t sig[96])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	mbedtls_mpi r, s;
	int rc;
	pqb_status_t st = PQB_ERR_SIG_CLASSIC;

	mbedtls_init();   /* TF-A helper: sets up the mbedTLS heap once */
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Q);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP384R1);
	if (rc == 0)
		rc = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 97);
	if (rc == 0)
		rc = mbedtls_ecp_check_pubkey(&grp, &Q);
	if (rc == 0)
		rc = mbedtls_mpi_read_binary(&r, sig, 48);
	if (rc == 0)
		rc = mbedtls_mpi_read_binary(&s, sig + 48, 48);
	if (rc == 0)
		rc = mbedtls_ecdsa_verify(&grp, digest, 48, &Q, &r, &s);
	if (rc == 0)
		st = PQB_OK;

	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);
	return st;
}
