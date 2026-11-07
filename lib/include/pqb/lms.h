/*
 * lms.h - Leighton-Micali hash-based signature VERIFICATION
 *         (RFC 8554, NIST SP 800-208 - CNSA 2.0's preferred firmware-signing
 *         algorithm). Single-level LMS (no HSS hierarchy).
 *
 * Supported parameter sets (SHA-256, n = m = 32):
 *   LMS:    LMS_SHA256_M32_H5  (0x05, 32 signatures)
 *           LMS_SHA256_M32_H10 (0x06, 1024 signatures)
 *   LM-OTS: LMOTS_SHA256_N32_W4 (0x03, p = 67)
 *           LMOTS_SHA256_N32_W8 (0x04, p = 34)
 *
 * LMS is STATEFUL on the signing side: every one-time key index q must be
 * used once only. The verifier cannot enforce that; the signing tool keeps
 * the state file (tools/pqsign/lms.py).
 */
#ifndef PQB_LMS_H
#define PQB_LMS_H

#include "pqb/common.h"

#define PQB_LMS_SHA256_M32_H5    0x00000005u
#define PQB_LMS_SHA256_M32_H10   0x00000006u
#define PQB_LMOTS_SHA256_N32_W4  0x00000003u
#define PQB_LMOTS_SHA256_N32_W8  0x00000004u

#define PQB_LMS_PK_BYTES 56u   /* lms_type(4) || ots_type(4) || I(16) || T1(32) */

/* Largest signature we accept: 4 + (4 + 32 + 67*32) + 4 + 10*32 = 2508 */
#define PQB_LMS_SIG_MAX  2508u

/* Exact signature length for a public key, or 0 if the key is unsupported. */
size_t pqb_lms_sig_len(const uint8_t pk[PQB_LMS_PK_BYTES]);

pqb_status_t pqb_lms_verify(const uint8_t pk[PQB_LMS_PK_BYTES],
			    const uint8_t *msg, size_t msglen,
			    const uint8_t *sig, size_t siglen);

#endif /* PQB_LMS_H */
