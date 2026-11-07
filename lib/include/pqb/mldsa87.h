/*
 * mldsa87.h - ML-DSA-87 signature VERIFICATION (FIPS 204, "pure" mode)
 *
 * Boot firmware only ever verifies, so only verification is implemented.
 * Signing lives in the host tool (tools/pqsign) where keys are kept.
 *
 * Parameter set ML-DSA-87 (NIST category 5, required by CNSA 2.0):
 *   q = 8380417, n = 256, (k, l) = (8, 7), eta = 2, tau = 60,
 *   gamma1 = 2^19, gamma2 = (q-1)/32, omega = 75, lambda = 256
 */
#ifndef PQB_MLDSA87_H
#define PQB_MLDSA87_H

#include "pqb/common.h"

#define PQB_MLDSA87_PK_BYTES   2592u
#define PQB_MLDSA87_SIG_BYTES  4627u

/*
 * Verify sig over msg with optional context string (FIPS 204 Alg. 3:
 * M' = 0x00 || len(ctx) || ctx || M). ctxlen must be <= 255.
 *
 * Memory: ~13.5 KiB of working buffers (the 224 KiB matrix A is never
 * stored; it is regenerated row by row). They live on the stack unless the
 * library is built with -DPQB_MLDSA_STATIC_WS (recommended for TF-A, where
 * stacks are 4-8 KiB). Returns PQB_OK on success.
 */
pqb_status_t pqb_mldsa87_verify(const uint8_t pk[PQB_MLDSA87_PK_BYTES],
				const uint8_t *msg, size_t msglen,
				const uint8_t *ctx, size_t ctxlen,
				const uint8_t sig[PQB_MLDSA87_SIG_BYTES]);

#endif /* PQB_MLDSA87_H */
