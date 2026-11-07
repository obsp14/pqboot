/*
 * hash.h - SHA-256, SHA-384, SHA3 / SHAKE and HMAC-SHA384
 *
 * SHA-256      : LMS / LM-OTS (RFC 8554, NIST SP 800-208)
 * SHA-384      : image digests, ECDSA-P384 message digest, DICE CDI chain
 * SHAKE128/256 : ML-DSA-87 (FIPS 204)
 */
#ifndef PQB_HASH_H
#define PQB_HASH_H

#include "pqb/common.h"

#define PQB_SHA256_LEN 32u
#define PQB_SHA384_LEN 48u

/* ---------------- SHA-256 ---------------- */
typedef struct {
	uint32_t h[8];
	uint64_t len;      /* total bytes absorbed */
	uint8_t buf[64];
	size_t fill;
} pqb_sha256_ctx;

void pqb_sha256_init(pqb_sha256_ctx *c);
void pqb_sha256_update(pqb_sha256_ctx *c, const void *data, size_t n);
void pqb_sha256_final(pqb_sha256_ctx *c, uint8_t out[PQB_SHA256_LEN]);
void pqb_sha256(const void *data, size_t n, uint8_t out[PQB_SHA256_LEN]);

/* ---------------- SHA-384 (SHA-512 core) ---------------- */
typedef struct {
	uint64_t h[8];
	uint64_t len_lo;   /* total bytes absorbed (128-bit counter, low)  */
	uint64_t len_hi;
	uint8_t buf[128];
	size_t fill;
} pqb_sha384_ctx;

void pqb_sha384_init(pqb_sha384_ctx *c);
void pqb_sha384_update(pqb_sha384_ctx *c, const void *data, size_t n);
void pqb_sha384_final(pqb_sha384_ctx *c, uint8_t out[PQB_SHA384_LEN]);
void pqb_sha384(const void *data, size_t n, uint8_t out[PQB_SHA384_LEN]);

/* ---------------- Keccak / SHA-3 / SHAKE ---------------- */
typedef struct {
	uint64_t s[25];
	size_t rate;       /* bytes */
	size_t pos;        /* position inside current block */
	uint8_t dsbyte;    /* domain separation: 0x06 SHA3, 0x1F SHAKE */
	int squeezing;
} pqb_keccak_ctx;

void pqb_shake128_init(pqb_keccak_ctx *c);
void pqb_shake256_init(pqb_keccak_ctx *c);
void pqb_keccak_absorb(pqb_keccak_ctx *c, const void *data, size_t n);
void pqb_keccak_squeeze(pqb_keccak_ctx *c, uint8_t *out, size_t n);

void pqb_shake256(const void *in, size_t inlen, uint8_t *out, size_t outlen);
void pqb_sha3_256(const void *in, size_t inlen, uint8_t out[32]);
void pqb_sha3_384(const void *in, size_t inlen, uint8_t out[48]);

/* ---------------- HMAC-SHA384 ---------------- */
void pqb_hmac_sha384(const uint8_t *key, size_t keylen,
		     const uint8_t *msg, size_t msglen,
		     uint8_t out[PQB_SHA384_LEN]);

/* Wipe sensitive buffers in a way the compiler cannot optimise away. */
void pqb_wipe(void *p, size_t n);

#endif /* PQB_HASH_H */
