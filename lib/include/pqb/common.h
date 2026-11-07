/*
 * pqboot - post-quantum secure & measured boot library
 * common.h - shared types, status codes and small helpers
 *
 * The library is freestanding: no malloc, no stdio, no global state.
 * It only needs <stdint.h>, <stddef.h> and memcpy/memset (provided by every
 * bare-metal libc, TF-A's libc and OP-TEE's libutils).
 */
#ifndef PQB_COMMON_H
#define PQB_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Status codes.
 *
 * PQB_OK is deliberately NOT 0 or 1. A single bit flip, a skipped
 * "mov r0, #0" or a corrupted return register is very unlikely to turn an
 * error into this exact 32-bit pattern. Every caller compares against
 * PQB_OK explicitly ("== PQB_OK"), never "if (!ret)".
 */
typedef uint32_t pqb_status_t;

#define PQB_OK                 0x3CA5965Au
#define PQB_ERR                0xC35A69A5u /* generic failure            */
#define PQB_ERR_FORMAT         0xC35A0001u /* malformed header / encoding */
#define PQB_ERR_BOUNDS         0xC35A0002u /* length / offset out of range*/
#define PQB_ERR_DIGEST         0xC35A0003u /* payload hash mismatch       */
#define PQB_ERR_SIG_CLASSIC    0xC35A0004u /* ECDSA-P384 rejected         */
#define PQB_ERR_SIG_PQ         0xC35A0005u /* ML-DSA / LMS rejected       */
#define PQB_ERR_ROLLBACK       0xC35A0006u /* version below counter       */
#define PQB_ERR_KEY            0xC35A0007u /* key hash not trusted        */
#define PQB_ERR_POLICY         0xC35A0008u /* algorithm not allowed       */
#define PQB_ERR_FAULT          0xC35A0009u /* redundancy check tripped    */
#define PQB_ERR_PORT           0xC35A000Au /* platform hook failed        */

/* Endianness helpers (image format is little-endian, LMS is big-endian). */
static inline uint32_t pqb_load_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline uint16_t pqb_load_le16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t pqb_load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void pqb_store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static inline void pqb_store_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void pqb_store_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

#endif /* PQB_COMMON_H */
