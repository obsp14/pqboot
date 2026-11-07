/*
 * image.h - PQB1 signed boot image format
 *
 *   +---------------------------+ 0
 *   | header (256 bytes, LE)    |  <- signed by BOTH algorithms
 *   +---------------------------+ 256
 *   | payload (payload_size)    |  <- bound via payload_digest in header
 *   +---------------------------+
 *   | classic public key  (97)  |  ECDSA-P384, SEC1 uncompressed 04||X||Y
 *   | PQ public key   (2592/56) |  ML-DSA-87 or LMS
 *   | classic signature   (96)  |  ECDSA-P384 raw r||s over SHA-384(header)
 *   | PQ signature  (4627/var)  |  ML-DSA-87 (ctx "pqboot-image-v1") or LMS
 *   +---------------------------+ total
 *
 * The public keys travel with the image; the device only stores
 * SHA-384(classic_pk || pq_pk) in one-time-programmable memory (like the
 * PPK hash in eFUSE on Versal or ROTPK hash in TF-A). This lets the key
 * blob be large (2.6 KiB for ML-DSA) while OTP stays at 48 bytes.
 *
 * Header layout (offsets in bytes):
 *   0   magic "PQB1"
 *   4   u16 header_version (=1)
 *   6   u16 header_size    (=256)
 *   8   u32 image_type     (PQB_IMG_*)
 *   12  u16 pq_alg         (PQB_PQ_MLDSA87 | PQB_PQ_LMS)
 *   14  u16 classic_alg    (PQB_CLASSIC_ECDSA_P384)
 *   16  u32 security_version (anti-rollback)
 *   20  u64 load_addr
 *   28  u64 entry_point
 *   36  u32 payload_size
 *   40  u8  payload_digest[48]  (SHA-384 of payload)
 *   88  u16 classic_pk_len, 90 u16 pq_pk_len,
 *   92  u16 classic_sig_len, 94 u16 pq_sig_len
 *   96  u8  reserved[160]   (must be zero)
 */
#ifndef PQB_IMAGE_H
#define PQB_IMAGE_H

#include "pqb/common.h"
#include "pqb/hash.h"

#define PQB_HDR_SIZE        256u
#define PQB_HDR_VERSION     1u
#define PQB_MAGIC           "PQB1"
#define PQB_MLDSA_CTX       "pqboot-image-v1"

#define PQB_IMG_BL2         1u
#define PQB_IMG_BL31        2u
#define PQB_IMG_BL32        3u   /* OP-TEE   */
#define PQB_IMG_BL33        4u   /* U-Boot   */
#define PQB_IMG_KERNEL      5u
#define PQB_IMG_TEST        0xFFu
#define PQB_IMG_TYPE_MAX    8u   /* rollback counters slots */

#define PQB_PQ_MLDSA87      1u
#define PQB_PQ_LMS          2u
#define PQB_CLASSIC_ECDSA_P384 1u

#define PQB_ECDSA_P384_PK_LEN  97u
#define PQB_ECDSA_P384_SIG_LEN 96u

#define PQB_MAX_PAYLOAD     (64u * 1024u * 1024u)

typedef struct {
	uint32_t image_type;
	uint32_t security_version;
	uint64_t load_addr;
	uint64_t entry_point;
	const uint8_t *payload;
	uint32_t payload_size;
	uint16_t pq_alg;
	/* Measurement = SHA-384(header). The header binds the payload digest,
	 * versions and addresses, so it identifies the image completely. */
	uint8_t measurement[PQB_SHA384_LEN];
} pqb_image_info;

/* Trust anchor: what the device "fuses" hold. */
typedef struct {
	uint8_t key_hash[PQB_SHA384_LEN];  /* SHA-384(classic_pk || pq_pk)   */
	uint32_t allowed_pq_algs;          /* bitmask: 1 << PQB_PQ_*         */
} pqb_trust_anchor;

/*
 * Verify a complete image in memory. On PQB_OK, *info describes it.
 * The function never reads outside [img, img + len).
 */
pqb_status_t pqb_image_verify(const uint8_t *img, size_t len,
			      const pqb_trust_anchor *ta,
			      pqb_image_info *info);

/*
 * Detached form: the payload lives elsewhere in memory (already loaded by
 * the boot loader) and `blob` is header || classic_pk || pq_pk ||
 * classic_sig || pq_sig, i.e. the image without its payload. header
 * .payload_size must equal payload_len. Same checks as pqb_image_verify().
 */
pqb_status_t pqb_image_verify_detached(const uint8_t *blob, size_t blob_len,
				       const uint8_t *payload, size_t payload_len,
				       const pqb_trust_anchor *ta,
				       pqb_image_info *info);

/*
 * Trailer form, convenient for TF-A: the file in the FIP is
 *     payload || blob || "PQBT" || u32 blob_len (LE)
 * so the loader can copy it to the image's load address unchanged and the
 * code starts at offset 0. buf/len is the whole loaded region.
 */
#define PQB_TRAILER_MAGIC "PQBT"
pqb_status_t pqb_image_verify_trailer(const uint8_t *buf, size_t len,
				      const pqb_trust_anchor *ta,
				      pqb_image_info *info);

#endif /* PQB_IMAGE_H */
