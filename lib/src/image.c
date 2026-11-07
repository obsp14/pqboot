/*
 * image.c - hardened hybrid (classical + post-quantum) image verification
 *
 * Acceptance rule: an image boots only if ALL of these hold
 *   - header is well-formed, reserved bytes are zero, sizes are exact
 *   - SHA-384(classic_pk || pq_pk) equals the trust anchor (OTP) value
 *   - ECDSA-P384 signature over SHA-384(header) is valid      } hybrid:
 *   - ML-DSA-87 (or LMS) signature over the header is valid   } both
 *   - SHA-384(payload) equals header.payload_digest
 *   - header.security_version >= rollback counter for its type
 *
 * Hybrid means an attacker must break BOTH ECDSA and the PQ scheme. If a
 * quantum computer breaks ECDSA, ML-DSA still holds; if a flaw is found in
 * the young PQ scheme (or its implementation), ECDSA still holds.
 */
#include "pqb/image.h"
#include "pqb/harden.h"
#include "pqb/lms.h"
#include "pqb/mldsa87.h"
#include "pqb/port.h"

/* Flow-counter increments: arbitrary distinct odd constants. */
#define FLOW_PARSE    0x1F3Bu
#define FLOW_KEYHASH  0x2C81u
#define FLOW_CLASSIC  0x3A57u
#define FLOW_PQ       0x4D29u
#define FLOW_DIGEST   0x5E13u
#define FLOW_ROLLBACK 0x6B65u
#define FLOW_EXPECTED (FLOW_PARSE + FLOW_KEYHASH + FLOW_CLASSIC + FLOW_PQ + \
		       FLOW_DIGEST + FLOW_ROLLBACK)

typedef struct {
	const uint8_t *hdr;
	uint16_t pq_alg, classic_alg;
	uint32_t type, secver, payload_size;
	uint64_t load, entry;
	const uint8_t *payload_digest;
	const uint8_t *payload, *cpk, *pqpk, *csig, *pqsig;
	uint16_t cpk_len, pqpk_len, csig_len, pqsig_len;
} parsed_hdr;

static uint64_t load_le64(const uint8_t *p)
{
	return (uint64_t)pqb_load_le32(p) | ((uint64_t)pqb_load_le32(p + 4) << 32);
}

static int expected_pq_lengths(uint16_t alg, const uint8_t *pqpk,
			       size_t pk_len, size_t sig_len)
{
	if (alg == PQB_PQ_MLDSA87)
		return pk_len == PQB_MLDSA87_PK_BYTES &&
		       sig_len == PQB_MLDSA87_SIG_BYTES;
	if (alg == PQB_PQ_LMS)
		return pk_len == PQB_LMS_PK_BYTES && pqpk != NULL &&
		       pqb_lms_sig_len(pqpk) == sig_len && sig_len != 0;
	return 0;
}

/*
 * Parse and bounds-check. All arithmetic is done in size_t with explicit
 * overflow checks: offsets come from an attacker-controlled header.
 */
static pqb_status_t parse(const uint8_t *img, size_t len,
			  const uint8_t *ext_payload, size_t ext_len,
			  const pqb_trust_anchor *ta, parsed_hdr *h)
{
	const uint8_t *p = img;
	size_t off, i;
	uint32_t nz = 0;

	if (len < PQB_HDR_SIZE)
		return PQB_ERR_BOUNDS;
	if (!PQB_CHECK(SITE_MAGIC, pqb_ct_equal(p, (const uint8_t *)PQB_MAGIC, 4)))
		return PQB_ERR_FORMAT;
	if (!PQB_CHECK(SITE_HDR_VERSION, pqb_load_le16(p + 4) == PQB_HDR_VERSION))
		return PQB_ERR_FORMAT;
	if (!PQB_CHECK(SITE_HDR_SIZE, pqb_load_le16(p + 6) == PQB_HDR_SIZE))
		return PQB_ERR_FORMAT;
	for (i = 96; i < PQB_HDR_SIZE; i++)
		nz |= p[i];
	if (!PQB_CHECK(SITE_RESERVED, nz == 0))
		return PQB_ERR_FORMAT;

	h->hdr = p;
	h->type = pqb_load_le32(p + 8);
	h->pq_alg = pqb_load_le16(p + 12);
	h->classic_alg = pqb_load_le16(p + 14);
	h->secver = pqb_load_le32(p + 16);
	h->load = load_le64(p + 20);
	h->entry = load_le64(p + 28);
	h->payload_size = pqb_load_le32(p + 36);
	h->payload_digest = p + 40;
	h->cpk_len = pqb_load_le16(p + 88);
	h->pqpk_len = pqb_load_le16(p + 90);
	h->csig_len = pqb_load_le16(p + 92);
	h->pqsig_len = pqb_load_le16(p + 94);

	if (!PQB_CHECK(SITE_ALG_ALLOWED,
		       h->classic_alg == PQB_CLASSIC_ECDSA_P384 &&
		       h->pq_alg < 32 &&
		       ((ta->allowed_pq_algs >> h->pq_alg) & 1u)))
		return PQB_ERR_POLICY;
	if (h->type >= PQB_IMG_TYPE_MAX && h->type != PQB_IMG_TEST)
		return PQB_ERR_FORMAT;
	if (h->payload_size > PQB_MAX_PAYLOAD)
		return PQB_ERR_BOUNDS;

	/* Walk the layout with overflow-safe additions. */
	off = PQB_HDR_SIZE;
	if (ext_payload == NULL) {
		if (h->payload_size > len - off)
			return PQB_ERR_BOUNDS;
		h->payload = p + off;
		off += h->payload_size;
	} else {
		/* detached: payload is somewhere else, sizes must agree */
		if ((size_t)h->payload_size != ext_len)
			return PQB_ERR_BOUNDS;
		h->payload = ext_payload;
	}

#define TAKE(field, n)                                   \
	do {                                             \
		if ((size_t)(n) > len - off)             \
			return PQB_ERR_BOUNDS;           \
		h->field = p + off;                      \
		off += (size_t)(n);                      \
	} while (0)

	TAKE(cpk, h->cpk_len);
	TAKE(pqpk, h->pqpk_len);
	TAKE(csig, h->csig_len);
	TAKE(pqsig, h->pqsig_len);
#undef TAKE

	if (!PQB_CHECK(SITE_LENGTHS,
		       h->cpk_len == PQB_ECDSA_P384_PK_LEN &&
		       h->csig_len == PQB_ECDSA_P384_SIG_LEN &&
		       expected_pq_lengths(h->pq_alg, h->pqpk,
					   h->pqpk_len, h->pqsig_len)))
		return PQB_ERR_FORMAT;
	/* No trailing garbage: what is signed is exactly what is loaded. */
	if (!PQB_CHECK(SITE_TOTAL_LEN, off == len))
		return PQB_ERR_BOUNDS;
	return PQB_OK;
}

static void key_hash(const parsed_hdr *h, uint8_t out[48])
{
	pqb_sha384_ctx c;
	pqb_sha384_init(&c);
	pqb_sha384_update(&c, h->cpk, h->cpk_len);
	pqb_sha384_update(&c, h->pqpk, h->pqpk_len);
	pqb_sha384_final(&c, out);
}

static pqb_status_t pq_verify(const parsed_hdr *h)
{
	if (h->pq_alg == PQB_PQ_MLDSA87)
		return pqb_mldsa87_verify(h->pqpk, h->hdr, PQB_HDR_SIZE,
					  (const uint8_t *)PQB_MLDSA_CTX,
					  sizeof(PQB_MLDSA_CTX) - 1, h->pqsig);
	if (h->pq_alg == PQB_PQ_LMS)
		return pqb_lms_verify(h->pqpk, h->hdr, PQB_HDR_SIZE,
				      h->pqsig, h->pqsig_len);
	return PQB_ERR_POLICY;
}

#if PQB_HARDEN
/* A redundant check disagreed with the first one: treat as an attack. */
static pqb_status_t fault(uint32_t site)
{
	pqb_port_fault_detected(site);
	return PQB_ERR_FAULT;
}
#endif

static pqb_status_t verify_common(const uint8_t *img, size_t len,
				  const uint8_t *ext_payload, size_t ext_len,
				  const pqb_trust_anchor *ta,
				  pqb_image_info *info)
{
	parsed_hdr h;
	uint8_t kh[48], hd[48], dg[48];
	uint32_t flow = 0, ctr = 0;
	pqb_status_t st;

	memset(info, 0, sizeof(*info));
	if (img == NULL || ta == NULL)
		return PQB_ERR;

	/* 1. structure */
	st = parse(img, len, ext_payload, ext_len, ta, &h);
	if (st != PQB_OK)
		return st;
	flow += FLOW_PARSE;

	/* 2. key manifest hash vs trust anchor */
	key_hash(&h, kh);
	if (!PQB_CHECK(SITE_KEYHASH_1, pqb_ct_equal(kh, ta->key_hash, 48)))
		return PQB_ERR_KEY;
#if PQB_HARDEN
	memset(kh, 0, sizeof(kh));
	key_hash(&h, kh);                    /* recompute, don't reuse */
	if (!PQB_CHECK(SITE_KEYHASH_2, pqb_ct_equal(kh, ta->key_hash, 48)))
		return fault(SITE_KEYHASH_2);
#endif
	flow += FLOW_KEYHASH;

	/* 3. classical signature: ECDSA-P384 over SHA-384(header) */
	pqb_sha384(h.hdr, PQB_HDR_SIZE, hd);
	st = pqb_port_ecdsa_p384_verify(h.cpk, hd, h.csig);
	if (!PQB_CHECK(SITE_CLASSIC_1, st == PQB_OK))
		return PQB_ERR_SIG_CLASSIC;
#if PQB_HARDEN
	st = PQB_ERR;
	pqb_sha384(h.hdr, PQB_HDR_SIZE, hd);
	st = pqb_port_ecdsa_p384_verify(h.cpk, hd, h.csig);
	if (!PQB_CHECK(SITE_CLASSIC_2, st == PQB_OK))
		return fault(SITE_CLASSIC_2);
#endif
	flow += FLOW_CLASSIC;

	/* 4. post-quantum signature over the header */
	st = pq_verify(&h);
	if (!PQB_CHECK(SITE_PQ_1, st == PQB_OK))
		return PQB_ERR_SIG_PQ;
#if PQB_HARDEN
	st = PQB_ERR;
	st = pq_verify(&h);                  /* full second verification */
	if (!PQB_CHECK(SITE_PQ_2, st == PQB_OK))
		return fault(SITE_PQ_2);
#endif
	flow += FLOW_PQ;

	/* 5. payload binding */
	pqb_sha384(h.payload, h.payload_size, dg);
	if (!PQB_CHECK(SITE_DIGEST_1, pqb_ct_equal(dg, h.payload_digest, 48)))
		return PQB_ERR_DIGEST;
#if PQB_HARDEN
	memset(dg, 0, sizeof(dg));
	pqb_sha384(h.payload, h.payload_size, dg);
	if (!PQB_CHECK(SITE_DIGEST_2, pqb_ct_equal(dg, h.payload_digest, 48)))
		return fault(SITE_DIGEST_2);
#endif
	flow += FLOW_DIGEST;

	/* 6. anti-rollback */
	if (pqb_port_rollback_read(h.type == PQB_IMG_TEST ? 0 : h.type, &ctr) != PQB_OK)
		return PQB_ERR_PORT;
	if (!PQB_CHECK(SITE_ROLLBACK_1, h.secver >= ctr))
		return PQB_ERR_ROLLBACK;
#if PQB_HARDEN
	ctr = 0xFFFFFFFFu;
	if (pqb_port_rollback_read(h.type == PQB_IMG_TEST ? 0 : h.type, &ctr) != PQB_OK)
		return PQB_ERR_PORT;
	if (!PQB_CHECK(SITE_ROLLBACK_2, h.secver >= ctr))
		return fault(SITE_ROLLBACK_2);
#endif
	flow += FLOW_ROLLBACK;

	/* 7. every mandatory step ran exactly once */
#if PQB_HARDEN
	if (!PQB_CHECK(SITE_FLOW, flow == FLOW_EXPECTED))
		return fault(SITE_FLOW);
#endif

	info->image_type = h.type;
	info->security_version = h.secver;
	info->load_addr = h.load;
	info->entry_point = h.entry;
	info->payload = h.payload;
	info->payload_size = h.payload_size;
	info->pq_alg = h.pq_alg;
	pqb_sha384(h.hdr, PQB_HDR_SIZE, info->measurement);

	if (PQB_CHECK(SITE_FINAL, flow == FLOW_EXPECTED))
		return PQB_OK;
	return PQB_ERR_FAULT;
}

pqb_status_t pqb_image_verify(const uint8_t *img, size_t len,
			      const pqb_trust_anchor *ta,
			      pqb_image_info *info)
{
	return verify_common(img, len, NULL, 0, ta, info);
}

pqb_status_t pqb_image_verify_detached(const uint8_t *blob, size_t blob_len,
				       const uint8_t *payload, size_t payload_len,
				       const pqb_trust_anchor *ta,
				       pqb_image_info *info)
{
	if (payload == NULL) {
		memset(info, 0, sizeof(*info));
		return PQB_ERR;
	}
	return verify_common(blob, blob_len, payload, payload_len, ta, info);
}

pqb_status_t pqb_image_verify_trailer(const uint8_t *buf, size_t len,
				      const pqb_trust_anchor *ta,
				      pqb_image_info *info)
{
	size_t blob_len;

	memset(info, 0, sizeof(*info));
	if (buf == NULL || len < 8)
		return PQB_ERR_BOUNDS;
	if (!pqb_ct_equal(buf + len - 8, (const uint8_t *)PQB_TRAILER_MAGIC, 4))
		return PQB_ERR_FORMAT;
	blob_len = pqb_load_le32(buf + len - 4);
	if (blob_len < PQB_HDR_SIZE || blob_len > len - 8)
		return PQB_ERR_BOUNDS;
	return pqb_image_verify_detached(buf + (len - 8 - blob_len), blob_len,
					 buf, len - 8 - blob_len, ta, info);
}
