/*
 * lms.c - LMS / LM-OTS verification (RFC 8554 sections 4.6 and 5.4.2)
 */
#include "pqb/lms.h"
#include "pqb/hash.h"

#define LMS_N 32u
#define D_PBLC 0x8080u
#define D_MESG 0x8181u
#define D_LEAF 0x8282u
#define D_INTR 0x8383u

struct ots_params { uint32_t type; unsigned w, p, ls; };
struct lms_params { uint32_t type; unsigned h; };

static const struct ots_params OTS[] = {
	{ PQB_LMOTS_SHA256_N32_W4, 4, 67, 4 },
	{ PQB_LMOTS_SHA256_N32_W8, 8, 34, 0 },
};
static const struct lms_params LMSP[] = {
	{ PQB_LMS_SHA256_M32_H5, 5 },
	{ PQB_LMS_SHA256_M32_H10, 10 },
};

static const struct ots_params *find_ots(uint32_t t)
{
	size_t i;
	for (i = 0; i < sizeof(OTS) / sizeof(OTS[0]); i++)
		if (OTS[i].type == t)
			return &OTS[i];
	return NULL;
}

static const struct lms_params *find_lms(uint32_t t)
{
	size_t i;
	for (i = 0; i < sizeof(LMSP) / sizeof(LMSP[0]); i++)
		if (LMSP[i].type == t)
			return &LMSP[i];
	return NULL;
}

/* RFC 8554 section 3.1.3: coef(S, i, w) */
static unsigned coef(const uint8_t *S, unsigned i, unsigned w)
{
	unsigned mask = (1u << w) - 1u;
	unsigned byte = S[(i * w) / 8u];
	unsigned shift = 8u - (w * (i % (8u / w)) + w);
	return (byte >> shift) & mask;
}

size_t pqb_lms_sig_len(const uint8_t pk[PQB_LMS_PK_BYTES])
{
	const struct lms_params *lp = find_lms(pqb_load_be32(pk));
	const struct ots_params *op = find_ots(pqb_load_be32(pk + 4));
	if (!lp || !op)
		return 0;
	return 4u + (4u + LMS_N + op->p * LMS_N) + 4u + lp->h * LMS_N;
}

pqb_status_t pqb_lms_verify(const uint8_t pk[PQB_LMS_PK_BYTES],
			    const uint8_t *msg, size_t msglen,
			    const uint8_t *sig, size_t siglen)
{
	const struct lms_params *lp;
	const struct ots_params *op;
	const uint8_t *I = pk + 8, *T1 = pk + 24;
	const uint8_t *C, *y, *path;
	uint8_t Q[LMS_N + 2], tmp[LMS_N], Kc[LMS_N], pre[23];
	pqb_sha256_ctx h;
	uint32_t q, node, sum = 0, diff = 0;
	unsigned i, j, a, nchk, maxd;

	lp = find_lms(pqb_load_be32(pk));
	op = find_ots(pqb_load_be32(pk + 4));
	if (!lp || !op)
		return PQB_ERR_POLICY;
	if (siglen != pqb_lms_sig_len(pk))
		return PQB_ERR_FORMAT;

	/* signature = q || ots_type || C || y[p] || lms_type || path[h] */
	q = pqb_load_be32(sig);
	if (pqb_load_be32(sig + 4) != op->type)
		return PQB_ERR_SIG_PQ;
	C = sig + 8;
	y = C + LMS_N;
	if (pqb_load_be32(y + op->p * LMS_N) != lp->type)
		return PQB_ERR_SIG_PQ;
	path = y + op->p * LMS_N + 4;
	if (q >= (1u << lp->h))
		return PQB_ERR_SIG_PQ;

	/* ---- LM-OTS candidate public key (Algorithm 4b) ---- */
	memcpy(pre, I, 16);
	pqb_store_be32(pre + 16, q);
	pqb_store_be16(pre + 20, D_MESG);
	pqb_sha256_init(&h);
	pqb_sha256_update(&h, pre, 22);
	pqb_sha256_update(&h, C, LMS_N);
	pqb_sha256_update(&h, msg, msglen);
	pqb_sha256_final(&h, Q);

	maxd = (1u << op->w) - 1u;
	nchk = (LMS_N * 8u) / op->w;
	for (i = 0; i < nchk; i++)
		sum += maxd - coef(Q, i, op->w);
	sum <<= op->ls;
	Q[LMS_N] = (uint8_t)(sum >> 8);
	Q[LMS_N + 1] = (uint8_t)sum;

	{
		pqb_sha256_ctx kc;
		pqb_sha256_init(&kc);
		pqb_store_be16(pre + 20, D_PBLC);
		pqb_sha256_update(&kc, pre, 22);
		for (i = 0; i < op->p; i++) {
			a = coef(Q, i, op->w);
			memcpy(tmp, y + i * LMS_N, LMS_N);
			for (j = a; j < maxd; j++) {
				pqb_store_be16(pre + 20, (uint16_t)i);
				pre[22] = (uint8_t)j;
				pqb_sha256_init(&h);
				pqb_sha256_update(&h, pre, 23);
				pqb_sha256_update(&h, tmp, LMS_N);
				pqb_sha256_final(&h, tmp);
			}
			pqb_sha256_update(&kc, tmp, LMS_N);
		}
		pqb_sha256_final(&kc, Kc);
	}

	/* ---- Merkle path to the root (Algorithm 6a) ---- */
	node = (1u << lp->h) + q;
	pqb_store_be32(pre + 16, node);
	pqb_store_be16(pre + 20, D_LEAF);
	pqb_sha256_init(&h);
	pqb_sha256_update(&h, pre, 22);
	pqb_sha256_update(&h, Kc, LMS_N);
	pqb_sha256_final(&h, tmp);

	for (i = 0; node > 1; i++, node >>= 1) {
		pqb_store_be32(pre + 16, node >> 1);
		pqb_store_be16(pre + 20, D_INTR);
		pqb_sha256_init(&h);
		pqb_sha256_update(&h, pre, 22);
		if (node & 1u) {
			pqb_sha256_update(&h, path + i * LMS_N, LMS_N);
			pqb_sha256_update(&h, tmp, LMS_N);
		} else {
			pqb_sha256_update(&h, tmp, LMS_N);
			pqb_sha256_update(&h, path + i * LMS_N, LMS_N);
		}
		pqb_sha256_final(&h, tmp);
	}

	for (i = 0; i < LMS_N; i++)
		diff |= (uint32_t)(tmp[i] ^ T1[i]);
	return diff == 0 ? PQB_OK : PQB_ERR_SIG_PQ;
}
