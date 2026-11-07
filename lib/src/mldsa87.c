/*
 * mldsa87.c - ML-DSA-87 verification, written directly from FIPS 204.
 *
 * Section/algorithm numbers in comments refer to FIPS 204 (August 2024).
 * Arithmetic is plain modular arithmetic on int64 (no Montgomery tricks):
 * slower than the optimised reference code, but every line maps onto the
 * standard, which is the point of a learning implementation. Verification
 * handles only public data, so constant-time arithmetic is not required.
 *
 * Memory: the matrix A_hat (8 x 7 polynomials, 224 KiB as int64) is never
 * stored. Each row is expanded on the fly while computing A_hat * NTT(z).
 */
#include "pqb/mldsa87.h"
#include "pqb/hash.h"

#define N       256
#define Q       8380417
#define D       13
#define K       8
#define L       7
#define TAU     60
#define GAMMA1  (1 << 19)
#define GAMMA2  ((Q - 1) / 32)
#define BETA    (TAU * 2)          /* tau * eta, eta = 2 */
#define OMEGA   75
#define CTILDE  64                 /* lambda / 4 bytes, lambda = 256 */

#define T1_POLY_BYTES   320        /* 256 coeffs * 10 bits / 8 */
#define Z_POLY_BYTES    640        /* 256 coeffs * 20 bits / 8 */
#define W1_POLY_BYTES   128        /* 256 coeffs * 4 bits / 8  */

typedef struct { int32_t c[N]; } poly;

/*
 * Large working buffers (~13 KiB). Boot stages such as TF-A BL1/BL2 run on
 * 4-8 KiB stacks, so -DPQB_MLDSA_STATIC_WS places them in .bss instead.
 * That makes verification non-reentrant, which is fine in single-threaded
 * boot code. Host builds keep them on the stack (reentrant, thread-safe).
 */
typedef struct {
	poly zhat[L];
	poly chat, acc, tmp;
	uint8_t hint[K][N];
} mldsa_ws;

/* ------------------------------------------------------------------ */
/* Modular helpers                                                    */
/* ------------------------------------------------------------------ */
static int32_t mod_q(int64_t a)
{
	int64_t r = a % Q;
	return (int32_t)(r < 0 ? r + Q : r);
}

/* zetas[i] = 1753^{brv8(i)} mod q  (FIPS 204 Appendix B) */
static const int32_t ZETAS[N] = {
	      1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
	7778734, 3542485, 2682288, 2129892, 3764867, 7375178,  557458, 7159240,
	5010068, 4317364, 2663378, 6705802, 4855975, 7946292,  676590, 7044481,
	5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
	3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
	 394148,  928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
	3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
	5483103, 3192354,  556856, 3870317, 2917338, 1853806, 3345963, 1858416,
	3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
	2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
	1528066,  482649, 1148858, 5418153, 7814814,  169688, 2462444, 5046034,
	4213992, 4892034, 1987814, 5183169, 1736313,  235407, 5130263, 3258457,
	5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
	7062739, 2461387, 3035980,  621164, 3901472, 7153756, 2925816, 3374250,
	1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
	 348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
	   1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
	1182243,   87208,  636927, 4415111, 4423672, 6084020, 5095502, 4663471,
	8352605,  822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
	6695264, 4969849, 2678278, 4611469, 4829411,  635956, 8129971, 5925040,
	4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
	3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
	2998219,  141835, 8291116, 2513018, 7025525,  613238, 7070156, 6161950,
	7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
	6757063, 2105286, 6006015, 6346610,  586241, 7200804,  527981, 5637006,
	6903432, 1994046, 2491325, 6987258,  507927, 7192532, 7655613, 6545891,
	5346675, 8041997, 2647994, 3009748, 5767564, 4148469,  749577, 4357667,
	3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
	3994671, 8368538, 7009900, 3020393, 3363542,  214880,  545376, 7609976,
	3105558, 7277073,  508145, 7826699,  860144, 3430436,  140244, 6866265,
	6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
	8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

/* Algorithm 41: NTT */
static void ntt(poly *w)
{
	int len, start, j, m = 0;
	for (len = 128; len >= 1; len >>= 1) {
		for (start = 0; start < N; start += 2 * len) {
			int64_t z = ZETAS[++m];
			for (j = start; j < start + len; j++) {
				int32_t t = mod_q(z * w->c[j + len]);
				w->c[j + len] = mod_q((int64_t)w->c[j] - t);
				w->c[j] = mod_q((int64_t)w->c[j] + t);
			}
		}
	}
}

/* Algorithm 42: NTT^-1 */
static void intt(poly *w)
{
	int len, start, j, m = N;
	const int64_t f = 8347681; /* 256^-1 mod q */
	for (len = 1; len < N; len <<= 1) {
		for (start = 0; start < N; start += 2 * len) {
			int64_t z = Q - ZETAS[--m];
			for (j = start; j < start + len; j++) {
				int32_t t = w->c[j];
				w->c[j] = mod_q((int64_t)t + w->c[j + len]);
				w->c[j + len] = mod_q((int64_t)t - w->c[j + len]);
				w->c[j + len] = mod_q(z * w->c[j + len]);
			}
		}
	}
	for (j = 0; j < N; j++)
		w->c[j] = mod_q(f * w->c[j]);
}

/* ------------------------------------------------------------------ */
/* Sampling                                                           */
/* ------------------------------------------------------------------ */

/* Algorithm 30: RejNTTPoly(rho || s || r) using SHAKE128 */
static void rej_ntt_poly(poly *a, const uint8_t rho[32], uint8_t s, uint8_t r)
{
	pqb_keccak_ctx x;
	uint8_t seed[34], b[3];
	int j = 0;

	memcpy(seed, rho, 32);
	seed[32] = s;
	seed[33] = r;
	pqb_shake128_init(&x);
	pqb_keccak_absorb(&x, seed, sizeof(seed));
	while (j < N) {
		uint32_t v;
		pqb_keccak_squeeze(&x, b, 3);
		v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)(b[2] & 0x7F) << 16);
		if (v < Q)
			a->c[j++] = (int32_t)v;
	}
}

/* Algorithm 29: SampleInBall(c_tilde) -> c with TAU coefficients = +-1 */
static void sample_in_ball(poly *c, const uint8_t ct[CTILDE])
{
	pqb_keccak_ctx x;
	uint8_t s[8], jb;
	uint64_t h = 0;
	int i, k;

	memset(c, 0, sizeof(*c));
	pqb_shake256_init(&x);
	pqb_keccak_absorb(&x, ct, CTILDE);
	pqb_keccak_squeeze(&x, s, 8);
	for (k = 0; k < 8; k++)
		h |= (uint64_t)s[k] << (8 * k);
	for (i = N - TAU; i < N; i++) {
		do {
			pqb_keccak_squeeze(&x, &jb, 1);
		} while (jb > i);
		c->c[i] = c->c[jb];
		c->c[jb] = ((h >> (i + TAU - N)) & 1) ? Q - 1 : 1;
	}
}

/* ------------------------------------------------------------------ */
/* Encodings                                                          */
/* ------------------------------------------------------------------ */

/* SimpleBitUnpack with 10-bit coefficients (t1). */
static void unpack_t1(poly *t, const uint8_t *b)
{
	int i;
	for (i = 0; i < N / 4; i++) {
		const uint8_t *p = b + 5 * i;
		t->c[4 * i + 0] = (int32_t)(((p[0] >> 0) | ((uint32_t)p[1] << 8)) & 0x3FF);
		t->c[4 * i + 1] = (int32_t)(((p[1] >> 2) | ((uint32_t)p[2] << 6)) & 0x3FF);
		t->c[4 * i + 2] = (int32_t)(((p[2] >> 4) | ((uint32_t)p[3] << 4)) & 0x3FF);
		t->c[4 * i + 3] = (int32_t)(((p[3] >> 6) | ((uint32_t)p[4] << 2)) & 0x3FF);
	}
}

/* BitUnpack(z, gamma1-1, gamma1): 20-bit values v, coefficient = gamma1 - v.
 * Result is centred, in [-(gamma1-1), gamma1]. */
static void unpack_z(poly *z, const uint8_t *b)
{
	int i;
	for (i = 0; i < N / 2; i++) {
		const uint8_t *p = b + 5 * i;
		uint32_t v0 = ((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
			       ((uint32_t)p[2] << 16)) & 0xFFFFF;
		uint32_t v1 = (((uint32_t)p[2] >> 4) | ((uint32_t)p[3] << 4) |
			       ((uint32_t)p[4] << 12)) & 0xFFFFF;
		z->c[2 * i + 0] = GAMMA1 - (int32_t)v0;
		z->c[2 * i + 1] = GAMMA1 - (int32_t)v1;
	}
}

/* Algorithm 21: HintBitUnpack. Returns 0 on success, -1 if malformed. */
static int unpack_hint(uint8_t (*h)[N], const uint8_t y[OMEGA + K])
{
	unsigned idx = 0, i, first;

	memset(h, 0, (size_t)K * N);
	for (i = 0; i < K; i++) {
		if (y[OMEGA + i] < idx || y[OMEGA + i] > OMEGA)
			return -1;
		first = idx;
		while (idx < y[OMEGA + i]) {
			if (idx > first && y[idx - 1] >= y[idx])
				return -1;   /* indices must be strictly increasing */
			h[i][y[idx]] = 1;
			idx++;
		}
	}
	for (i = idx; i < OMEGA; i++)
		if (y[i] != 0)
			return -1;       /* unused slots must be zero */
	return 0;
}

/* Algorithm 36: Decompose; Algorithm 40: UseHint (gamma2 = (q-1)/32, m = 16) */
static int32_t use_hint(uint8_t hint, int32_t r)
{
	int32_t rp = mod_q(r);
	int32_t r0 = rp % (2 * GAMMA2);
	int32_t r1;

	if (r0 > GAMMA2)
		r0 -= 2 * GAMMA2;                  /* r0 = r+ mod+- 2*gamma2 */
	if (rp - r0 == Q - 1) {
		r1 = 0;
		r0 -= 1;
	} else {
		r1 = (rp - r0) / (2 * GAMMA2);
	}
	if (!hint)
		return r1;
	if (r0 > 0)
		return (r1 + 1) & 15;
	return (r1 - 1) & 15;
}

/* ------------------------------------------------------------------ */
/* Algorithm 8: ML-DSA.Verify_internal (+ Algorithm 3 wrapper)        */
/* ------------------------------------------------------------------ */
pqb_status_t pqb_mldsa87_verify(const uint8_t pk[PQB_MLDSA87_PK_BYTES],
				const uint8_t *msg, size_t msglen,
				const uint8_t *ctx, size_t ctxlen,
				const uint8_t sig[PQB_MLDSA87_SIG_BYTES])
{
	const uint8_t *rho = pk;
	const uint8_t *t1b = pk + 32;
	const uint8_t *ct = sig;
	const uint8_t *zb = sig + CTILDE;
	const uint8_t *hb = sig + CTILDE + L * Z_POLY_BYTES;
#ifdef PQB_MLDSA_STATIC_WS
	static mldsa_ws ws;
#else
	mldsa_ws ws;
#endif
	poly *zhat = ws.zhat, *chat = &ws.chat, *acc = &ws.acc, *tmp = &ws.tmp;
	uint8_t (*hint)[N] = ws.hint;
	uint8_t tr[64], mu[64], ct2[CTILDE], w1buf[W1_POLY_BYTES];
	uint8_t pre[2];
	pqb_keccak_ctx x;
	int i, j, r, s;
	uint32_t diff = 0;

	if (ctxlen > 255)
		return PQB_ERR_FORMAT;

	/* sigDecode: hint first (cheap rejection of malformed signatures) */
	if (unpack_hint(hint, hb) != 0)
		return PQB_ERR_SIG_PQ;

	/* z: decode, check infinity norm, transform to NTT domain */
	for (s = 0; s < L; s++) {
		unpack_z(&zhat[s], zb + s * Z_POLY_BYTES);
		for (j = 0; j < N; j++) {
			int32_t v = zhat[s].c[j];
			if (v >= GAMMA1 - BETA || v <= -(GAMMA1 - BETA))
				return PQB_ERR_SIG_PQ;
			zhat[s].c[j] = mod_q(v);
		}
		ntt(&zhat[s]);
	}

	/* tr = H(pk, 64); mu = H(tr || M', 64), M' = 0 || |ctx| || ctx || M */
	pqb_shake256(pk, PQB_MLDSA87_PK_BYTES, tr, sizeof(tr));
	pre[0] = 0;
	pre[1] = (uint8_t)ctxlen;
	pqb_shake256_init(&x);
	pqb_keccak_absorb(&x, tr, sizeof(tr));
	pqb_keccak_absorb(&x, pre, 2);
	if (ctxlen)
		pqb_keccak_absorb(&x, ctx, ctxlen);
	pqb_keccak_absorb(&x, msg, msglen);
	pqb_keccak_squeeze(&x, mu, sizeof(mu));

	/* c = SampleInBall(c_tilde), chat = NTT(c) */
	sample_in_ball(chat, ct);
	ntt(chat);

	/* c_tilde' = H(mu || w1Encode(w1'), 64), absorbed row by row */
	pqb_shake256_init(&x);
	pqb_keccak_absorb(&x, mu, sizeof(mu));

	for (r = 0; r < K; r++) {
		/* acc = sum_s A_hat[r][s] * zhat[s] */
		memset(acc, 0, sizeof(*acc));
		for (s = 0; s < L; s++) {
			rej_ntt_poly(tmp, rho, (uint8_t)s, (uint8_t)r);
			for (j = 0; j < N; j++)
				acc->c[j] = mod_q((int64_t)acc->c[j] +
						  (int64_t)tmp->c[j] * zhat[s].c[j]);
		}
		/* tmp = NTT(t1[r] * 2^d); acc -= chat * tmp */
		unpack_t1(tmp, t1b + r * T1_POLY_BYTES);
		for (j = 0; j < N; j++)
			tmp->c[j] = mod_q((int64_t)tmp->c[j] << D);
		ntt(tmp);
		for (j = 0; j < N; j++)
			acc->c[j] = mod_q((int64_t)acc->c[j] -
					  (int64_t)chat->c[j] * tmp->c[j]);
		intt(acc);

		/* w1' = UseHint(h, w'_approx); w1Encode packs 4-bit values */
		for (j = 0; j < N; j += 2) {
			int32_t a = use_hint(hint[r][j], acc->c[j]);
			int32_t b = use_hint(hint[r][j + 1], acc->c[j + 1]);
			w1buf[j / 2] = (uint8_t)(a | (b << 4));
		}
		pqb_keccak_absorb(&x, w1buf, sizeof(w1buf));
	}
	pqb_keccak_squeeze(&x, ct2, sizeof(ct2));

	/* Compare without early exit (habit for security code). */
	for (i = 0; i < CTILDE; i++)
		diff |= (uint32_t)(ct[i] ^ ct2[i]);
	return diff == 0 ? PQB_OK : PQB_ERR_SIG_PQ;
}
