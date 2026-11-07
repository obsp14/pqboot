/*
 * sha384.c - FIPS 180-4 SHA-384 (SHA-512 core, truncated) and HMAC-SHA384
 */
#include "pqb/hash.h"

static const uint64_t K512[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t load_be64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;
	for (i = 0; i < 8; i++)
		v = (v << 8) | p[i];
	return v;
}

static void sha512_block(uint64_t h[8], const uint8_t *p)
{
	uint64_t w[80], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = load_be64(p + 8 * i);
	for (i = 16; i < 80; i++) {
		uint64_t s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
		uint64_t s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 80; i++) {
		uint64_t S1 = ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41);
		uint64_t ch = (e & f) ^ (~e & g);
		uint64_t S0 = ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39);
		uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		t1 = hh + S1 + ch + K512[i] + w[i];
		t2 = S0 + maj;
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void pqb_sha384_init(pqb_sha384_ctx *c)
{
	static const uint64_t iv[8] = {
		0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
		0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
		0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
	};
	memcpy(c->h, iv, sizeof(iv));
	c->len_lo = 0;
	c->len_hi = 0;
	c->fill = 0;
}

void pqb_sha384_update(pqb_sha384_ctx *c, const void *data, size_t n)
{
	const uint8_t *p = (const uint8_t *)data;
	uint64_t old = c->len_lo;

	c->len_lo += (uint64_t)n;
	if (c->len_lo < old)
		c->len_hi++;
	if (c->fill) {
		size_t take = 128 - c->fill;
		if (take > n)
			take = n;
		memcpy(c->buf + c->fill, p, take);
		c->fill += take;
		p += take;
		n -= take;
		if (c->fill == 128) {
			sha512_block(c->h, c->buf);
			c->fill = 0;
		}
	}
	while (n >= 128) {
		sha512_block(c->h, p);
		p += 128;
		n -= 128;
	}
	if (n) {
		memcpy(c->buf, p, n);
		c->fill = n;
	}
}

void pqb_sha384_final(pqb_sha384_ctx *c, uint8_t out[PQB_SHA384_LEN])
{
	uint64_t hi = (c->len_hi << 3) | (c->len_lo >> 61);
	uint64_t lo = c->len_lo << 3;
	uint8_t pad = 0x80, zero = 0, lenbuf[16];
	int i;

	pqb_sha384_update(c, &pad, 1);
	while (c->fill != 112)
		pqb_sha384_update(c, &zero, 1);
	for (i = 0; i < 8; i++) {
		lenbuf[i] = (uint8_t)(hi >> (56 - 8 * i));
		lenbuf[8 + i] = (uint8_t)(lo >> (56 - 8 * i));
	}
	pqb_sha384_update(c, lenbuf, 16);
	for (i = 0; i < 6; i++) {
		int j;
		for (j = 0; j < 8; j++)
			out[8 * i + j] = (uint8_t)(c->h[i] >> (56 - 8 * j));
	}
	pqb_wipe(c, sizeof(*c));
}

void pqb_sha384(const void *data, size_t n, uint8_t out[PQB_SHA384_LEN])
{
	pqb_sha384_ctx c;
	pqb_sha384_init(&c);
	pqb_sha384_update(&c, data, n);
	pqb_sha384_final(&c, out);
}

/* RFC 2104 HMAC with SHA-384 (block size 128 bytes). */
void pqb_hmac_sha384(const uint8_t *key, size_t keylen,
		     const uint8_t *msg, size_t msglen,
		     uint8_t out[PQB_SHA384_LEN])
{
	uint8_t k0[128], pad[128], inner[PQB_SHA384_LEN];
	pqb_sha384_ctx c;
	size_t i;

	memset(k0, 0, sizeof(k0));
	if (keylen > sizeof(k0))
		pqb_sha384(key, keylen, k0);
	else
		memcpy(k0, key, keylen);

	for (i = 0; i < 128; i++)
		pad[i] = k0[i] ^ 0x36;
	pqb_sha384_init(&c);
	pqb_sha384_update(&c, pad, 128);
	pqb_sha384_update(&c, msg, msglen);
	pqb_sha384_final(&c, inner);

	for (i = 0; i < 128; i++)
		pad[i] = k0[i] ^ 0x5c;
	pqb_sha384_init(&c);
	pqb_sha384_update(&c, pad, 128);
	pqb_sha384_update(&c, inner, sizeof(inner));
	pqb_sha384_final(&c, out);

	pqb_wipe(k0, sizeof(k0));
	pqb_wipe(pad, sizeof(pad));
	pqb_wipe(inner, sizeof(inner));
}

void pqb_wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;
	while (n--)
		*v++ = 0;
}
