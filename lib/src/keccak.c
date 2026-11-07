/*
 * keccak.c - Keccak-f[1600] sponge: SHA3-256, SHA3-384, SHAKE128, SHAKE256
 * (FIPS 202). Straightforward reference implementation, little-endian lanes.
 */
#include "pqb/hash.h"

static const uint64_t RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned ROTC[24] = {
	1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const unsigned PILN[24] = {
	10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static void keccakf(uint64_t st[25])
{
	uint64_t bc[5], t;
	int r, i, j;

	for (r = 0; r < 24; r++) {
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = (int)PILN[i];
			bc[0] = st[j];
			st[j] = ROL64(t, ROTC[i]);
			t = bc[0];
		}
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}
		st[0] ^= RC[r];
	}
}

static void xor_byte(uint64_t st[25], size_t idx, uint8_t b)
{
	st[idx / 8] ^= (uint64_t)b << (8 * (idx % 8));
}

static uint8_t get_byte(const uint64_t st[25], size_t idx)
{
	return (uint8_t)(st[idx / 8] >> (8 * (idx % 8)));
}

static void keccak_init(pqb_keccak_ctx *c, size_t rate, uint8_t ds)
{
	memset(c->s, 0, sizeof(c->s));
	c->rate = rate;
	c->pos = 0;
	c->dsbyte = ds;
	c->squeezing = 0;
}

void pqb_shake128_init(pqb_keccak_ctx *c) { keccak_init(c, 168, 0x1F); }
void pqb_shake256_init(pqb_keccak_ctx *c) { keccak_init(c, 136, 0x1F); }

void pqb_keccak_absorb(pqb_keccak_ctx *c, const void *data, size_t n)
{
	const uint8_t *p = (const uint8_t *)data;

	/* Absorbing after squeezing is a programming error; ignore silently
	 * would hide bugs, so we restart is not allowed either. Callers in this
	 * library never do it. */
	while (n--) {
		xor_byte(c->s, c->pos++, *p++);
		if (c->pos == c->rate) {
			keccakf(c->s);
			c->pos = 0;
		}
	}
}

static void keccak_finalize(pqb_keccak_ctx *c)
{
	xor_byte(c->s, c->pos, c->dsbyte);
	xor_byte(c->s, c->rate - 1, 0x80);
	keccakf(c->s);
	c->pos = 0;
	c->squeezing = 1;
}

void pqb_keccak_squeeze(pqb_keccak_ctx *c, uint8_t *out, size_t n)
{
	if (!c->squeezing)
		keccak_finalize(c);
	while (n--) {
		if (c->pos == c->rate) {
			keccakf(c->s);
			c->pos = 0;
		}
		*out++ = get_byte(c->s, c->pos++);
	}
}

void pqb_shake256(const void *in, size_t inlen, uint8_t *out, size_t outlen)
{
	pqb_keccak_ctx c;
	pqb_shake256_init(&c);
	pqb_keccak_absorb(&c, in, inlen);
	pqb_keccak_squeeze(&c, out, outlen);
}

void pqb_sha3_256(const void *in, size_t inlen, uint8_t out[32])
{
	pqb_keccak_ctx c;
	keccak_init(&c, 136, 0x06);
	pqb_keccak_absorb(&c, in, inlen);
	pqb_keccak_squeeze(&c, out, 32);
}

void pqb_sha3_384(const void *in, size_t inlen, uint8_t out[48])
{
	pqb_keccak_ctx c;
	keccak_init(&c, 104, 0x06);
	pqb_keccak_absorb(&c, in, inlen);
	pqb_keccak_squeeze(&c, out, 48);
}
