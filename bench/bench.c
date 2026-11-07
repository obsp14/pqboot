#define _POSIX_C_SOURCE 199309L
/*
 * bench.c - cost of classical vs post-quantum verification on the host.
 * Numbers on a Cortex-A53 at ~1 GHz will be roughly 5-15x slower; run the
 * same binary inside QEMU only for functional checks (QEMU timing is not
 * representative of silicon).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "host_port.h"
#include "pqb/hash.h"
#include "pqb/image.h"
#include "pqb/lms.h"
#include "pqb/mldsa87.h"

static double now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (double)t.tv_sec + (double)t.tv_nsec * 1e-9;
}

static uint8_t *rd(const char *dir, const char *name, size_t *n)
{
	char p[1024];
	FILE *f;
	uint8_t *b;
	long l;
	snprintf(p, sizeof(p), "%s/%s", dir, name);
	f = fopen(p, "rb");
	if (!f)
		exit(2);
	fseek(f, 0, SEEK_END);
	l = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)l + 1);
	if (fread(b, 1, (size_t)l, f) != (size_t)l)
		exit(2);
	fclose(f);
	b[l] = 0;
	*n = (size_t)l;
	return b;
}

#define RUN(label, iters, expr) do {                                        \
		double t0 = now(); int k_;                                  \
		for (k_ = 0; k_ < (iters); k_++) { if ((expr) != PQB_OK) {  \
			printf("%s failed\n", label); exit(1); } }          \
		printf("  %-34s %9.1f us\n", label,                          \
		       (now() - t0) * 1e6 / (iters));                       \
	} while (0)

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "build/vectors";
	size_t n, pl, ml, sl, i;
	uint8_t *img = rd(dir, "bl33.pqb", &n), *hx = rd(dir, "anchor_mldsa.hex", &pl);
	uint8_t *lpk = rd(dir, "lms_h5w4.pk", &pl), *lm = rd(dir, "lms_h5w4.msg", &ml);
	uint8_t *ls = rd(dir, "lms_h5w4.sig", &sl);
	uint8_t *lpk8 = rd(dir, "lms_h5w8.pk", &pl), *lm8 = rd(dir, "lms_h5w8.msg", &ml);
	uint8_t *ls8 = rd(dir, "lms_h5w8.sig", &sl);
	uint32_t payload = pqb_load_le32(img + 36);
	const uint8_t *cpk = img + 256 + payload, *pqpk = cpk + 97;
	const uint8_t *csig = pqpk + 2592, *pqsig = csig + 96;
	uint8_t hd[48];
	pqb_trust_anchor ta;
	pqb_image_info info;
	size_t lms_len8 = pqb_lms_sig_len(lpk8), lms_len = pqb_lms_sig_len(lpk);

	memset(&ta, 0, sizeof(ta));
	for (i = 0; i < 48; i++) {
		unsigned v;
		sscanf((char *)hx + 2 * i, "%2x", &v);
		ta.key_hash[i] = (uint8_t)v;
	}
	ta.allowed_pq_algs = 1u << PQB_PQ_MLDSA87;
	pqb_sha384(img, 256, hd);

	printf("signature sizes: ECDSA-P384 96 B | ML-DSA-87 %u B (pk %u B) | "
	       "LMS-H5/W4 %zu B | LMS-H5/W8 %zu B\n",
	       PQB_MLDSA87_SIG_BYTES, PQB_MLDSA87_PK_BYTES, lms_len, lms_len8);
	printf("verification time (host, %s):\n", "single core");
	RUN("ECDSA-P384 (OpenSSL)", 200, pqb_port_ecdsa_p384_verify(cpk, hd, csig));
	RUN("ML-DSA-87 (pqboot C)", 200,
	    pqb_mldsa87_verify(pqpk, img, 256, (const uint8_t *)PQB_MLDSA_CTX, 15, pqsig));
	RUN("LMS SHA256 H5/W4 (pqboot C)", 200, pqb_lms_verify(lpk, lm, ml, ls, lms_len));
	RUN("LMS SHA256 H5/W8 (pqboot C)", 50, pqb_lms_verify(lpk8, lm8, ml, ls8, lms_len8));
	{
		double t0 = now();
		int k;
		for (k = 0; k < 200; k++)
			pqb_sha384(img + 256, payload, hd);
		printf("  %-34s %9.1f us  (%u-byte payload)\n", "SHA-384 payload",
		       (now() - t0) * 1e6 / 200, payload);
	}
	RUN("full hardened image verify", 50, pqb_image_verify(img, n, &ta, &info));
	return 0;
}
