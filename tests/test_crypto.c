/*
 * test_crypto.c - hash, ML-DSA-87 and LMS verification against vectors
 * produced by independent implementations (see tests/gen_vectors.py).
 */
#include "testlib.h"

#include "pqb/hash.h"
#include "pqb/lms.h"
#include "pqb/mldsa87.h"

static void test_hashes(void)
{
	size_t len;
	char *txt = (char *)t_read("hash_vectors.txt", &len);
	char *line = strtok(txt, "\n");
	static uint8_t msg[4096], key[256], want[256], got[256];
	int n = 0;

	printf("hashes\n");
	while (line) {
		char alg[512], mh[8192], dh[1024];
		size_t ml, dl, kl = 0;

		if (sscanf(line, "%511s %8191s %1023s", alg, mh, dh) != 3)
			break;
		ml = t_unhex(mh, msg, sizeof(msg));
		dl = t_unhex(dh, want, sizeof(want));
		if (!strcmp(alg, "sha256")) {
			pqb_sha256(msg, ml, got);
		} else if (!strcmp(alg, "sha384")) {
			pqb_sha384(msg, ml, got);
		} else if (!strcmp(alg, "sha3_256")) {
			pqb_sha3_256(msg, ml, got);
		} else if (!strcmp(alg, "sha3_384")) {
			pqb_sha3_384(msg, ml, got);
		} else if (!strcmp(alg, "shake256")) {
			pqb_shake256(msg, ml, got, dl);
		} else if (!strncmp(alg, "hmac384:", 8)) {
			kl = t_unhex(alg + 8, key, sizeof(key));
			pqb_hmac_sha384(key, kl, msg, ml, got);
		}
		CHECK(memcmp(got, want, dl) == 0, "%s len=%zu", alg, ml);
		n++;
		line = strtok(NULL, "\n");
	}
	CHECK(n >= 80, "parsed only %d hash vectors", n);
	free(txt);
}

static void test_mldsa(void)
{
	size_t l, count, i;
	char name[64];
	uint8_t *pk = t_read("mldsa.pk", &l);
	uint8_t *cnt = t_read("mldsa_count", &l);

	printf("ML-DSA-87\n");
	count = (size_t)atoi((char *)cnt);
	for (i = 0; i < count; i++) {
		size_t ml, cl, sl;
		uint8_t *m, *c, *s;

		snprintf(name, sizeof(name), "mldsa_%zu.msg", i);
		m = t_read(name, &ml);
		snprintf(name, sizeof(name), "mldsa_%zu.ctx", i);
		c = t_read(name, &cl);
		snprintf(name, sizeof(name), "mldsa_%zu.sig", i);
		s = t_read(name, &sl);

		CHECK(sl == PQB_MLDSA87_SIG_BYTES, "sig length");
		CHECK(pqb_mldsa87_verify(pk, m, ml, c, cl, s) == PQB_OK,
		      "valid signature %zu rejected", i);

		/* wrong context */
		CHECK(pqb_mldsa87_verify(pk, m, ml, (const uint8_t *)"other", 5, s) != PQB_OK,
		      "accepted with wrong context %zu", i);
		/* message modified */
		if (ml) {
			m[0] ^= 1;
			CHECK(pqb_mldsa87_verify(pk, m, ml, c, cl, s) != PQB_OK,
			      "accepted modified message %zu", i);
			m[0] ^= 1;
		}
		/* flip one bit in c_tilde, z and the hint area */
		{
			size_t pos[] = { 0, 63, 64, 2000, 4543, 4544, 4626 };
			size_t k;
			for (k = 0; k < sizeof(pos) / sizeof(pos[0]); k++) {
				s[pos[k]] ^= 0x01;
				CHECK(pqb_mldsa87_verify(pk, m, ml, c, cl, s) != PQB_OK,
				      "accepted sig %zu with bit flip at %zu", i, pos[k]);
				s[pos[k]] ^= 0x01;
			}
		}
		/* malformed hint: index count above omega */
		s[PQB_MLDSA87_SIG_BYTES - 1] = 200;
		CHECK(pqb_mldsa87_verify(pk, m, ml, c, cl, s) != PQB_OK, "malformed hint accepted");
		/* context longer than 255 */
		CHECK(pqb_mldsa87_verify(pk, m, ml, c, 256, s) == PQB_ERR_FORMAT, "ctx > 255");
		free(m);
		free(c);
		free(s);
	}
	/* wrong public key */
	{
		size_t ml, cl, sl;
		uint8_t *m = t_read("mldsa_1.msg", &ml), *c = t_read("mldsa_1.ctx", &cl);
		uint8_t *s = t_read("mldsa_1.sig", &sl);
		pk[100] ^= 0x80;
		CHECK(pqb_mldsa87_verify(pk, m, ml, c, cl, s) != PQB_OK, "accepted with wrong pk");
		free(m);
		free(c);
		free(s);
	}
	free(pk);
	free(cnt);
}

static void test_lms_one(const char *tag)
{
	char name[64];
	size_t pl, ml, sl;
	uint8_t *pk, *m, *s;

	snprintf(name, sizeof(name), "lms_%s.pk", tag);
	pk = t_read(name, &pl);
	snprintf(name, sizeof(name), "lms_%s.msg", tag);
	m = t_read(name, &ml);
	snprintf(name, sizeof(name), "lms_%s.sig", tag);
	s = t_read(name, &sl);

	CHECK(pl == PQB_LMS_PK_BYTES, "lms pk length");
	CHECK(pqb_lms_sig_len(pk) == sl, "lms sig length %zu", sl);
	CHECK(pqb_lms_verify(pk, m, ml, s, sl) == PQB_OK, "LMS %s valid sig rejected", tag);
	m[0] ^= 1;
	CHECK(pqb_lms_verify(pk, m, ml, s, sl) != PQB_OK, "LMS %s modified msg accepted", tag);
	m[0] ^= 1;
	{
		size_t pos[] = { 3, 8, 40, 100, sl - 40, sl - 1 };
		size_t k;
		for (k = 0; k < sizeof(pos) / sizeof(pos[0]); k++) {
			s[pos[k]] ^= 0x04;
			CHECK(pqb_lms_verify(pk, m, ml, s, sl) != PQB_OK,
			      "LMS %s flip at %zu accepted", tag, pos[k]);
			s[pos[k]] ^= 0x04;
		}
	}
	CHECK(pqb_lms_verify(pk, m, ml, s, sl - 1) == PQB_ERR_FORMAT, "LMS short sig");
	/* q out of range */
	s[0] = 0xFF;
	CHECK(pqb_lms_verify(pk, m, ml, s, sl) != PQB_OK, "LMS q out of range");
	/* unsupported type */
	pk[3] = 0x09;
	CHECK(pqb_lms_verify(pk, m, ml, s, sl) == PQB_ERR_POLICY, "LMS unsupported type");
	free(pk);
	free(m);
	free(s);
}

int main(int argc, char **argv)
{
	snprintf(t_dir, sizeof(t_dir), "%s", argc > 1 ? argv[1] : "build/vectors");
	test_hashes();
	test_mldsa();
	printf("LMS\n");
	test_lms_one("h5w4");
	test_lms_one("h5w8");
	return t_summary("test_crypto");
}
