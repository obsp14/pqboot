/*
 * test_image.c - image policy, tamper resistance, rollback, DICE, quote
 */
#include "testlib.h"

#include "host_port.h"
#include "pqb/attest.h"
#include "pqb/dice.h"
#include "pqb/image.h"

static pqb_trust_anchor ta_mldsa, ta_lms;

static void load_anchor(const char *file, pqb_trust_anchor *ta, uint32_t alg)
{
	size_t l;
	uint8_t *h = t_read(file, &l);
	memset(ta, 0, sizeof(*ta));
	t_unhex((char *)h, ta->key_hash, 48);
	ta->allowed_pq_algs = 1u << alg;
	free(h);
}

static pqb_status_t verify(const uint8_t *img, size_t n, const pqb_trust_anchor *ta)
{
	pqb_image_info info;
	return pqb_image_verify(img, n, ta, &info);
}

static void test_good(void)
{
	const char *names[] = { "bl2.pqb", "bl31.pqb", "bl32.pqb", "bl33.pqb" };
	uint32_t types[] = { 1, 2, 3, 4 }, vers[] = { 2, 3, 1, 5 };
	size_t i, n;

	printf("good images\n");
	for (i = 0; i < 4; i++) {
		pqb_image_info info;
		uint8_t *img = t_read(names[i], &n);
		pqb_status_t st = pqb_image_verify(img, n, &ta_mldsa, &info);
		CHECK(st == PQB_OK, "%s rejected: 0x%08x", names[i], st);
		CHECK(info.image_type == types[i], "%s type", names[i]);
		CHECK(info.security_version == vers[i], "%s version", names[i]);
		CHECK(info.payload == img + 256, "%s payload pointer", names[i]);
		CHECK(info.pq_alg == PQB_PQ_MLDSA87, "%s pq alg", names[i]);
		free(img);
	}
	{
		uint8_t *img = t_read("test_lms.pqb", &n);
		CHECK(verify(img, n, &ta_lms) == PQB_OK, "LMS image rejected");
		/* policy: ML-DSA-only anchor must refuse an LMS image */
		CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_POLICY, "LMS accepted by ML-DSA policy");
		free(img);
	}
}

/* Flip one bit in every region of the image; every flip must be rejected. */
static void test_tamper(void)
{
	size_t n, i;
	uint8_t *img = t_read("bl31.pqb", &n);
	uint32_t payload = pqb_load_le32(img + 36);
	struct { const char *what; size_t off; } spots[] = {
		{ "magic", 0 }, { "type", 8 }, { "pq_alg", 12 }, { "version", 16 },
		{ "load_addr", 20 }, { "entry", 28 }, { "payload_size", 36 },
		{ "payload_digest", 60 }, { "len fields", 90 }, { "reserved", 200 },
		{ "payload first", 256 }, { "payload mid", 256 + 3000 },
		{ "payload last", 256 + (size_t)payload - 1 },
		{ "classic pk", 256 + (size_t)payload + 10 },
		{ "pq pk", 256 + (size_t)payload + 97 + 1000 },
		{ "classic sig", 256 + (size_t)payload + 97 + 2592 + 5 },
		{ "pq sig", 256 + (size_t)payload + 97 + 2592 + 96 + 2000 },
		{ "last byte", 0 },
	};
	spots[sizeof(spots) / sizeof(spots[0]) - 1].off = n - 1;

	printf("tamper (single-bit flips)\n");
	for (i = 0; i < sizeof(spots) / sizeof(spots[0]); i++) {
		pqb_status_t st;
		img[spots[i].off] ^= 0x10;
		st = verify(img, n, &ta_mldsa);
		CHECK(st != PQB_OK, "flip in %s accepted", spots[i].what);
		img[spots[i].off] ^= 0x10;
	}
	CHECK(verify(img, n, &ta_mldsa) == PQB_OK, "restored image rejected");

	/* Specific error classes for the regions with a dedicated check */
	img[300] ^= 1;
	CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_DIGEST, "payload -> DIGEST");
	img[300] ^= 1;
	img[256 + payload + 97 + 2592 + 5] ^= 1;
	CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_SIG_CLASSIC, "csig -> SIG_CLASSIC");
	img[256 + payload + 97 + 2592 + 5] ^= 1;
	img[n - 100] ^= 1;
	CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_SIG_PQ, "pqsig -> SIG_PQ");
	img[n - 100] ^= 1;
	img[256 + payload + 10] ^= 1;
	CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_KEY, "cpk -> KEY");
	img[256 + payload + 10] ^= 1;
	free(img);
}

static void test_bounds(void)
{
	size_t n;
	uint8_t *img = t_read("bl2.pqb", &n);
	uint8_t *big = malloc(n + 1);

	printf("bounds\n");
	CHECK(verify(img, 0, &ta_mldsa) == PQB_ERR_BOUNDS, "empty");
	CHECK(verify(img, 255, &ta_mldsa) == PQB_ERR_BOUNDS, "short header");
	CHECK(verify(img, n - 1, &ta_mldsa) == PQB_ERR_BOUNDS, "truncated by 1");
	memcpy(big, img, n);
	big[n] = 0;
	CHECK(verify(big, n + 1, &ta_mldsa) == PQB_ERR_BOUNDS, "trailing byte");
	/* payload_size = 0xFFFFFFFF must not wrap */
	pqb_store_le32(big + 36, 0xFFFFFFFFu);
	CHECK(verify(big, n, &ta_mldsa) == PQB_ERR_BOUNDS, "huge payload size");
	/* payload_size just below the limit but larger than the buffer */
	memcpy(big, img, n);
	pqb_store_le32(big + 36, 0x00FFFFFFu);
	CHECK(verify(big, n, &ta_mldsa) == PQB_ERR_BOUNDS, "payload past end");
	/* pq_sig_len = 0xFFFF */
	memcpy(big, img, n);
	big[94] = 0xFF;
	big[95] = 0xFF;
	CHECK(verify(big, n, &ta_mldsa) == PQB_ERR_BOUNDS, "pq sig len past end");
	CHECK(verify(NULL, n, &ta_mldsa) == PQB_ERR, "NULL image");
	free(big);
	free(img);
}

static void test_policy_and_rollback(void)
{
	size_t n;
	uint8_t *img = t_read("bl31.pqb", &n);   /* version 3 */
	pqb_trust_anchor bad = ta_mldsa;

	printf("trust anchor, policy, rollback\n");
	bad.key_hash[0] ^= 1;
	CHECK(verify(img, n, &bad) == PQB_ERR_KEY, "foreign key accepted");
	bad = ta_mldsa;
	bad.allowed_pq_algs = 1u << PQB_PQ_LMS;
	CHECK(verify(img, n, &bad) == PQB_ERR_POLICY, "disallowed alg accepted");

	host_rollback_set(PQB_IMG_BL31, 3);
	CHECK(verify(img, n, &ta_mldsa) == PQB_OK, "version == counter must boot");
	host_rollback_set(PQB_IMG_BL31, 4);
	CHECK(verify(img, n, &ta_mldsa) == PQB_ERR_ROLLBACK, "rollback accepted");
	host_rollback_set(PQB_IMG_BL31, 0);
	CHECK(host_fault_count() == 0, "no fault events in normal operation");
	free(img);
}

static void test_dice_and_quote(void)
{
	const char *names[] = { "bl2.pqb", "bl31.pqb", "bl32.pqb", "bl33.pqb" };
	pqb_dice_state s, s2;
	uint8_t uds[48], want_pcr[48], want_alias[97], seed[48], alias[97], nonce[32];
	uint8_t tbs[1024];
	size_t i, n, l;
	char *exp = (char *)t_read("dice_expected.txt", &l);
	char *p;

	printf("DICE + attestation\n");
	p = strstr(exp, "pcr ");
	t_unhex(p + 4, want_pcr, 48);
	p = strstr(exp, "alias ");
	t_unhex(p + 6, want_alias, 97);

	memset(uds, 0xA5, sizeof(uds));
	pqb_dice_init(&s, uds);
	for (i = 0; i < 4; i++) {
		pqb_image_info info;
		uint8_t *img = t_read(names[i], &n);
		CHECK(pqb_image_verify(img, n, &ta_mldsa, &info) == PQB_OK, "chain %zu", i);
		CHECK(pqb_dice_extend(&s, &info) == PQB_OK, "extend %zu", i);
		free(img);
	}
	CHECK(s.count == 4, "event count");
	CHECK(memcmp(s.pcr, want_pcr, 48) == 0, "PCR matches Python model");
	pqb_dice_derive(&s, PQB_ALIAS_LABEL, seed);
	CHECK(host_ecdsa_from_seed(seed, alias) == PQB_OK, "alias derive");
	CHECK(memcmp(alias, want_alias, 97) == 0, "alias key matches Python model");

	/* different UDS => different CDI => different alias key */
	uds[0] ^= 1;
	pqb_dice_init(&s2, uds);
	memcpy(s2.log, s.log, sizeof(s.log));
	for (i = 0; i < 4; i++) {
		pqb_image_info info;
		memset(&info, 0, sizeof(info));
		memcpy(info.measurement, s.log[i].measurement, 48);
		pqb_dice_extend(&s2, &info);
	}
	CHECK(memcmp(s.cdi, s2.cdi, 48) != 0, "CDI depends on UDS");
	CHECK(memcmp(s.pcr, s2.pcr, 48) == 0, "PCR independent of UDS");

	memset(nonce, 0x42, sizeof(nonce));
	n = pqb_quote_build_tbs(&s, nonce, alias, tbs, sizeof(tbs));
	CHECK(n == 92 + 4 * 56 + 97, "quote tbs length %zu", n);
	CHECK(memcmp(tbs, "PQBQ", 4) == 0 && memcmp(tbs + 8, nonce, 32) == 0, "quote header");
	CHECK(pqb_quote_build_tbs(&s, nonce, alias, tbs, 10) == 0, "small buffer refused");

	/* overflow of the event log is refused */
	{
		pqb_image_info info;
		memset(&info, 0, sizeof(info));
		while (s.count < PQB_DICE_MAX_EVENTS)
			pqb_dice_extend(&s, &info);
		CHECK(pqb_dice_extend(&s, &info) == PQB_ERR_BOUNDS, "log overflow");
	}
	free(exp);
}

static void test_detached_trailer(void)
{
	size_t n, tn;
	uint8_t *img = t_read("bl31.pqb", &n);
	uint8_t *tr = t_read("bl31_trailer.bin", &tn);
	uint32_t payload = pqb_load_le32(img + 36);
	uint8_t *blob = malloc(n - payload);
	pqb_image_info a, b;

	printf("detached + trailer forms\n");
	memcpy(blob, img, 256);
	memcpy(blob + 256, img + 256 + payload, n - 256 - payload);
	CHECK(pqb_image_verify_detached(blob, n - payload, img + 256, payload,
					&ta_mldsa, &a) == PQB_OK, "detached rejected");
	CHECK(pqb_image_verify_detached(blob, n - payload, img + 256, payload - 1,
					&ta_mldsa, &b) == PQB_ERR_BOUNDS, "detached size mismatch");
	CHECK(pqb_image_verify_detached(blob, n - payload, NULL, payload,
					&ta_mldsa, &b) == PQB_ERR, "detached NULL payload");
	CHECK(pqb_image_verify_trailer(tr, tn, &ta_mldsa, &b) == PQB_OK, "trailer rejected");
	CHECK(b.payload == tr && b.payload_size == payload, "trailer payload at offset 0");
	CHECK(memcmp(a.measurement, b.measurement, 48) == 0, "same measurement in all forms");
	tr[5] ^= 1;
	CHECK(pqb_image_verify_trailer(tr, tn, &ta_mldsa, &b) == PQB_ERR_DIGEST, "trailer payload tamper");
	tr[5] ^= 1;
	tr[tn - 1] = 0xFF;
	CHECK(pqb_image_verify_trailer(tr, tn, &ta_mldsa, &b) == PQB_ERR_BOUNDS, "trailer huge len");
	tr[tn - 8] = 'X';
	CHECK(pqb_image_verify_trailer(tr, tn, &ta_mldsa, &b) == PQB_ERR_FORMAT, "trailer magic");
	CHECK(pqb_image_verify_trailer(tr, 7, &ta_mldsa, &b) == PQB_ERR_BOUNDS, "trailer tiny");
	free(blob);
	free(img);
	free(tr);
}

int main(int argc, char **argv)
{
	snprintf(t_dir, sizeof(t_dir), "%s", argc > 1 ? argv[1] : "build/vectors");
	load_anchor("anchor_mldsa.hex", &ta_mldsa, PQB_PQ_MLDSA87);
	load_anchor("anchor_lms.hex", &ta_lms, PQB_PQ_LMS);
	test_good();
	test_tamper();
	test_bounds();
	test_policy_and_rollback();
	test_dice_and_quote();
	test_detached_trailer();
	return t_summary("test_image");
}
