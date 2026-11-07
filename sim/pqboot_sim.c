/*
 * pqboot_sim.c - run the whole boot policy on the host.
 *
 * Simulates what BL1 -> BL2 -> BL31 -> BL32 -> BL33 do on QEMU: each stage
 * verifies the next image, measures it into the DICE state, then "jumps".
 * At the end it answers an attestation challenge with a signed quote.
 *
 *   pqboot-sim --key-hash HEX --allowed MASK [--rollback FILE]
 *              [--uds FILE] [--nonce HEX --quote OUT] [--alias-out OUT]
 *              IMAGE...
 *
 * Exit code 0 = every image verified, 1 = boot halted, 2 = usage error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_port.h"
#include "pqb/attest.h"
#include "pqb/dice.h"
#include "pqb/image.h"

static const char *type_name(uint32_t t)
{
	switch (t) {
	case PQB_IMG_BL2: return "BL2 ";
	case PQB_IMG_BL31: return "BL31";
	case PQB_IMG_BL32: return "BL32";
	case PQB_IMG_BL33: return "BL33";
	case PQB_IMG_KERNEL: return "KERN";
	default: return "IMG ";
	}
}

static const char *status_name(pqb_status_t s)
{
	switch (s) {
	case PQB_OK: return "OK";
	case PQB_ERR_FORMAT: return "malformed header";
	case PQB_ERR_BOUNDS: return "size/offset out of bounds";
	case PQB_ERR_DIGEST: return "payload digest mismatch";
	case PQB_ERR_SIG_CLASSIC: return "ECDSA-P384 signature invalid";
	case PQB_ERR_SIG_PQ: return "post-quantum signature invalid";
	case PQB_ERR_ROLLBACK: return "rollback: version below counter";
	case PQB_ERR_KEY: return "signing key not trusted";
	case PQB_ERR_POLICY: return "algorithm not allowed by policy";
	case PQB_ERR_FAULT: return "fault detected (redundant check mismatch)";
	default: return "error";
	}
}

static int hex2bin(const char *h, uint8_t *out, size_t n)
{
	size_t i;
	if (strlen(h) != 2 * n)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(h + 2 * i, "%2x", &v) != 1)
			return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static uint8_t *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	long n;

	if (!f)
		return NULL;
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(n > 0 ? (size_t)n : 1);
	if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
		free(buf);
		buf = NULL;
	}
	fclose(f);
	*len = (size_t)n;
	return buf;
}

static int write_file(const char *path, const uint8_t *b, size_t n)
{
	FILE *f = fopen(path, "wb");
	int ok;
	if (!f)
		return -1;
	ok = fwrite(b, 1, n, f) == n;
	fclose(f);
	return ok ? 0 : -1;
}

static void print_hex(const uint8_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
}

int main(int argc, char **argv)
{
	pqb_trust_anchor ta;
	pqb_dice_state dice;
	uint8_t uds[48], nonce[32], seed[48], alias[97], digest[48], sig[96];
	const char *quote_out = NULL, *alias_out = NULL;
	int have_key = 0, have_nonce = 0, i, first_img = -1;

	memset(&ta, 0, sizeof(ta));
	memset(uds, 0xA5, sizeof(uds));   /* demo UDS if none given */

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--key-hash") && i + 1 < argc) {
			if (hex2bin(argv[++i], ta.key_hash, 48))
				return 2;
			have_key = 1;
		} else if (!strcmp(argv[i], "--allowed") && i + 1 < argc) {
			ta.allowed_pq_algs = (uint32_t)strtoul(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--rollback") && i + 1 < argc) {
			if (host_rollback_load(argv[++i]) != PQB_OK) {
				fprintf(stderr, "cannot read rollback file\n");
				return 2;
			}
		} else if (!strcmp(argv[i], "--uds") && i + 1 < argc) {
			size_t n;
			uint8_t *b = read_file(argv[++i], &n);
			if (!b || n != 48) {
				fprintf(stderr, "UDS must be 48 bytes\n");
				return 2;
			}
			memcpy(uds, b, 48);
			free(b);
		} else if (!strcmp(argv[i], "--nonce") && i + 1 < argc) {
			if (hex2bin(argv[++i], nonce, 32))
				return 2;
			have_nonce = 1;
		} else if (!strcmp(argv[i], "--quote") && i + 1 < argc) {
			quote_out = argv[++i];
		} else if (!strcmp(argv[i], "--alias-out") && i + 1 < argc) {
			alias_out = argv[++i];
		} else if (argv[i][0] == '-') {
			fprintf(stderr, "unknown option %s\n", argv[i]);
			return 2;
		} else {
			first_img = i;
			break;
		}
	}
	if (!have_key || first_img < 0) {
		fprintf(stderr, "usage: pqboot-sim --key-hash HEX --allowed MASK "
				"[--rollback F] [--uds F] [--nonce HEX --quote OUT] IMAGE...\n");
		return 2;
	}

	pqb_dice_init(&dice, uds);
	pqb_wipe(uds, sizeof(uds));
	printf("[BL1 ] ROM: trust anchor key hash ");
	print_hex(ta.key_hash, 8);
	printf("...\n");

	for (i = first_img; i < argc; i++) {
		pqb_image_info info;
		pqb_status_t st;
		size_t n;
		uint8_t *img = read_file(argv[i], &n);

		if (!img) {
			printf("BOOT HALTED: cannot read %s\n", argv[i]);
			return 1;
		}
		st = pqb_image_verify(img, n, &ta, &info);
		if (st != PQB_OK) {
			printf("[%s] %s: REJECTED - %s\n", "????", argv[i], status_name(st));
			printf("BOOT HALTED\n");
			free(img);
			return 1;
		}
		pqb_dice_extend(&dice, &info);
		printf("[%s] verified v%u %-9s load=0x%llx measurement ",
		       type_name(info.image_type), info.security_version,
		       info.pq_alg == PQB_PQ_MLDSA87 ? "ML-DSA-87" : "LMS",
		       (unsigned long long)info.load_addr);
		print_hex(info.measurement, 8);
		printf("...\n");
		free(img);
	}
	printf("[BOOT] all %d images verified, PCR ", argc - first_img);
	print_hex(dice.pcr, 8);
	printf("...\n");

	/* Attestation: alias key derived from the final CDI. */
	pqb_dice_derive(&dice, PQB_ALIAS_LABEL, seed);
	if (host_ecdsa_from_seed(seed, alias) != PQB_OK)
		return 1;
	if (alias_out && write_file(alias_out, alias, sizeof(alias)))
		return 1;
	if (have_nonce && quote_out) {
		size_t tbs_len = pqb_quote_tbs_len(&dice);
		uint8_t *q = malloc(tbs_len + 96);
		if (!q || pqb_quote_build_tbs(&dice, nonce, alias, q, tbs_len) != tbs_len)
			return 1;
		pqb_sha384(q, tbs_len, digest);
		if (host_ecdsa_sign_seed(seed, digest, sig) != PQB_OK)
			return 1;
		memcpy(q + tbs_len, sig, 96);
		if (write_file(quote_out, q, tbs_len + 96))
			return 1;
		printf("[ATT ] quote (%zu bytes) signed by alias key ", tbs_len + 96);
		print_hex(alias + 1, 8);
		printf("... -> %s\n", quote_out);
		free(q);
	}
	pqb_wipe(seed, sizeof(seed));
	pqb_wipe(&dice, sizeof(dice));
	return 0;
}
