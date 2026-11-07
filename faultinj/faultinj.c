/*
 * faultinj.c - single-fault injection sweep.
 *
 * Attacker model: ONE glitch that makes ONE security-relevant condition
 * evaluate the wrong way (the classic "skip the branch" fault). Compiled
 * with -DPQB_FAULT_SIM, every PQB_CHECK(site, cond) in lib/src/image.c
 * calls pqb_fi_eval() below, which inverts the result for the targeted
 * site. We try every site, at every one of its evaluations, against a set
 * of malicious images, and count how many faults produce PQB_OK.
 *
 *   PQB_HARDEN=0 build : expect bypasses (each check is a single point)
 *   PQB_HARDEN=1 build : expect 0 bypasses (redundant checks + flow counter)
 *
 * On real hardware the same experiment is done with a ChipWhisperer or by
 * single-stepping QEMU under GDB and skipping instructions; see
 * faultinj/qemu_gdb_skip.py for the QEMU variant.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_port.h"
#include "pqb/harden.h"
#include "pqb/image.h"

static int fi_site = -1;      /* site to fault, -1 = none */
static int fi_nth = 0;        /* fault the nth evaluation of that site */
static int fi_seen = 0;
static int fi_fired = 0;

int pqb_fi_eval(uint32_t site, int cond)
{
	if ((int)site == fi_site && fi_seen++ == fi_nth) {
		fi_fired = 1;
		return !cond;
	}
	return cond;
}

static const char *SITE_NAMES[SITE_MAX] = {
	"", "magic", "hdr_version", "hdr_size", "reserved", "alg_allowed",
	"lengths", "total_len", "keyhash_1", "keyhash_2", "classic_1",
	"classic_2", "pq_1", "pq_2", "digest_1", "digest_2", "rollback_1",
	"rollback_2", "flow", "final"
};

static uint8_t *rd(const char *dir, const char *name, size_t *n)
{
	char p[1024];
	FILE *f;
	uint8_t *b;
	long l;
	snprintf(p, sizeof(p), "%s/%s", dir, name);
	f = fopen(p, "rb");
	if (!f) {
		fprintf(stderr, "missing %s\n", p);
		exit(2);
	}
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

struct attack {
	const char *name;
	uint8_t *img;
	size_t len;
	const pqb_trust_anchor *ta;
};

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "build/vectors";
	pqb_trust_anchor ta, foreign;
	struct attack at[6];
	size_t n, i, payload;
	uint8_t *good, *hx;
	int a, s, bypass_total = 0, faults_tried = 0, detected = 0;
	int site_bypass[SITE_MAX] = { 0 };

	hx = rd(dir, "anchor_mldsa.hex", &n);
	memset(&ta, 0, sizeof(ta));
	for (i = 0; i < 48; i++) {
		unsigned v;
		sscanf((char *)hx + 2 * i, "%2x", &v);
		ta.key_hash[i] = (uint8_t)v;
	}
	ta.allowed_pq_algs = 1u << PQB_PQ_MLDSA87;
	foreign = ta;
	foreign.key_hash[0] ^= 1;

	good = rd(dir, "bl31.pqb", &n);       /* version 3 */
	payload = pqb_load_le32(good + 36);

#define CLONE(k, label) do { at[k].name = label; at[k].len = n;          \
		at[k].img = malloc(n); memcpy(at[k].img, good, n);         \
		at[k].ta = &ta; } while (0)

	CLONE(0, "payload modified");      at[0].img[256 + 10] ^= 1;
	CLONE(1, "ECDSA sig corrupted");   at[1].img[256 + payload + 97 + 2592 + 3] ^= 1;
	CLONE(2, "ML-DSA sig corrupted");  at[2].img[n - 200] ^= 1;
	CLONE(3, "untrusted signing key"); at[3].ta = &foreign;
	CLONE(4, "rollback (counter=4)");
	CLONE(5, "reserved byte set");     at[5].img[150] = 1;

	printf("build: PQB_HARDEN=%d, %d fault sites, %d malicious images\n",
	       PQB_HARDEN, SITE_MAX - 1, 6);

	/* sanity: with no fault, every attack is rejected */
	for (a = 0; a < 6; a++) {
		pqb_image_info info;
		host_rollback_set(PQB_IMG_BL31, a == 4 ? 4 : 0);
		fi_site = -1;
		if (pqb_image_verify(at[a].img, at[a].len, at[a].ta, &info) == PQB_OK) {
			printf("BUG: attack '%s' accepted without any fault\n", at[a].name);
			return 2;
		}
	}

	for (a = 0; a < 6; a++) {
		host_rollback_set(PQB_IMG_BL31, a == 4 ? 4 : 0);
		for (s = 1; s < SITE_MAX; s++) {
			int nth;
			for (nth = 0; nth < 4; nth++) {
				pqb_image_info info;
				pqb_status_t st;
				fi_site = s;
				fi_nth = nth;
				fi_seen = 0;
				fi_fired = 0;
				host_fault_reset();
				st = pqb_image_verify(at[a].img, at[a].len, at[a].ta, &info);
				if (!fi_fired)
					break;          /* site evaluated fewer times */
				faults_tried++;
				if (host_fault_count())
					detected++;
				if (st == PQB_OK) {
					bypass_total++;
					site_bypass[s]++;
					printf("  BYPASS: '%s' accepted by faulting site %s (eval #%d)\n",
					       at[a].name, SITE_NAMES[s], nth);
				}
			}
		}
	}
	printf("faults injected: %d, redundancy alarms raised: %d, bypasses: %d\n",
	       faults_tried, detected, bypass_total);
	for (s = 1; s < SITE_MAX; s++)
		if (site_bypass[s])
			printf("  weak site %-12s : %d bypass(es)\n", SITE_NAMES[s], site_bypass[s]);
	printf("%s\n", bypass_total ? "RESULT: single-fault bypass POSSIBLE"
				    : "RESULT: no single fault bypasses verification");
	return bypass_total ? 1 : 0;
}
