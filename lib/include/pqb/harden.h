/*
 * harden.h - fault-injection countermeasures and the simulation hook.
 *
 * Threat: an attacker glitches voltage/clock (or uses a laser) so ONE
 * instruction misbehaves - typically a conditional branch goes the wrong
 * way - and a bad image is accepted. Countermeasures used in pqboot:
 *
 *   1. Non-trivial status values (PQB_OK = 0x3CA5965A), compared exactly.
 *   2. Every security decision is evaluated twice from independently
 *      recomputed inputs (PQB_HARDEN=1). A single fault flips only one.
 *   3. A flow counter: each mandatory step adds a distinct constant, and
 *      success requires the exact total, so skipping a step is detected.
 *
 * PQB_CHECK(site, cond) wraps every security-relevant condition. In normal
 * builds it is just (cond). With -DPQB_FAULT_SIM it calls pqb_fi_eval(),
 * which lets the fault-injection harness (faultinj/) invert the outcome
 * of exactly one chosen site, emulating a single-glitch attacker.
 */
#ifndef PQB_HARDEN_H
#define PQB_HARDEN_H

#include "pqb/common.h"

#ifndef PQB_HARDEN
#define PQB_HARDEN 1
#endif

#ifdef PQB_FAULT_SIM
int pqb_fi_eval(uint32_t site, int cond);
#define PQB_CHECK(site, cond) pqb_fi_eval((site), (cond) ? 1 : 0)
#else
#define PQB_CHECK(site, cond) ((cond) ? 1 : 0)
#endif

/* Constant-time equality: returns 1 if equal. No early exit. */
static inline int pqb_ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint32_t d = 0;
	size_t i;
	for (i = 0; i < n; i++)
		d |= (uint32_t)(a[i] ^ b[i]);
	/* (d - 1) >> 31 is 1 iff d == 0, without a data-dependent branch */
	return (int)((d - 1u) >> 31);
}

/* Fault-check sites (stable numbers so harness reports are readable). */
enum pqb_site {
	SITE_MAGIC = 1, SITE_HDR_VERSION, SITE_HDR_SIZE, SITE_RESERVED,
	SITE_ALG_ALLOWED, SITE_LENGTHS, SITE_TOTAL_LEN,
	SITE_KEYHASH_1, SITE_KEYHASH_2,
	SITE_CLASSIC_1, SITE_CLASSIC_2,
	SITE_PQ_1, SITE_PQ_2,
	SITE_DIGEST_1, SITE_DIGEST_2,
	SITE_ROLLBACK_1, SITE_ROLLBACK_2,
	SITE_FLOW, SITE_FINAL,
	SITE_MAX
};

#endif /* PQB_HARDEN_H */
