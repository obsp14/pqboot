/*
 * dice.h - DICE-style layered measured boot (TCG DICE concepts, simplified)
 *
 * Every boot stage, before jumping to the next one:
 *   1. measures it:    M_n   = SHA-384(header of image n)
 *   2. derives:        CDI_n = HMAC-SHA384(CDI_{n-1}, "PQB-CDI-v1" || M_n)
 *                      (CDI_0 input is the UDS, a per-device fused secret)
 *   3. extends a PCR:  PCR   = SHA-384(PCR || M_n)
 *   4. logs (type, version, M_n), then WIPES CDI_{n-1} before handing off.
 *
 * Consequence: if any image changes, every later CDI changes, so keys
 * derived from it (attestation alias key, sealing keys) change too. A
 * compromised later stage can never recover an earlier stage's secret.
 *
 * Simplification vs. full DICE / Caliptra: no X.509 certificate chain per
 * layer. The quote carries the event log; the verifier replays it.
 */
#ifndef PQB_DICE_H
#define PQB_DICE_H

#include "pqb/common.h"
#include "pqb/hash.h"
#include "pqb/image.h"

#define PQB_DICE_MAX_EVENTS 8u
#define PQB_DICE_MAGIC      0x45434944u /* "DICE" */

typedef struct {
	uint32_t image_type;
	uint32_t security_version;
	uint8_t measurement[PQB_SHA384_LEN];
} pqb_dice_event;

/* Passed from stage to stage (e.g. in a TF-A/OP-TEE shared buffer). */
typedef struct {
	uint32_t magic;
	uint32_t count;
	uint8_t cdi[PQB_SHA384_LEN];
	uint8_t pcr[PQB_SHA384_LEN];
	pqb_dice_event log[PQB_DICE_MAX_EVENTS];
} pqb_dice_state;

/* First mutable stage: start from the Unique Device Secret. */
void pqb_dice_init(pqb_dice_state *s, const uint8_t uds[PQB_SHA384_LEN]);

/* Record a verified image and derive the next CDI. */
pqb_status_t pqb_dice_extend(pqb_dice_state *s, const pqb_image_info *img);

/* Derive a purpose-specific 48-byte seed: HMAC(CDI, label). */
void pqb_dice_derive(const pqb_dice_state *s, const char *label,
		     uint8_t out[PQB_SHA384_LEN]);

/* Hand-off sanity check used by the receiving stage. */
pqb_status_t pqb_dice_validate(const pqb_dice_state *s);

#endif /* PQB_DICE_H */
