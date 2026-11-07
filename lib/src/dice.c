/*
 * dice.c - layered CDI derivation, PCR extension and event log
 */
#include "pqb/dice.h"

#define CDI_LABEL "PQB-CDI-v1"

void pqb_dice_init(pqb_dice_state *s, const uint8_t uds[PQB_SHA384_LEN])
{
	memset(s, 0, sizeof(*s));
	s->magic = PQB_DICE_MAGIC;
	memcpy(s->cdi, uds, PQB_SHA384_LEN);   /* CDI_{-1} := UDS */
	/* PCR starts at all-zero, like a TPM PCR after reset. */
}

pqb_status_t pqb_dice_extend(pqb_dice_state *s, const pqb_image_info *img)
{
	uint8_t msg[sizeof(CDI_LABEL) - 1 + PQB_SHA384_LEN];
	uint8_t next[PQB_SHA384_LEN];
	uint8_t pcrin[2 * PQB_SHA384_LEN];
	pqb_dice_event *ev;

	if (pqb_dice_validate(s) != PQB_OK)
		return PQB_ERR_FORMAT;
	if (s->count >= PQB_DICE_MAX_EVENTS)
		return PQB_ERR_BOUNDS;

	/* CDI_n = HMAC(CDI_{n-1}, label || M_n) */
	memcpy(msg, CDI_LABEL, sizeof(CDI_LABEL) - 1);
	memcpy(msg + sizeof(CDI_LABEL) - 1, img->measurement, PQB_SHA384_LEN);
	pqb_hmac_sha384(s->cdi, PQB_SHA384_LEN, msg, sizeof(msg), next);
	pqb_wipe(s->cdi, sizeof(s->cdi));          /* forget the old secret */
	memcpy(s->cdi, next, sizeof(next));
	pqb_wipe(next, sizeof(next));

	/* PCR = SHA-384(PCR || M_n) */
	memcpy(pcrin, s->pcr, PQB_SHA384_LEN);
	memcpy(pcrin + PQB_SHA384_LEN, img->measurement, PQB_SHA384_LEN);
	pqb_sha384(pcrin, sizeof(pcrin), s->pcr);

	ev = &s->log[s->count++];
	ev->image_type = img->image_type;
	ev->security_version = img->security_version;
	memcpy(ev->measurement, img->measurement, PQB_SHA384_LEN);
	return PQB_OK;
}

void pqb_dice_derive(const pqb_dice_state *s, const char *label,
		     uint8_t out[PQB_SHA384_LEN])
{
	pqb_hmac_sha384(s->cdi, PQB_SHA384_LEN, (const uint8_t *)label,
			strlen(label), out);
}

pqb_status_t pqb_dice_validate(const pqb_dice_state *s)
{
	if (s->magic != PQB_DICE_MAGIC || s->count > PQB_DICE_MAX_EVENTS)
		return PQB_ERR_FORMAT;
	return PQB_OK;
}
