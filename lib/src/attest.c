/*
 * attest.c - build the to-be-signed part of an attestation quote
 */
#include "pqb/attest.h"

size_t pqb_quote_tbs_len(const pqb_dice_state *s)
{
	return PQB_QUOTE_HDR_LEN + (size_t)s->count * PQB_QUOTE_EVENT_LEN + 97u;
}

size_t pqb_quote_build_tbs(const pqb_dice_state *s, const uint8_t nonce[32],
			   const uint8_t alias_pub[97],
			   uint8_t *out, size_t outlen)
{
	size_t need, off;
	uint32_t i;

	if (pqb_dice_validate(s) != PQB_OK)
		return 0;
	need = pqb_quote_tbs_len(s);
	if (outlen < need)
		return 0;

	memcpy(out, PQB_QUOTE_MAGIC, 4);
	pqb_store_le32(out + 4, PQB_QUOTE_VERSION);
	memcpy(out + 8, nonce, 32);
	memcpy(out + 40, s->pcr, PQB_SHA384_LEN);
	pqb_store_le32(out + 88, s->count);
	off = PQB_QUOTE_HDR_LEN;
	for (i = 0; i < s->count; i++) {
		pqb_store_le32(out + off, s->log[i].image_type);
		pqb_store_le32(out + off + 4, s->log[i].security_version);
		memcpy(out + off + 8, s->log[i].measurement, PQB_SHA384_LEN);
		off += PQB_QUOTE_EVENT_LEN;
	}
	memcpy(out + off, alias_pub, 97);
	off += 97;
	return off;
}
