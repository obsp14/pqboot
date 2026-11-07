/*
 * attest.h - attestation quote ("PQBQ") serialisation
 *
 * A verifier sends a fresh 32-byte nonce. The device returns:
 *
 *   0    magic "PQBQ"
 *   4    u32 version (=1)
 *   8    u8  nonce[32]
 *   40   u8  pcr[48]
 *   88   u32 event_count
 *   92   event_count * { u32 type, u32 secver, u8 measurement[48] }  (56 each)
 *   ...  u8  alias_pub[97]   (ECDSA-P384 key derived from the final CDI)
 *   ...  u8  signature[96]   (ECDSA-P384 r||s over SHA-384(all bytes above))
 *
 * Because the alias key is derived from the CDI, a device running a
 * modified image produces a DIFFERENT alias key; the verifier pins the
 * expected alias key at enrolment (or checks it against golden values).
 * The signature itself is produced by the platform (OpenSSL in the
 * simulator, mbedTLS inside the OP-TEE TA).
 */
#ifndef PQB_ATTEST_H
#define PQB_ATTEST_H

#include "pqb/dice.h"

#define PQB_QUOTE_MAGIC     "PQBQ"
#define PQB_QUOTE_VERSION   1u
#define PQB_QUOTE_HDR_LEN   92u
#define PQB_QUOTE_EVENT_LEN 56u
#define PQB_ALIAS_LABEL     "PQB-ALIAS-ECDSA-P384"

/* Size of the to-be-signed part for a given state. */
size_t pqb_quote_tbs_len(const pqb_dice_state *s);

/*
 * Serialise the to-be-signed part (everything except the signature) into
 * out. Returns the number of bytes written, or 0 if outlen is too small.
 */
size_t pqb_quote_build_tbs(const pqb_dice_state *s, const uint8_t nonce[32],
			   const uint8_t alias_pub[97],
			   uint8_t *out, size_t outlen);

#endif /* PQB_ATTEST_H */
