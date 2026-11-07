/*
 * fuzz_image.c - fuzz target for the image parser / verifier.
 *
 * Works with libFuzzer (clang -fsanitize=fuzzer,address) AND with the
 * bundled standalone_driver.c (any compiler, ASan+UBSan).
 *
 * The fuzzer cannot forge signatures, so most inputs die in parse() or at
 * the key-hash check. That is exactly the attack surface that matters:
 * the code that runs on attacker bytes BEFORE any signature is verified.
 * To reach deeper code, the trust anchor is set to the key hash of the
 * keys embedded in the input itself (when the layout parses), so mutated
 * signatures and payloads also exercise ECDSA / ML-DSA / LMS decoding.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "host_port.h"
#include "pqb/hash.h"
#include "pqb/image.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	pqb_trust_anchor ta;
	pqb_image_info info;
	uint8_t *copy;
	uint32_t psz;
	size_t off;

	/* Copy into an exact-size heap buffer so ASan catches 1-byte overreads */
	copy = malloc(size ? size : 1);
	if (!copy)
		return 0;
	memcpy(copy, data, size);

	memset(&ta, 0, sizeof(ta));
	ta.allowed_pq_algs = (1u << PQB_PQ_MLDSA87) | (1u << PQB_PQ_LMS);

	/* Self-consistent anchor: hash whatever key bytes the header points at */
	if (size >= PQB_HDR_SIZE) {
		psz = pqb_load_le32(copy + 36);
		off = PQB_HDR_SIZE + (size_t)psz;
		if (psz <= size && off <= size) {
			size_t cl = pqb_load_le16(copy + 88), ql = pqb_load_le16(copy + 90);
			if (cl + ql <= size - off) {
				pqb_sha384_ctx c;
				pqb_sha384_init(&c);
				pqb_sha384_update(&c, copy + off, cl + ql);
				pqb_sha384_final(&c, ta.key_hash);
			}
		}
	}
	(void)pqb_image_verify(copy, size, &ta, &info);
	(void)pqb_image_verify_trailer(copy, size, &ta, &info);
	free(copy);
	return 0;
}
