/*
 * pqb_attest.c - Linux user-space client: ask the OP-TEE PTA for a quote.
 *
 * STATUS: UNTESTED. Build with the OP-TEE client library:
 *   $(CROSS_COMPILE)gcc pqb_attest.c -lteec -o pqb_attest
 *
 *   pqb_attest <64-hex-char nonce> <quote-output-file>
 *
 * Copy the quote out of QEMU (e.g. via the 9p shared folder that the
 * OP-TEE QEMU build sets up with QEMU_VIRTFS_ENABLE=y) and check it on
 * the host with:  python3 -m pqsign verify-quote ...
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#define PTA_PQB_ATTEST_UUID { 0x6f6e7f0c, 0x9a1e, 0x4c42, \
	{ 0x8d, 0x3a, 0x70, 0x71, 0x62, 0x3f, 0x41, 0x54 } }
#define PQB_CMD_GET_QUOTE 0

int main(int argc, char **argv)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = PTA_PQB_ATTEST_UUID;
	TEEC_Result res;
	uint32_t origin;
	uint8_t nonce[32], quote[2048];
	FILE *f;
	int i;

	if (argc != 3 || strlen(argv[1]) != 64) {
		fprintf(stderr, "usage: %s <nonce-hex64> <out-file>\n", argv[0]);
		return 2;
	}
	for (i = 0; i < 32; i++) {
		unsigned v;
		sscanf(argv[1] + 2 * i, "%2x", &v);
		nonce[i] = (uint8_t)v;
	}

	if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS)
		return 1;
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "open session failed 0x%x (origin %u)\n", res, origin);
		return 1;
	}
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = sizeof(nonce);
	op.params[1].tmpref.buffer = quote;
	op.params[1].tmpref.size = sizeof(quote);
	res = TEEC_InvokeCommand(&sess, PQB_CMD_GET_QUOTE, &op, &origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "get quote failed 0x%x (origin %u)\n", res, origin);
		return 1;
	}
	f = fopen(argv[2], "wb");
	if (!f || fwrite(quote, 1, op.params[1].tmpref.size, f) != op.params[1].tmpref.size)
		return 1;
	fclose(f);
	printf("quote: %zu bytes -> %s\n", op.params[1].tmpref.size, argv[2]);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
