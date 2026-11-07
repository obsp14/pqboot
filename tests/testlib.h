/* testlib.h - tiny test helpers (no framework dependency) */
#ifndef PQB_TESTLIB_H
#define PQB_TESTLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int t_fail, t_pass;
static char t_dir[512];

#define CHECK(cond, ...)                                                   \
	do {                                                               \
		if (cond) {                                                \
			t_pass++;                                          \
		} else {                                                   \
			t_fail++;                                          \
			printf("  FAIL %s:%d: ", __FILE__, __LINE__);      \
			printf(__VA_ARGS__);                               \
			printf("\n");                                      \
		}                                                          \
	} while (0)

static uint8_t *t_read(const char *name, size_t *len)
{
	char path[1024];
	FILE *f;
	uint8_t *b;
	long n;

	snprintf(path, sizeof(path), "%s/%s", t_dir, name);
	f = fopen(path, "rb");
	if (!f) {
		printf("missing vector %s (run `make vectors`)\n", path);
		exit(2);
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	b = malloc((size_t)n + 1);
	if (fread(b, 1, (size_t)n, f) != (size_t)n)
		exit(2);
	fclose(f);
	b[n] = 0;
	*len = (size_t)n;
	return b;
}

static size_t t_unhex(const char *h, uint8_t *out, size_t max)
{
	size_t n = 0;
	if (h[0] == '-' && h[1] == 0)
		return 0;
	while (h[0] && h[1] && n < max) {
		unsigned v;
		if (sscanf(h, "%2x", &v) != 1)
			break;
		out[n++] = (uint8_t)v;
		h += 2;
	}
	return n;
}

static int t_summary(const char *name)
{
	printf("%s: %d passed, %d failed\n", name, t_pass, t_fail);
	return t_fail ? 1 : 0;
}

#endif
