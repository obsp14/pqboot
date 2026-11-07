#define _POSIX_C_SOURCE 200809L
/*
 * standalone_driver.c - minimal mutation fuzzer for environments without
 * libFuzzer. Loads a seed corpus, then for N seconds applies random
 * structure-aware mutations (bit flips, byte sets, interesting 16/32-bit
 * values at header length/offset fields, truncation, extension) and runs
 * the target. Crashes are caught by ASan/UBSan, which abort the process.
 *
 *   fuzz_image [-seconds=N] [-seed=S] CORPUS_DIR
 *
 * With clang + libFuzzer available, prefer:
 *   clang -fsanitize=fuzzer,address,undefined fuzz/fuzz_image.c ... -lcrypto
 */
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_SEEDS 64
#define MAX_LEN   (1u << 20)

static uint8_t *seeds[MAX_SEEDS];
static size_t seed_len[MAX_SEEDS];
static int nseeds;
static uint64_t rng = 0x9E3779B97F4A7C15ULL;

static uint64_t rnd(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static void load_corpus(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	char path[1024];

	if (!d) {
		perror(dir);
		exit(2);
	}
	while ((e = readdir(d)) && nseeds < MAX_SEEDS) {
		FILE *f;
		long n;
		if (e->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		f = fopen(path, "rb");
		if (!f)
			continue;
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		fseek(f, 0, SEEK_SET);
		if (n > 0 && n <= (long)MAX_LEN) {
			seeds[nseeds] = malloc((size_t)n);
			if (fread(seeds[nseeds], 1, (size_t)n, f) == (size_t)n)
				seed_len[nseeds++] = (size_t)n;
		}
		fclose(f);
	}
	closedir(d);
}

static size_t mutate(uint8_t *b, size_t n)
{
	static const uint32_t interesting[] = {
		0, 1, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x10000, 0x7FFFFFFF,
		0x80000000u, 0xFFFFFFFFu, 256, 2592, 4627, 97, 96, 56
	};
	/* header fields worth hitting: type, alg, sizes, length fields */
	static const size_t fields[] = { 4, 6, 8, 12, 14, 16, 36, 88, 90, 92, 94 };
	int k, rounds = 1 + (int)(rnd() % 4);

	for (k = 0; k < rounds; k++) {
		switch (rnd() % 7) {
		case 0: /* bit flip */
			if (n)
				b[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
			break;
		case 1: /* random byte */
			if (n)
				b[rnd() % n] = (uint8_t)rnd();
			break;
		case 2: { /* interesting value into a header field */
			size_t f = fields[rnd() % (sizeof(fields) / sizeof(fields[0]))];
			uint32_t v = interesting[rnd() % (sizeof(interesting) / sizeof(interesting[0]))];
			if (f + 4 <= n) {
				b[f] = (uint8_t)v;
				b[f + 1] = (uint8_t)(v >> 8);
				if (f != 4 && f != 6 && f != 12 && f != 14 && f < 88) {
					b[f + 2] = (uint8_t)(v >> 16);
					b[f + 3] = (uint8_t)(v >> 24);
				}
			}
			break;
		}
		case 3: /* truncate */
			if (n)
				n = (size_t)(rnd() % n);
			break;
		case 4: /* extend with garbage */
			if (n + 64 <= MAX_LEN) {
				size_t add = 1 + (size_t)(rnd() % 64), i;
				for (i = 0; i < add; i++)
					b[n + i] = (uint8_t)rnd();
				n += add;
			}
			break;
		case 5: /* hint / tail region of a PQ signature */
			if (n > 100)
				b[n - 1 - (size_t)(rnd() % 90)] = (uint8_t)rnd();
			break;
		default: /* reserved area */
			if (n > 255)
				b[96 + (size_t)(rnd() % 160)] = (uint8_t)rnd();
			break;
		}
	}
	return n;
}

int main(int argc, char **argv)
{
	int seconds = 60, i;
	const char *dir = NULL;
	uint8_t *buf = malloc(MAX_LEN + 64);
	unsigned long execs = 0;
	time_t start;

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "-seconds=", 9))
			seconds = atoi(argv[i] + 9);
		else if (!strncmp(argv[i], "-seed=", 6))
			rng = strtoull(argv[i] + 6, NULL, 0) | 1;
		else
			dir = argv[i];
	}
	if (!dir || !buf) {
		fprintf(stderr, "usage: %s [-seconds=N] [-seed=S] CORPUS_DIR\n", argv[0]);
		return 2;
	}
	load_corpus(dir);
	if (!nseeds) {
		fprintf(stderr, "empty corpus\n");
		return 2;
	}
	/* run every seed unmodified first */
	for (i = 0; i < nseeds; i++)
		LLVMFuzzerTestOneInput(seeds[i], seed_len[i]);

	start = time(NULL);
	while (time(NULL) - start < seconds) {
		int s = (int)(rnd() % (uint64_t)nseeds);
		size_t n = seed_len[s];
		memcpy(buf, seeds[s], n);
		n = mutate(buf, n);
		LLVMFuzzerTestOneInput(buf, n);
		execs++;
		if (execs % 2000 == 0) {
			printf("\r#%lu execs (%lu/s)", execs,
			       execs / (unsigned long)(time(NULL) - start + 1));
			fflush(stdout);
		}
	}
	printf("\ndone: %lu executions, no sanitizer findings\n", execs);
	for (i = 0; i < nseeds; i++)
		free(seeds[i]);
	free(buf);
	return 0;
}
