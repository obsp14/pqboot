/*
 * host_openssl.c - host implementation of the pqboot port layer (OpenSSL 3)
 *
 * Uses the legacy EC_KEY / ECDSA_SIG API because it maps one-to-one onto
 * what embedded crypto libraries (mbedTLS) expose; the deprecation
 * warnings are silenced on purpose.
 */
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "host_port.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <stdio.h>

static uint32_t g_rollback[PQB_IMG_TYPE_MAX];
static uint32_t g_fault_count, g_fault_site;

void host_rollback_set(uint32_t t, uint32_t v)
{
	if (t < PQB_IMG_TYPE_MAX)
		g_rollback[t] = v;
}

pqb_status_t host_rollback_load(const char *path)
{
	FILE *f = fopen(path, "r");
	unsigned t, v;

	if (!f)
		return PQB_ERR_PORT;
	while (fscanf(f, "%u %u", &t, &v) == 2)
		host_rollback_set(t, v);
	fclose(f);
	return PQB_OK;
}

pqb_status_t pqb_port_rollback_read(uint32_t t, uint32_t *counter)
{
	if (t >= PQB_IMG_TYPE_MAX)
		return PQB_ERR_PORT;
	*counter = g_rollback[t];
	return PQB_OK;
}

void pqb_port_fault_detected(uint32_t site)
{
	g_fault_count++;
	g_fault_site = site;
}

uint32_t host_fault_count(void) { return g_fault_count; }
uint32_t host_fault_last_site(void) { return g_fault_site; }
void host_fault_reset(void) { g_fault_count = 0; g_fault_site = 0; }

static EC_KEY *pub_from_bytes(const uint8_t pub[97])
{
	EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp384r1);
	const EC_GROUP *g;
	EC_POINT *pt;

	if (!k)
		return NULL;
	g = EC_KEY_get0_group(k);
	pt = EC_POINT_new(g);
	if (!pt || EC_POINT_oct2point(g, pt, pub, 97, NULL) != 1 ||
	    EC_KEY_set_public_key(k, pt) != 1 || EC_KEY_check_key(k) != 1) {
		EC_POINT_free(pt);
		EC_KEY_free(k);
		return NULL;
	}
	EC_POINT_free(pt);
	return k;
}

pqb_status_t pqb_port_ecdsa_p384_verify(const uint8_t pub[97],
					const uint8_t digest[48],
					const uint8_t sig[96])
{
	EC_KEY *k;
	ECDSA_SIG *s;
	BIGNUM *r, *ss;
	int ok;

	if (pub[0] != 0x04)
		return PQB_ERR_SIG_CLASSIC;
	k = pub_from_bytes(pub);
	if (!k)
		return PQB_ERR_SIG_CLASSIC;
	s = ECDSA_SIG_new();
	r = BN_bin2bn(sig, 48, NULL);
	ss = BN_bin2bn(sig + 48, 48, NULL);
	if (!s || !r || !ss || ECDSA_SIG_set0(s, r, ss) != 1) {
		BN_free(r);
		BN_free(ss);
		ECDSA_SIG_free(s);
		EC_KEY_free(k);
		return PQB_ERR_PORT;
	}
	ok = ECDSA_do_verify(digest, 48, s, k);
	ECDSA_SIG_free(s);
	EC_KEY_free(k);
	return ok == 1 ? PQB_OK : PQB_ERR_SIG_CLASSIC;
}

static EC_KEY *key_from_seed(const uint8_t seed[48])
{
	EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp384r1);
	const EC_GROUP *g = k ? EC_KEY_get0_group(k) : NULL;
	BIGNUM *d = BN_bin2bn(seed, 48, NULL), *nm1 = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	EC_POINT *pt = g ? EC_POINT_new(g) : NULL;
	int ok = k && d && nm1 && ctx && pt &&
		 BN_copy(nm1, EC_GROUP_get0_order(g)) &&
		 BN_sub_word(nm1, 1) &&
		 BN_nnmod(d, d, nm1, ctx) &&
		 BN_add_word(d, 1) &&
		 EC_KEY_set_private_key(k, d) == 1 &&
		 EC_POINT_mul(g, pt, d, NULL, NULL, ctx) == 1 &&
		 EC_KEY_set_public_key(k, pt) == 1;

	EC_POINT_free(pt);
	BN_CTX_free(ctx);
	BN_clear_free(d);
	BN_free(nm1);
	if (!ok) {
		EC_KEY_free(k);
		return NULL;
	}
	return k;
}

pqb_status_t host_ecdsa_from_seed(const uint8_t seed[48], uint8_t pub[97])
{
	EC_KEY *k = key_from_seed(seed);
	size_t n;

	if (!k)
		return PQB_ERR_PORT;
	n = EC_POINT_point2oct(EC_KEY_get0_group(k), EC_KEY_get0_public_key(k),
			       POINT_CONVERSION_UNCOMPRESSED, pub, 97, NULL);
	EC_KEY_free(k);
	return n == 97 ? PQB_OK : PQB_ERR_PORT;
}

pqb_status_t host_ecdsa_sign_seed(const uint8_t seed[48],
				  const uint8_t digest[48], uint8_t sig[96])
{
	EC_KEY *k = key_from_seed(seed);
	ECDSA_SIG *s;
	const BIGNUM *r, *ss;
	int ok;

	if (!k)
		return PQB_ERR_PORT;
	s = ECDSA_do_sign(digest, 48, k);
	EC_KEY_free(k);
	if (!s)
		return PQB_ERR_PORT;
	ECDSA_SIG_get0(s, &r, &ss);
	ok = BN_bn2binpad(r, sig, 48) == 48 && BN_bn2binpad(ss, sig + 48, 48) == 48;
	ECDSA_SIG_free(s);
	return ok ? PQB_OK : PQB_ERR_PORT;
}
