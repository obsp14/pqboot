/*
 * host_port.h - extra controls available only in the host port
 * (unit tests, fuzzing, fault-injection harness, boot simulator).
 */
#ifndef PQB_HOST_PORT_H
#define PQB_HOST_PORT_H

#include "pqb/port.h"
#include "pqb/image.h"

/* Rollback counters, one per image type (simulated OTP). */
void host_rollback_set(uint32_t image_type, uint32_t value);
pqb_status_t host_rollback_load(const char *path);   /* "type value" lines */

/* How many times pqb_port_fault_detected() fired, and the last site. */
uint32_t host_fault_count(void);
uint32_t host_fault_last_site(void);
void host_fault_reset(void);

/*
 * Deterministically derive an ECDSA-P384 key pair from a 48-byte seed
 * (d = seed mod (n - 1) + 1), export the public key (04||X||Y) and sign a
 * SHA-384 digest (raw r||s). Used for the DICE alias key in the simulator.
 * tools/pqsign/pqsign/dice.py implements the same derivation.
 */
pqb_status_t host_ecdsa_from_seed(const uint8_t seed[48], uint8_t pub[97]);
pqb_status_t host_ecdsa_sign_seed(const uint8_t seed[48],
				  const uint8_t digest[48], uint8_t sig[96]);

#endif
