/*
 * port.h - platform hooks the library needs. Each environment provides its
 * own implementation:
 *
 *   ports/host_openssl.c   - host tests and the boot simulator (OpenSSL)
 *   integration/tf-a/...   - TF-A BL2 using mbedTLS (from TF-A's tree)
 *
 * Keeping these behind an interface is what lets the same verifier run on
 * a laptop, inside TF-A and inside unit tests.
 */
#ifndef PQB_PORT_H
#define PQB_PORT_H

#include "pqb/common.h"

/* ECDSA-P384 verification. pub = 04||X||Y (97 bytes), sig = r||s (96). */
pqb_status_t pqb_port_ecdsa_p384_verify(const uint8_t pub[97],
					const uint8_t digest[48],
					const uint8_t sig[96]);

/*
 * Read the anti-rollback counter for an image type. On silicon this is a
 * monotonic counter in OTP / RPMB; in the simulator it is a file.
 */
pqb_status_t pqb_port_rollback_read(uint32_t image_type, uint32_t *counter);

/*
 * Called when a redundant check disagrees with the first evaluation. That
 * can only happen under fault injection (or a bug), so a real platform
 * should lock down: wipe keys, stop the boot, possibly count the event.
 */
void pqb_port_fault_detected(uint32_t site);

#endif /* PQB_PORT_H */
