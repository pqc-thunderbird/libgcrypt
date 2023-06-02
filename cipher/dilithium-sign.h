#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-polyvec.h"
#include "dilithium-poly.h"

void challenge(poly *c, const uint8_t seed[GCRY_DILITHIUM_SEEDBYTES]);

gcry_error_t _gcry_dilithium_keypair(gcry_dilithium_param_t *params, uint8_t *pk, uint8_t *sk);

gcry_error_t _gcry_dilithium_sign(gcry_dilithium_param_t *params,
                          uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

gcry_error_t _gcry_dilithium_verify(gcry_dilithium_param_t *params,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#endif
