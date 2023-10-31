#ifndef _GCRY_MLDSA_SIGN_H
#define _GCRY_MLDSA_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly.h"

void _gcry_mldsa_challenge(gcry_mldsa_poly *c, const uint8_t seed[GCRY_MLDSA_SEEDBYTES]);

gcry_error_t _gcry_mldsa_keypair(gcry_mldsa_param_t *params, uint8_t *pk, uint8_t *sk);

gcry_error_t _gcry_mldsa_sign(gcry_mldsa_param_t *params,
                          uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

gcry_error_t _gcry_mldsa_verify(gcry_mldsa_param_t *params,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#endif
