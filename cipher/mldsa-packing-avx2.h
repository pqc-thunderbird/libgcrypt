#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-polyvec-avx2.h"


void unpack_sk(gcry_mldsa_param_t *params, uint8_t rho[GCRY_MLDSA_SEEDBYTES],
               uint8_t tr[GCRY_MLDSA_TRBYTES],
               uint8_t key[GCRY_MLDSA_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);


#endif
