#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-polyvec-avx2.h"


void unpack_sk(gcry_mldsa_param_t *params, byte rho[GCRY_MLDSA_SEEDBYTES],
               byte tr[GCRY_MLDSA_TRBYTES],
               byte key[GCRY_MLDSA_SEEDBYTES],
               byte *t0,
               byte *s1,
               byte *s2,
               const byte *sk);


#endif
