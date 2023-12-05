#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "mldsa-params-avx2.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-poly-avx2.h"

void challenge(gcry_mldsa_poly *c, const byte seed[GCRY_MLDSA_SEEDBYTES]);

#endif
