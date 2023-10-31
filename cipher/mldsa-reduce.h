#ifndef _GCRY_MLDSA_REDUCE_H
#define _GCRY_MLDSA_REDUCE_H

#include <stdint.h>
#include "mldsa-params.h"

#define GCRY_MLDSA_MONT -4186625 // 2^32 % GCRY_MLDSA_Q
#define GCRY_MLDSA_QINV 58728449 // q^(-1) mod 2^32

int32_t _gcry_mldsa_montgomery_reduce(int64_t a);

int32_t _gcry_mldsa_reduce32(int32_t a);

int32_t _gcry_mldsa_caddq(int32_t a);

int32_t _gcry_mldsa_freeze(int32_t a);

#endif
