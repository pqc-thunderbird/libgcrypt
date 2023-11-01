#ifndef _GCRY_MLDSA_REDUCE_H
#define _GCRY_MLDSA_REDUCE_H

#include "types.h"
#include "mldsa-params.h"

#define GCRY_MLDSA_MONT -4186625 // 2^32 % GCRY_MLDSA_Q
#define GCRY_MLDSA_QINV 58728449 // q^(-1) mod 2^32

s32 _gcry_mldsa_montgomery_reduce(int64_t a);

s32 _gcry_mldsa_reduce32(s32 a);

s32 _gcry_mldsa_caddq(s32 a);

s32 _gcry_mldsa_freeze(s32 a);

#endif
