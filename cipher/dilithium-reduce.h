#ifndef _GCRY_DILITHIUM_REDUCE_H
#define _GCRY_DILITHIUM_REDUCE_H

#include <stdint.h>
#include "dilithium-params.h"

#define GCRY_DILITHIUM_MONT -4186625 // 2^32 % GCRY_DILITHIUM_Q
#define GCRY_DILITHIUM_QINV 58728449 // q^(-1) mod 2^32

int32_t _gcry_dilithium_montgomery_reduce(int64_t a);

int32_t _gcry_dilithium_reduce32(int32_t a);

int32_t _gcry_dilithium_caddq(int32_t a);

int32_t _gcry_dilithium_freeze(int32_t a);

#endif
