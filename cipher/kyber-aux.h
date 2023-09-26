#ifndef GCRYPT_KYBER_AUX_H
#define GCRYPT_KYBER_AUX_H

#include <stddef.h>
#include <stdint.h>
#include "kyber-params.h"

int16_t _gcry_kyber_montgomery_reduce(int32_t a);

int16_t _gcry_kyber_barrett_reduce(int16_t a);

typedef void* (*try_alloc_func_t)(size_t);

#endif /* GCRYPT_KYBER_AUX_H */
