#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "dilithium-params.h"

int32_t _gcry_dilithium_power2round(int32_t *a0, int32_t a);

int32_t _gcry_dilithium_decompose(gcry_dilithium_param_t *params, int32_t *a0, int32_t a);

unsigned int _gcry_dilithium_make_hint(gcry_dilithium_param_t *params, int32_t a0, int32_t a1);

int32_t _gcry_dilithium_use_hint(gcry_dilithium_param_t *params, int32_t a, unsigned int hint);

#endif
