#ifndef _GCRY_MLDSA_ROUNDING_H
#define _GCRY_MLDSA_ROUNDING_H

#include <stdint.h>
#include "mldsa-params.h"

int32_t _gcry_mldsa_power2round(int32_t *a0, int32_t a);

int32_t _gcry_mldsa_decompose(gcry_mldsa_param_t *params, int32_t *a0, int32_t a);

unsigned int _gcry_mldsa_make_hint(gcry_mldsa_param_t *params, int32_t a0, int32_t a1);

int32_t _gcry_mldsa_use_hint(gcry_mldsa_param_t *params, int32_t a, unsigned int hint);

#endif
