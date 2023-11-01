#ifndef _GCRY_MLDSA_ROUNDING_H
#define _GCRY_MLDSA_ROUNDING_H

#include "types.h"
#include "mldsa-params.h"

s32 _gcry_mldsa_power2round(s32 *a0, s32 a);

s32 _gcry_mldsa_decompose(gcry_mldsa_param_t *params, s32 *a0, s32 a);

unsigned int _gcry_mldsa_make_hint(gcry_mldsa_param_t *params, s32 a0, s32 a1);

s32 _gcry_mldsa_use_hint(gcry_mldsa_param_t *params, s32 a, unsigned int hint);

#endif
