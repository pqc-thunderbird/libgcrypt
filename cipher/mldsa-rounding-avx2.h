#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "mldsa-params.h"
#include "types.h"

void power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a);
void decompose_avx(gcry_mldsa_param_t *params, __m256i *a1, __m256i *a0, const __m256i *a);
unsigned int make_hint_avx(gcry_mldsa_param_t *params, byte hint[GCRY_MLDSA_N], const __m256i *a0, const __m256i *a1);
void use_hint_avx(gcry_mldsa_param_t *params, __m256i *b, const __m256i *a, const __m256i *hint);

#endif
