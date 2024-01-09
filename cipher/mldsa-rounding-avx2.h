#ifndef _GCRY_MLDSA_AVX2_ROUNDING_H
#define _GCRY_MLDSA_AVX2_ROUNDING_H

#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "mldsa-params.h"
#include "types.h"
#include "avx2-immintrin-support.h"

#ifdef USE_AVX2

void _gcry_mldsa_avx2_power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a);
void _gcry_mldsa_avx2_decompose_avx(gcry_mldsa_param_t *params, __m256i *a1, __m256i *a0, const __m256i *a);
unsigned int _gcry_mldsa_avx2_make_hint_avx(gcry_mldsa_param_t *params,
                                            byte hint[GCRY_MLDSA_N],
                                            const __m256i *a0,
                                            const __m256i *a1);
void _gcry_mldsa_avx2_use_hint_avx(gcry_mldsa_param_t *params, __m256i *b, const __m256i *a, const __m256i *hint);

#endif
#endif
