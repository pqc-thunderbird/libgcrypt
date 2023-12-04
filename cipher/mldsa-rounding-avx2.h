#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include <immintrin.h>
#include "mldsa-params-avx2.h"

void power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a);
void decompose_avx(__m256i *a1, __m256i *a0, const __m256i *a);
unsigned int make_hint_avx(uint8_t hint[GCRY_MLDSA_N], const __m256i *a0, const __m256i *a1);
void use_hint_avx(__m256i *b, const __m256i *a, const __m256i *hint);

#endif
