#ifndef REDUCE_H
#define REDUCE_H

#include <immintrin.h>

void _gcry_mlkem_avx2_reduce_avx (__m256i *r, const __m256i *qdata);
void _gcry_mlkem_avx2_tomont_avx (__m256i *r, const __m256i *qdata);

#endif
