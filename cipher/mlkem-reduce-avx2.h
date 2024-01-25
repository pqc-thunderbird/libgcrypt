#ifndef GCRYPT_MLKEM_REDUCE_AVX2_H
#define GCRYPT_MLKEM_REDUCE_AVX2_H

#include <immintrin.h>

void _gcry_mlkem_avx2_reduce_avx (__m256i *r, const __m256i *gcry_mlkem_avx2_qdata);
void _gcry_mlkem_avx2_tomont_avx (__m256i *r, const __m256i *gcry_mlkem_avx2_qdata);

#endif
