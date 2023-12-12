#ifndef NTT_H
#define NTT_H

#include <immintrin.h>

void _gcry_mldsa_avx2_ntt_avx(__m256i *a, const __m256i *qdata);
void _gcry_mldsa_avx2_invntt_avx(__m256i *a, const __m256i *qdata);

void _gcry_mldsa_avx2_nttunpack_avx(__m256i *a);

void _gcry_mldsa_avx2_pointwise_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
void _gcry_mldsa_avx2_pointwise_acc_avx_L4(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
void _gcry_mldsa_avx2_pointwise_acc_avx_L5(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
void _gcry_mldsa_avx2_pointwise_acc_avx_L7(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);

#endif
