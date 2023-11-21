#ifndef NTT_H
#define NTT_H

#include <immintrin.h>

void ntt_avx(__m256i *a, const __m256i *qdata);
void invntt_avx(__m256i *a, const __m256i *qdata);

void nttunpack_avx(__m256i *a);

void pointwise_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);
void pointwise_acc_avx(__m256i *c, const __m256i *a, const __m256i *b, const __m256i *qdata);

#endif
