#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include <immintrin.h>

void _gcry_mlkem_avx2_ntt_avx (__m256i *r, const __m256i *qdata);
void _gcry_mlkem_avx2_invntt_avx (__m256i *r, const __m256i *qdata);

void _gcry_mlkem_avx2_nttpack_avx (__m256i *r, const __m256i *qdata);
void _gcry_mlkem_avx2_nttunpack_avx (__m256i *r, const __m256i *qdata);

void _gcry_mlkem_avx2_basemul_avx (__m256i *r,
                                   const __m256i *a,
                                   const __m256i *b,
                                   const __m256i *qdata);

void _gcry_mlkem_avx2_ntttobytes_avx (uint8_t *r,
                                      const __m256i *a,
                                      const __m256i *qdata);
void _gcry_mlkem_avx2_nttfrombytes_avx (__m256i *r,
                                        const uint8_t *a,
                                        const __m256i *qdata);

#endif
