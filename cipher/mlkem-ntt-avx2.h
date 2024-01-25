/* mlkem-ntt-avx2.c
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-KEM NIST submission.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GCRYPT_MLKEM_NTT_AVX2_H
#define GCRYPT_MLKEM_NTT_AVX2_H

#include <stdint.h>
#include <immintrin.h>

void _gcry_mlkem_avx2_ntt_avx (__m256i *r,
                               const __m256i *gcry_mlkem_avx2_qdata);
void _gcry_mlkem_avx2_invntt_avx (__m256i *r,
                                  const __m256i *gcry_mlkem_avx2_qdata);

void _gcry_mlkem_avx2_nttpack_avx (__m256i *r,
                                   const __m256i *gcry_mlkem_avx2_qdata);
void _gcry_mlkem_avx2_nttunpack_avx (__m256i *r,
                                     const __m256i *gcry_mlkem_avx2_qdata);

void _gcry_mlkem_avx2_basemul_avx (__m256i *r,
                                   const __m256i *a,
                                   const __m256i *b,
                                   const __m256i *gcry_mlkem_avx2_qdata);

void _gcry_mlkem_avx2_ntttobytes_avx (uint8_t *r,
                                      const __m256i *a,
                                      const __m256i *gcry_mlkem_avx2_qdata);
void _gcry_mlkem_avx2_nttfrombytes_avx (__m256i *r,
                                        const uint8_t *a,
                                        const __m256i *gcry_mlkem_avx2_qdata);

#endif
