/* mldsa-rejsample-avx2.c
 * Copyright (C) 2024 MTG AG
 * The code was created based on the reference implementation that is part of the ML-DSA NIST submission.
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

#include "mldsa-rejsample-avx2.h"
#ifdef USE_AVX2
#include <stdint.h>
#include <immintrin.h>
#include "config.h"
#include "types.h"
#include "mldsa-symmetric.h"

const byte _gcry_mldsa_avx2_idxlut[256][8]
    = {{0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0},
       {1, 0, 0, 0, 0, 0, 0, 0}, {0, 1, 0, 0, 0, 0, 0, 0},
       {2, 0, 0, 0, 0, 0, 0, 0}, {0, 2, 0, 0, 0, 0, 0, 0},
       {1, 2, 0, 0, 0, 0, 0, 0}, {0, 1, 2, 0, 0, 0, 0, 0},
       {3, 0, 0, 0, 0, 0, 0, 0}, {0, 3, 0, 0, 0, 0, 0, 0},
       {1, 3, 0, 0, 0, 0, 0, 0}, {0, 1, 3, 0, 0, 0, 0, 0},
       {2, 3, 0, 0, 0, 0, 0, 0}, {0, 2, 3, 0, 0, 0, 0, 0},
       {1, 2, 3, 0, 0, 0, 0, 0}, {0, 1, 2, 3, 0, 0, 0, 0},
       {4, 0, 0, 0, 0, 0, 0, 0}, {0, 4, 0, 0, 0, 0, 0, 0},
       {1, 4, 0, 0, 0, 0, 0, 0}, {0, 1, 4, 0, 0, 0, 0, 0},
       {2, 4, 0, 0, 0, 0, 0, 0}, {0, 2, 4, 0, 0, 0, 0, 0},
       {1, 2, 4, 0, 0, 0, 0, 0}, {0, 1, 2, 4, 0, 0, 0, 0},
       {3, 4, 0, 0, 0, 0, 0, 0}, {0, 3, 4, 0, 0, 0, 0, 0},
       {1, 3, 4, 0, 0, 0, 0, 0}, {0, 1, 3, 4, 0, 0, 0, 0},
       {2, 3, 4, 0, 0, 0, 0, 0}, {0, 2, 3, 4, 0, 0, 0, 0},
       {1, 2, 3, 4, 0, 0, 0, 0}, {0, 1, 2, 3, 4, 0, 0, 0},
       {5, 0, 0, 0, 0, 0, 0, 0}, {0, 5, 0, 0, 0, 0, 0, 0},
       {1, 5, 0, 0, 0, 0, 0, 0}, {0, 1, 5, 0, 0, 0, 0, 0},
       {2, 5, 0, 0, 0, 0, 0, 0}, {0, 2, 5, 0, 0, 0, 0, 0},
       {1, 2, 5, 0, 0, 0, 0, 0}, {0, 1, 2, 5, 0, 0, 0, 0},
       {3, 5, 0, 0, 0, 0, 0, 0}, {0, 3, 5, 0, 0, 0, 0, 0},
       {1, 3, 5, 0, 0, 0, 0, 0}, {0, 1, 3, 5, 0, 0, 0, 0},
       {2, 3, 5, 0, 0, 0, 0, 0}, {0, 2, 3, 5, 0, 0, 0, 0},
       {1, 2, 3, 5, 0, 0, 0, 0}, {0, 1, 2, 3, 5, 0, 0, 0},
       {4, 5, 0, 0, 0, 0, 0, 0}, {0, 4, 5, 0, 0, 0, 0, 0},
       {1, 4, 5, 0, 0, 0, 0, 0}, {0, 1, 4, 5, 0, 0, 0, 0},
       {2, 4, 5, 0, 0, 0, 0, 0}, {0, 2, 4, 5, 0, 0, 0, 0},
       {1, 2, 4, 5, 0, 0, 0, 0}, {0, 1, 2, 4, 5, 0, 0, 0},
       {3, 4, 5, 0, 0, 0, 0, 0}, {0, 3, 4, 5, 0, 0, 0, 0},
       {1, 3, 4, 5, 0, 0, 0, 0}, {0, 1, 3, 4, 5, 0, 0, 0},
       {2, 3, 4, 5, 0, 0, 0, 0}, {0, 2, 3, 4, 5, 0, 0, 0},
       {1, 2, 3, 4, 5, 0, 0, 0}, {0, 1, 2, 3, 4, 5, 0, 0},
       {6, 0, 0, 0, 0, 0, 0, 0}, {0, 6, 0, 0, 0, 0, 0, 0},
       {1, 6, 0, 0, 0, 0, 0, 0}, {0, 1, 6, 0, 0, 0, 0, 0},
       {2, 6, 0, 0, 0, 0, 0, 0}, {0, 2, 6, 0, 0, 0, 0, 0},
       {1, 2, 6, 0, 0, 0, 0, 0}, {0, 1, 2, 6, 0, 0, 0, 0},
       {3, 6, 0, 0, 0, 0, 0, 0}, {0, 3, 6, 0, 0, 0, 0, 0},
       {1, 3, 6, 0, 0, 0, 0, 0}, {0, 1, 3, 6, 0, 0, 0, 0},
       {2, 3, 6, 0, 0, 0, 0, 0}, {0, 2, 3, 6, 0, 0, 0, 0},
       {1, 2, 3, 6, 0, 0, 0, 0}, {0, 1, 2, 3, 6, 0, 0, 0},
       {4, 6, 0, 0, 0, 0, 0, 0}, {0, 4, 6, 0, 0, 0, 0, 0},
       {1, 4, 6, 0, 0, 0, 0, 0}, {0, 1, 4, 6, 0, 0, 0, 0},
       {2, 4, 6, 0, 0, 0, 0, 0}, {0, 2, 4, 6, 0, 0, 0, 0},
       {1, 2, 4, 6, 0, 0, 0, 0}, {0, 1, 2, 4, 6, 0, 0, 0},
       {3, 4, 6, 0, 0, 0, 0, 0}, {0, 3, 4, 6, 0, 0, 0, 0},
       {1, 3, 4, 6, 0, 0, 0, 0}, {0, 1, 3, 4, 6, 0, 0, 0},
       {2, 3, 4, 6, 0, 0, 0, 0}, {0, 2, 3, 4, 6, 0, 0, 0},
       {1, 2, 3, 4, 6, 0, 0, 0}, {0, 1, 2, 3, 4, 6, 0, 0},
       {5, 6, 0, 0, 0, 0, 0, 0}, {0, 5, 6, 0, 0, 0, 0, 0},
       {1, 5, 6, 0, 0, 0, 0, 0}, {0, 1, 5, 6, 0, 0, 0, 0},
       {2, 5, 6, 0, 0, 0, 0, 0}, {0, 2, 5, 6, 0, 0, 0, 0},
       {1, 2, 5, 6, 0, 0, 0, 0}, {0, 1, 2, 5, 6, 0, 0, 0},
       {3, 5, 6, 0, 0, 0, 0, 0}, {0, 3, 5, 6, 0, 0, 0, 0},
       {1, 3, 5, 6, 0, 0, 0, 0}, {0, 1, 3, 5, 6, 0, 0, 0},
       {2, 3, 5, 6, 0, 0, 0, 0}, {0, 2, 3, 5, 6, 0, 0, 0},
       {1, 2, 3, 5, 6, 0, 0, 0}, {0, 1, 2, 3, 5, 6, 0, 0},
       {4, 5, 6, 0, 0, 0, 0, 0}, {0, 4, 5, 6, 0, 0, 0, 0},
       {1, 4, 5, 6, 0, 0, 0, 0}, {0, 1, 4, 5, 6, 0, 0, 0},
       {2, 4, 5, 6, 0, 0, 0, 0}, {0, 2, 4, 5, 6, 0, 0, 0},
       {1, 2, 4, 5, 6, 0, 0, 0}, {0, 1, 2, 4, 5, 6, 0, 0},
       {3, 4, 5, 6, 0, 0, 0, 0}, {0, 3, 4, 5, 6, 0, 0, 0},
       {1, 3, 4, 5, 6, 0, 0, 0}, {0, 1, 3, 4, 5, 6, 0, 0},
       {2, 3, 4, 5, 6, 0, 0, 0}, {0, 2, 3, 4, 5, 6, 0, 0},
       {1, 2, 3, 4, 5, 6, 0, 0}, {0, 1, 2, 3, 4, 5, 6, 0},
       {7, 0, 0, 0, 0, 0, 0, 0}, {0, 7, 0, 0, 0, 0, 0, 0},
       {1, 7, 0, 0, 0, 0, 0, 0}, {0, 1, 7, 0, 0, 0, 0, 0},
       {2, 7, 0, 0, 0, 0, 0, 0}, {0, 2, 7, 0, 0, 0, 0, 0},
       {1, 2, 7, 0, 0, 0, 0, 0}, {0, 1, 2, 7, 0, 0, 0, 0},
       {3, 7, 0, 0, 0, 0, 0, 0}, {0, 3, 7, 0, 0, 0, 0, 0},
       {1, 3, 7, 0, 0, 0, 0, 0}, {0, 1, 3, 7, 0, 0, 0, 0},
       {2, 3, 7, 0, 0, 0, 0, 0}, {0, 2, 3, 7, 0, 0, 0, 0},
       {1, 2, 3, 7, 0, 0, 0, 0}, {0, 1, 2, 3, 7, 0, 0, 0},
       {4, 7, 0, 0, 0, 0, 0, 0}, {0, 4, 7, 0, 0, 0, 0, 0},
       {1, 4, 7, 0, 0, 0, 0, 0}, {0, 1, 4, 7, 0, 0, 0, 0},
       {2, 4, 7, 0, 0, 0, 0, 0}, {0, 2, 4, 7, 0, 0, 0, 0},
       {1, 2, 4, 7, 0, 0, 0, 0}, {0, 1, 2, 4, 7, 0, 0, 0},
       {3, 4, 7, 0, 0, 0, 0, 0}, {0, 3, 4, 7, 0, 0, 0, 0},
       {1, 3, 4, 7, 0, 0, 0, 0}, {0, 1, 3, 4, 7, 0, 0, 0},
       {2, 3, 4, 7, 0, 0, 0, 0}, {0, 2, 3, 4, 7, 0, 0, 0},
       {1, 2, 3, 4, 7, 0, 0, 0}, {0, 1, 2, 3, 4, 7, 0, 0},
       {5, 7, 0, 0, 0, 0, 0, 0}, {0, 5, 7, 0, 0, 0, 0, 0},
       {1, 5, 7, 0, 0, 0, 0, 0}, {0, 1, 5, 7, 0, 0, 0, 0},
       {2, 5, 7, 0, 0, 0, 0, 0}, {0, 2, 5, 7, 0, 0, 0, 0},
       {1, 2, 5, 7, 0, 0, 0, 0}, {0, 1, 2, 5, 7, 0, 0, 0},
       {3, 5, 7, 0, 0, 0, 0, 0}, {0, 3, 5, 7, 0, 0, 0, 0},
       {1, 3, 5, 7, 0, 0, 0, 0}, {0, 1, 3, 5, 7, 0, 0, 0},
       {2, 3, 5, 7, 0, 0, 0, 0}, {0, 2, 3, 5, 7, 0, 0, 0},
       {1, 2, 3, 5, 7, 0, 0, 0}, {0, 1, 2, 3, 5, 7, 0, 0},
       {4, 5, 7, 0, 0, 0, 0, 0}, {0, 4, 5, 7, 0, 0, 0, 0},
       {1, 4, 5, 7, 0, 0, 0, 0}, {0, 1, 4, 5, 7, 0, 0, 0},
       {2, 4, 5, 7, 0, 0, 0, 0}, {0, 2, 4, 5, 7, 0, 0, 0},
       {1, 2, 4, 5, 7, 0, 0, 0}, {0, 1, 2, 4, 5, 7, 0, 0},
       {3, 4, 5, 7, 0, 0, 0, 0}, {0, 3, 4, 5, 7, 0, 0, 0},
       {1, 3, 4, 5, 7, 0, 0, 0}, {0, 1, 3, 4, 5, 7, 0, 0},
       {2, 3, 4, 5, 7, 0, 0, 0}, {0, 2, 3, 4, 5, 7, 0, 0},
       {1, 2, 3, 4, 5, 7, 0, 0}, {0, 1, 2, 3, 4, 5, 7, 0},
       {6, 7, 0, 0, 0, 0, 0, 0}, {0, 6, 7, 0, 0, 0, 0, 0},
       {1, 6, 7, 0, 0, 0, 0, 0}, {0, 1, 6, 7, 0, 0, 0, 0},
       {2, 6, 7, 0, 0, 0, 0, 0}, {0, 2, 6, 7, 0, 0, 0, 0},
       {1, 2, 6, 7, 0, 0, 0, 0}, {0, 1, 2, 6, 7, 0, 0, 0},
       {3, 6, 7, 0, 0, 0, 0, 0}, {0, 3, 6, 7, 0, 0, 0, 0},
       {1, 3, 6, 7, 0, 0, 0, 0}, {0, 1, 3, 6, 7, 0, 0, 0},
       {2, 3, 6, 7, 0, 0, 0, 0}, {0, 2, 3, 6, 7, 0, 0, 0},
       {1, 2, 3, 6, 7, 0, 0, 0}, {0, 1, 2, 3, 6, 7, 0, 0},
       {4, 6, 7, 0, 0, 0, 0, 0}, {0, 4, 6, 7, 0, 0, 0, 0},
       {1, 4, 6, 7, 0, 0, 0, 0}, {0, 1, 4, 6, 7, 0, 0, 0},
       {2, 4, 6, 7, 0, 0, 0, 0}, {0, 2, 4, 6, 7, 0, 0, 0},
       {1, 2, 4, 6, 7, 0, 0, 0}, {0, 1, 2, 4, 6, 7, 0, 0},
       {3, 4, 6, 7, 0, 0, 0, 0}, {0, 3, 4, 6, 7, 0, 0, 0},
       {1, 3, 4, 6, 7, 0, 0, 0}, {0, 1, 3, 4, 6, 7, 0, 0},
       {2, 3, 4, 6, 7, 0, 0, 0}, {0, 2, 3, 4, 6, 7, 0, 0},
       {1, 2, 3, 4, 6, 7, 0, 0}, {0, 1, 2, 3, 4, 6, 7, 0},
       {5, 6, 7, 0, 0, 0, 0, 0}, {0, 5, 6, 7, 0, 0, 0, 0},
       {1, 5, 6, 7, 0, 0, 0, 0}, {0, 1, 5, 6, 7, 0, 0, 0},
       {2, 5, 6, 7, 0, 0, 0, 0}, {0, 2, 5, 6, 7, 0, 0, 0},
       {1, 2, 5, 6, 7, 0, 0, 0}, {0, 1, 2, 5, 6, 7, 0, 0},
       {3, 5, 6, 7, 0, 0, 0, 0}, {0, 3, 5, 6, 7, 0, 0, 0},
       {1, 3, 5, 6, 7, 0, 0, 0}, {0, 1, 3, 5, 6, 7, 0, 0},
       {2, 3, 5, 6, 7, 0, 0, 0}, {0, 2, 3, 5, 6, 7, 0, 0},
       {1, 2, 3, 5, 6, 7, 0, 0}, {0, 1, 2, 3, 5, 6, 7, 0},
       {4, 5, 6, 7, 0, 0, 0, 0}, {0, 4, 5, 6, 7, 0, 0, 0},
       {1, 4, 5, 6, 7, 0, 0, 0}, {0, 1, 4, 5, 6, 7, 0, 0},
       {2, 4, 5, 6, 7, 0, 0, 0}, {0, 2, 4, 5, 6, 7, 0, 0},
       {1, 2, 4, 5, 6, 7, 0, 0}, {0, 1, 2, 4, 5, 6, 7, 0},
       {3, 4, 5, 6, 7, 0, 0, 0}, {0, 3, 4, 5, 6, 7, 0, 0},
       {1, 3, 4, 5, 6, 7, 0, 0}, {0, 1, 3, 4, 5, 6, 7, 0},
       {2, 3, 4, 5, 6, 7, 0, 0}, {0, 2, 3, 4, 5, 6, 7, 0},
       {1, 2, 3, 4, 5, 6, 7, 0}, {0, 1, 2, 3, 4, 5, 6, 7}};

#define REJ_UNIFORM_NBLOCKS                                                   \
  ((768 + GCRY_STREAM128_BLOCKBYTES - 1) / GCRY_STREAM128_BLOCKBYTES)
#define REJ_UNIFORM_BUFLEN (REJ_UNIFORM_NBLOCKS * GCRY_STREAM128_BLOCKBYTES)

unsigned int
_gcry_mldsa_avx2_rej_uniform_avx (s32 *restrict r, const byte *buf)
{
  unsigned int ctr, pos;
  u32 good;
  __m256i d, tmp;
  const __m256i bound = _mm256_set1_epi32 (GCRY_MLDSA_Q);
  const __m256i mask  = _mm256_set1_epi32 (0x7FFFFF);
  const __m256i idx8  = _mm256_set_epi8 (-1,
                                        15,
                                        14,
                                        13,
                                        -1,
                                        12,
                                        11,
                                        10,
                                        -1,
                                        9,
                                        8,
                                        7,
                                        -1,
                                        6,
                                        5,
                                        4,
                                        -1,
                                        11,
                                        10,
                                        9,
                                        -1,
                                        8,
                                        7,
                                        6,
                                        -1,
                                        5,
                                        4,
                                        3,
                                        -1,
                                        2,
                                        1,
                                        0);
  u32 t;

  ctr = pos = 0;
  while (pos <= REJ_UNIFORM_BUFLEN - 24)
    {
      d = _mm256_loadu_si256 ((__m256i *)&buf[pos]);
      d = _mm256_permute4x64_epi64 (d, 0x94);
      d = _mm256_shuffle_epi8 (d, idx8);
      d = _mm256_and_si256 (d, mask);
      pos += 24;

      tmp  = _mm256_sub_epi32 (d, bound);
      good = _mm256_movemask_ps ((__m256)tmp);
      tmp  = _mm256_cvtepu8_epi32 (
          _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good]));
      d = _mm256_permutevar8x32_epi32 (d, tmp);

      _mm256_storeu_si256 ((__m256i *)&r[ctr], d);
      ctr += _mm_popcnt_u32 (good);

      if (ctr > GCRY_MLDSA_N - 8)
        break;
    }

  while (ctr < GCRY_MLDSA_N && pos <= REJ_UNIFORM_BUFLEN - 3)
    {
      t = buf[pos++];
      t |= (u32)buf[pos++] << 8;
      t |= (u32)buf[pos++] << 16;
      t &= 0x7FFFFF;

      if (t < GCRY_MLDSA_Q)
        r[ctr++] = t;
    }

  return ctr;
}

unsigned int
_gcry_mldsa_avx2_rej_eta_avx_eta2 (s32 *restrict r, const byte *buf)
{
  const size_t REJ_UNIFORM_ETA_BUFLEN
      = ((136 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES)
        * GCRY_STREAM256_BLOCKBYTES;

  unsigned int ctr, pos;
  u32 good;
  __m256i f0, f1, f2;
  __m128i g0, g1;
  const __m256i mask  = _mm256_set1_epi8 (15);
  const __m256i eta   = _mm256_set1_epi8 (2);
  const __m256i bound = mask;
  const __m256i v     = _mm256_set1_epi32 (-6560);
  const __m256i p     = _mm256_set1_epi32 (5);
  u32 t0, t1;

  ctr = pos = 0;
  while (ctr <= GCRY_MLDSA_N - 8 && pos <= REJ_UNIFORM_ETA_BUFLEN - 16)
    {
      f0 = _mm256_cvtepu8_epi16 (_mm_loadu_si128 ((__m128i *)&buf[pos]));
      f1 = _mm256_slli_epi16 (f0, 4);
      f0 = _mm256_or_si256 (f0, f1);
      f0 = _mm256_and_si256 (f0, mask);

      f1   = _mm256_sub_epi8 (f0, bound);
      f0   = _mm256_sub_epi8 (eta, f0);
      good = _mm256_movemask_epi8 (f1);

      g0 = _mm256_castsi256_si128 (f0);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      f2 = _mm256_mulhrs_epi16 (f1, v);
      f2 = _mm256_mullo_epi16 (f2, p);
      f1 = _mm256_add_epi32 (f1, f2);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm_bsrli_si128 (g0, 8);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      f2 = _mm256_mulhrs_epi16 (f1, v);
      f2 = _mm256_mullo_epi16 (f2, p);
      f1 = _mm256_add_epi32 (f1, f2);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm256_extracti128_si256 (f0, 1);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      f2 = _mm256_mulhrs_epi16 (f1, v);
      f2 = _mm256_mullo_epi16 (f2, p);
      f1 = _mm256_add_epi32 (f1, f2);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm_bsrli_si128 (g0, 8);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      f2 = _mm256_mulhrs_epi16 (f1, v);
      f2 = _mm256_mullo_epi16 (f2, p);
      f1 = _mm256_add_epi32 (f1, f2);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good);
      pos += 4;
    }

  while (ctr < GCRY_MLDSA_N && pos < REJ_UNIFORM_ETA_BUFLEN)
    {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

      if (t0 < 15)
        {
          t0       = t0 - (205 * t0 >> 10) * 5;
          r[ctr++] = 2 - t0;
        }
      if (t1 < 15 && ctr < GCRY_MLDSA_N)
        {
          t1       = t1 - (205 * t1 >> 10) * 5;
          r[ctr++] = 2 - t1;
        }
    }

  return ctr;
}

unsigned int
_gcry_mldsa_avx2_rej_eta_avx_eta4 (s32 *restrict r, const byte *buf)
{
  const size_t REJ_UNIFORM_ETA_BUFLEN
      = ((227 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES)
        * GCRY_STREAM256_BLOCKBYTES;

  unsigned int ctr, pos;
  u32 good;
  __m256i f0, f1;
  __m128i g0, g1;
  const __m256i mask  = _mm256_set1_epi8 (15);
  const __m256i eta   = _mm256_set1_epi8 (4);
  const __m256i bound = _mm256_set1_epi8 (9);
  u32 t0, t1;

  ctr = pos = 0;
  while (ctr <= GCRY_MLDSA_N - 8 && pos <= REJ_UNIFORM_ETA_BUFLEN - 16)
    {
      f0 = _mm256_cvtepu8_epi16 (_mm_loadu_si128 ((__m128i *)&buf[pos]));
      f1 = _mm256_slli_epi16 (f0, 4);
      f0 = _mm256_or_si256 (f0, f1);
      f0 = _mm256_and_si256 (f0, mask);

      f1   = _mm256_sub_epi8 (f0, bound);
      f0   = _mm256_sub_epi8 (eta, f0);
      good = _mm256_movemask_epi8 (f1);

      g0 = _mm256_castsi256_si128 (f0);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm_bsrli_si128 (g0, 8);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm256_extracti128_si256 (f0, 1);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good & 0xFF]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good & 0xFF);
      good >>= 8;
      pos += 4;

      if (ctr > GCRY_MLDSA_N - 8)
        break;
      g0 = _mm_bsrli_si128 (g0, 8);
      g1 = _mm_loadl_epi64 ((__m128i *)&_gcry_mldsa_avx2_idxlut[good]);
      g1 = _mm_shuffle_epi8 (g0, g1);
      f1 = _mm256_cvtepi8_epi32 (g1);
      _mm256_storeu_si256 ((__m256i *)&r[ctr], f1);
      ctr += _mm_popcnt_u32 (good);
      pos += 4;
    }

  while (ctr < GCRY_MLDSA_N && pos < REJ_UNIFORM_ETA_BUFLEN)
    {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

      if (t0 < 9)
        r[ctr++] = 4 - t0;
      if (t1 < 9 && ctr < GCRY_MLDSA_N)
        r[ctr++] = 4 - t1;
    }

  return ctr;
}
#endif