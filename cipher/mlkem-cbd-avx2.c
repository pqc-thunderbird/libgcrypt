/* mlkem-cbd-avx2.c
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

#include <stdint.h>
#include <immintrin.h>
#include "mlkem-params.h"
#include "mlkem-cbd-avx2.h"
#include "mlkem-poly.h"

/*************************************************
 * Name:        cbd2
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=2
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const __m256i *buf: pointer to aligned input byte array
 **************************************************/
static void
cbd2 (gcry_mlkem_poly *restrict r, const __m256i buf[2 * GCRY_MLKEM_N / 128])
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i mask55 = _mm256_set1_epi32 (0x55555555);
  const __m256i mask33 = _mm256_set1_epi32 (0x33333333);
  const __m256i mask03 = _mm256_set1_epi32 (0x03030303);
  const __m256i mask0F = _mm256_set1_epi32 (0x0F0F0F0F);

  for (i = 0; i < GCRY_MLKEM_N / 64; i++)
    {
      f0 = _mm256_load_si256 (&buf[i]);

      f1 = _mm256_srli_epi16 (f0, 1);
      f0 = _mm256_and_si256 (mask55, f0);
      f1 = _mm256_and_si256 (mask55, f1);
      f0 = _mm256_add_epi8 (f0, f1);

      f1 = _mm256_srli_epi16 (f0, 2);
      f0 = _mm256_and_si256 (mask33, f0);
      f1 = _mm256_and_si256 (mask33, f1);
      f0 = _mm256_add_epi8 (f0, mask33);
      f0 = _mm256_sub_epi8 (f0, f1);

      f1 = _mm256_srli_epi16 (f0, 4);
      f0 = _mm256_and_si256 (mask0F, f0);
      f1 = _mm256_and_si256 (mask0F, f1);
      f0 = _mm256_sub_epi8 (f0, mask03);
      f1 = _mm256_sub_epi8 (f1, mask03);

      f2 = _mm256_unpacklo_epi8 (f0, f1);
      f3 = _mm256_unpackhi_epi8 (f0, f1);

      f0 = _mm256_cvtepi8_epi16 (_mm256_castsi256_si128 (f2));
      f1 = _mm256_cvtepi8_epi16 (_mm256_extracti128_si256 (f2, 1));
      f2 = _mm256_cvtepi8_epi16 (_mm256_castsi256_si128 (f3));
      f3 = _mm256_cvtepi8_epi16 (_mm256_extracti128_si256 (f3, 1));

      _mm256_store_si256 (&r->vec[4 * i + 0], f0);
      _mm256_store_si256 (&r->vec[4 * i + 1], f2);
      _mm256_store_si256 (&r->vec[4 * i + 2], f1);
      _mm256_store_si256 (&r->vec[4 * i + 3], f3);
    }
}

/*************************************************
 * Name:        cbd3
 *
 * Description: Given an array of uniformly random bytes, compute
 *              polynomial with coefficients distributed according to
 *              a centered binomial distribution with parameter eta=3
 *              This function is only needed for Kyber-512
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const __m256i *buf: pointer to aligned input byte array
 **************************************************/
static void
cbd3 (gcry_mlkem_poly *restrict r, const uint8_t buf[3 * GCRY_MLKEM_N / 4 + 8])
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i mask249  = _mm256_set1_epi32 (0x249249);
  const __m256i mask6DB  = _mm256_set1_epi32 (0x6DB6DB);
  const __m256i mask07   = _mm256_set1_epi32 (7);
  const __m256i mask70   = _mm256_set1_epi32 (7 << 16);
  const __m256i mask3    = _mm256_set1_epi16 (3);
  const __m256i shufbidx = _mm256_set_epi8 (-1,
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

  for (i = 0; i < GCRY_MLKEM_N / 32; i++)
    {
      f0 = _mm256_loadu_si256 ((__m256i *)&buf[24 * i]);
      f0 = _mm256_permute4x64_epi64 (f0, 0x94);
      f0 = _mm256_shuffle_epi8 (f0, shufbidx);

      f1 = _mm256_srli_epi32 (f0, 1);
      f2 = _mm256_srli_epi32 (f0, 2);
      f0 = _mm256_and_si256 (mask249, f0);
      f1 = _mm256_and_si256 (mask249, f1);
      f2 = _mm256_and_si256 (mask249, f2);
      f0 = _mm256_add_epi32 (f0, f1);
      f0 = _mm256_add_epi32 (f0, f2);

      f1 = _mm256_srli_epi32 (f0, 3);
      f0 = _mm256_add_epi32 (f0, mask6DB);
      f0 = _mm256_sub_epi32 (f0, f1);

      f1 = _mm256_slli_epi32 (f0, 10);
      f2 = _mm256_srli_epi32 (f0, 12);
      f3 = _mm256_srli_epi32 (f0, 2);
      f0 = _mm256_and_si256 (f0, mask07);
      f1 = _mm256_and_si256 (f1, mask70);
      f2 = _mm256_and_si256 (f2, mask07);
      f3 = _mm256_and_si256 (f3, mask70);
      f0 = _mm256_add_epi16 (f0, f1);
      f1 = _mm256_add_epi16 (f2, f3);
      f0 = _mm256_sub_epi16 (f0, mask3);
      f1 = _mm256_sub_epi16 (f1, mask3);

      f2 = _mm256_unpacklo_epi32 (f0, f1);
      f3 = _mm256_unpackhi_epi32 (f0, f1);

      f0 = _mm256_permute2x128_si256 (f2, f3, 0x20);
      f1 = _mm256_permute2x128_si256 (f2, f3, 0x31);

      _mm256_store_si256 (&r->vec[2 * i + 0], f0);
      _mm256_store_si256 (&r->vec[2 * i + 1], f1);
    }
}

/* buf 32 bytes longer for cbd3 */
void
_gcry_mlkem_avx2_poly_cbd_eta1 (gcry_mlkem_poly *r,
                                const __m256i *buf,
                                gcry_mlkem_param_t const *param)
{
  if (param->eta1 == 2)
    {
      cbd2 (r, buf);
    }
  else // eta1 == 3
    {
      cbd3 (r, (uint8_t *)buf);
    }
}

void
_gcry_mlkem_avx2_poly_cbd_eta2 (
    gcry_mlkem_poly *r,
    const __m256i buf[GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 128])
{
  cbd2 (r, buf);
}
