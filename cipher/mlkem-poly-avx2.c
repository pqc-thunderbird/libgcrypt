/* mlkem-poly-avx2.c
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
#include <string.h>
#include "mlkem-poly-avx2.h"
#include "mlkem-ntt-avx2.h"
#include "mlkem-consts-avx2.h"
#include "mlkem-reduce-avx2.h"
#include "mlkem-cbd-avx2.h"
#include "mlkem-symmetric.h"
#include "mlkem-polyvec-avx2.h"
#include "ml-common-fips202x4-avx2.h"


/*************************************************
 * Name:        poly_compress
 *
 * Description: Compression and subsequent serialization of a polynomial.
 *              The coefficients of the input polynomial are assumed to
 *              lie in the invertal [0,q], i.e. the polynomial must be reduced
 *              by _gcry_mlkem_avx2_poly_reduce().
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *              - const gcry_mlkem_poly *a: pointer to input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_compress_128 (uint8_t r[128],
                                    const gcry_mlkem_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i v = _mm256_load_si256 (&gcry_mlkem_avx2_qdata.vec[_16XV / 16]);
  const __m256i shift1   = _mm256_set1_epi16 (1 << 9);
  const __m256i mask     = _mm256_set1_epi16 (15);
  const __m256i shift2   = _mm256_set1_epi16 ((16 << 8) + 1);
  const __m256i permdidx = _mm256_set_epi32 (7, 3, 6, 2, 5, 1, 4, 0);

  for (i = 0; i < GCRY_MLKEM_N / 64; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[4 * i + 0]);
      f1 = _mm256_load_si256 (&a->vec[4 * i + 1]);
      f2 = _mm256_load_si256 (&a->vec[4 * i + 2]);
      f3 = _mm256_load_si256 (&a->vec[4 * i + 3]);
      f0 = _mm256_mulhi_epi16 (f0, v);
      f1 = _mm256_mulhi_epi16 (f1, v);
      f2 = _mm256_mulhi_epi16 (f2, v);
      f3 = _mm256_mulhi_epi16 (f3, v);
      f0 = _mm256_mulhrs_epi16 (f0, shift1);
      f1 = _mm256_mulhrs_epi16 (f1, shift1);
      f2 = _mm256_mulhrs_epi16 (f2, shift1);
      f3 = _mm256_mulhrs_epi16 (f3, shift1);
      f0 = _mm256_and_si256 (f0, mask);
      f1 = _mm256_and_si256 (f1, mask);
      f2 = _mm256_and_si256 (f2, mask);
      f3 = _mm256_and_si256 (f3, mask);
      f0 = _mm256_packus_epi16 (f0, f1);
      f2 = _mm256_packus_epi16 (f2, f3);
      f0 = _mm256_maddubs_epi16 (f0, shift2);
      f2 = _mm256_maddubs_epi16 (f2, shift2);
      f0 = _mm256_packus_epi16 (f0, f2);
      f0 = _mm256_permutevar8x32_epi32 (f0, permdidx);
      _mm256_storeu_si256 ((__m256i *)&r[32 * i], f0);
    }
}

void
_gcry_mlkem_avx2_poly_decompress_128 (gcry_mlkem_poly *restrict r,
                                      const uint8_t a[128])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  const __m256i q = _mm256_load_si256 (&gcry_mlkem_avx2_qdata.vec[_16XQ / 16]);
  const __m256i shufbidx = _mm256_set_epi8 (7,
                                            7,
                                            7,
                                            7,
                                            6,
                                            6,
                                            6,
                                            6,
                                            5,
                                            5,
                                            5,
                                            5,
                                            4,
                                            4,
                                            4,
                                            4,
                                            3,
                                            3,
                                            3,
                                            3,
                                            2,
                                            2,
                                            2,
                                            2,
                                            1,
                                            1,
                                            1,
                                            1,
                                            0,
                                            0,
                                            0,
                                            0);
  const __m256i mask     = _mm256_set1_epi32 (0x00F0000F);
  const __m256i shift    = _mm256_set1_epi32 ((128 << 16) + 2048);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      t = _mm_loadl_epi64 ((__m128i *)&a[8 * i]);
      f = _mm256_broadcastsi128_si256 (t);
      f = _mm256_shuffle_epi8 (f, shufbidx);
      f = _mm256_and_si256 (f, mask);
      f = _mm256_mullo_epi16 (f, shift);
      f = _mm256_mulhrs_epi16 (f, q);
      _mm256_store_si256 (&r->vec[i], f);
    }
}

void
_gcry_mlkem_avx2_poly_compress_160 (uint8_t r[160],
                                    const gcry_mlkem_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1;
  __m128i t0, t1;
  const __m256i v = _mm256_load_si256 (&gcry_mlkem_avx2_qdata.vec[_16XV / 16]);
  const __m256i shift1   = _mm256_set1_epi16 (1 << 10);
  const __m256i mask     = _mm256_set1_epi16 (31);
  const __m256i shift2   = _mm256_set1_epi16 ((32 << 8) + 1);
  const __m256i shift3   = _mm256_set1_epi32 ((1024 << 16) + 1);
  const __m256i sllvdidx = _mm256_set1_epi64x (12);
  const __m256i shufbidx = _mm256_set_epi8 (8,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            4,
                                            3,
                                            2,
                                            1,
                                            0,
                                            -1,
                                            12,
                                            11,
                                            10,
                                            9,
                                            -1,
                                            12,
                                            11,
                                            10,
                                            9,
                                            8,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            -1,
                                            4,
                                            3,
                                            2,
                                            1,
                                            0);

  for (i = 0; i < GCRY_MLKEM_N / 32; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[2 * i + 0]);
      f1 = _mm256_load_si256 (&a->vec[2 * i + 1]);
      f0 = _mm256_mulhi_epi16 (f0, v);
      f1 = _mm256_mulhi_epi16 (f1, v);
      f0 = _mm256_mulhrs_epi16 (f0, shift1);
      f1 = _mm256_mulhrs_epi16 (f1, shift1);
      f0 = _mm256_and_si256 (f0, mask);
      f1 = _mm256_and_si256 (f1, mask);
      f0 = _mm256_packus_epi16 (f0, f1);
      f0 = _mm256_maddubs_epi16 (
          f0, shift2); // a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
      f0 = _mm256_madd_epi16 (f0, shift3); // a0 a1 b0 b1 a2 a3 b2 b3
      f0 = _mm256_sllv_epi32 (f0, sllvdidx);
      f0 = _mm256_srlv_epi64 (f0, sllvdidx);
      f0 = _mm256_shuffle_epi8 (f0, shufbidx);
      t0 = _mm256_castsi256_si128 (f0);
      t1 = _mm256_extracti128_si256 (f0, 1);
      t0 = _mm_blendv_epi8 (t0, t1, _mm256_castsi256_si128 (shufbidx));
      _mm_storeu_si128 ((__m128i *)&r[20 * i + 0], t0);
      memcpy (&r[20 * i + 16], &t1, 4);
    }
}

void
_gcry_mlkem_avx2_poly_decompress_160 (gcry_mlkem_poly *restrict r,
                                      const uint8_t a[160])
{
  unsigned int i;
  __m128i t;
  __m256i f;
  int16_t ti;
  const __m256i q = _mm256_load_si256 (&gcry_mlkem_avx2_qdata.vec[_16XQ / 16]);
  const __m256i shufbidx = _mm256_set_epi8 (9,
                                            9,
                                            9,
                                            8,
                                            8,
                                            8,
                                            8,
                                            7,
                                            7,
                                            6,
                                            6,
                                            6,
                                            6,
                                            5,
                                            5,
                                            5,
                                            4,
                                            4,
                                            4,
                                            3,
                                            3,
                                            3,
                                            3,
                                            2,
                                            2,
                                            1,
                                            1,
                                            1,
                                            1,
                                            0,
                                            0,
                                            0);
  const __m256i mask     = _mm256_set_epi16 (248,
                                         1984,
                                         62,
                                         496,
                                         3968,
                                         124,
                                         992,
                                         31,
                                         248,
                                         1984,
                                         62,
                                         496,
                                         3968,
                                         124,
                                         992,
                                         31);
  const __m256i shift    = _mm256_set_epi16 (
      128, 16, 512, 64, 8, 256, 32, 1024, 128, 16, 512, 64, 8, 256, 32, 1024);

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      t = _mm_loadl_epi64 ((__m128i *)&a[10 * i + 0]);
      memcpy (&ti, &a[10 * i + 8], 2);
      t = _mm_insert_epi16 (t, ti, 4);
      f = _mm256_broadcastsi128_si256 (t);
      f = _mm256_shuffle_epi8 (f, shufbidx);
      f = _mm256_and_si256 (f, mask);
      f = _mm256_mullo_epi16 (f, shift);
      f = _mm256_mulhrs_epi16 (f, q);
      _mm256_store_si256 (&r->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_tobytes
 *
 * Description: Serialization of a polynomial in NTT representation.
 *              The coefficients of the input polynomial are assumed to
 *              lie in the invertal [0,q], i.e. the polynomial must be reduced
 *              by _gcry_mlkem_avx2_poly_reduce(). The coefficients are orderd
 *as output by _gcry_mlkem_avx2_poly_ntt(); the serialized output coefficients
 *are in bitreversed order.
 *
 * Arguments:   - uint8_t *r: pointer to output byte array
 *                            (needs space for GCRY_MLKEM_POLYBYTES bytes)
 *              - gcry_mlkem_poly *a: pointer to input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_tobytes (uint8_t r[GCRY_MLKEM_POLYBYTES],
                               const gcry_mlkem_poly *a)
{
  _gcry_mlkem_avx2_ntttobytes_avx (r, a->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_frombytes
 *
 * Description: De-serialization of a polynomial;
 *              inverse of _gcry_mlkem_avx2_poly_tobytes
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const uint8_t *a: pointer to input byte array
 *                                  (of GCRY_MLKEM_POLYBYTES bytes)
 **************************************************/
void
_gcry_mlkem_avx2_poly_frombytes (gcry_mlkem_poly *r,
                                 const uint8_t a[GCRY_MLKEM_POLYBYTES])
{
  _gcry_mlkem_avx2_nttfrombytes_avx (r->vec, a, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_frommsg
 *
 * Description: Convert 32-byte message to polynomial
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const uint8_t *msg: pointer to input message
 **************************************************/
void
_gcry_mlkem_avx2_poly_frommsg (gcry_mlkem_poly *restrict r, const uint8_t *msg)
{
  __m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
  const __m256i shift
      = _mm256_broadcastsi128_si256 (_mm_set_epi32 (0, 1, 2, 3));
  const __m256i idx = _mm256_broadcastsi128_si256 (
      _mm_set_epi8 (15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0));
  const __m256i hqs = _mm256_set1_epi16 ((GCRY_MLKEM_Q + 1) / 2);

#define FROMMSG64(i)                                                          \
  g3 = _mm256_shuffle_epi32 (f, 0x55 * i);                                    \
  g3 = _mm256_sllv_epi32 (g3, shift);                                         \
  g3 = _mm256_shuffle_epi8 (g3, idx);                                         \
  g0 = _mm256_slli_epi16 (g3, 12);                                            \
  g1 = _mm256_slli_epi16 (g3, 8);                                             \
  g2 = _mm256_slli_epi16 (g3, 4);                                             \
  g0 = _mm256_srai_epi16 (g0, 15);                                            \
  g1 = _mm256_srai_epi16 (g1, 15);                                            \
  g2 = _mm256_srai_epi16 (g2, 15);                                            \
  g3 = _mm256_srai_epi16 (g3, 15);                                            \
  g0 = _mm256_and_si256 (g0, hqs); /* 19 18 17 16  3  2  1  0 */              \
  g1 = _mm256_and_si256 (g1, hqs); /* 23 22 21 20  7  6  5  4 */              \
  g2 = _mm256_and_si256 (g2, hqs); /* 27 26 25 24 11 10  9  8 */              \
  g3 = _mm256_and_si256 (g3, hqs); /* 31 30 29 28 15 14 13 12 */              \
  h0 = _mm256_unpacklo_epi64 (g0, g1);                                        \
  h2 = _mm256_unpackhi_epi64 (g0, g1);                                        \
  h1 = _mm256_unpacklo_epi64 (g2, g3);                                        \
  h3 = _mm256_unpackhi_epi64 (g2, g3);                                        \
  g0 = _mm256_permute2x128_si256 (h0, h1, 0x20);                              \
  g2 = _mm256_permute2x128_si256 (h0, h1, 0x31);                              \
  g1 = _mm256_permute2x128_si256 (h2, h3, 0x20);                              \
  g3 = _mm256_permute2x128_si256 (h2, h3, 0x31);                              \
  _mm256_store_si256 (&r->vec[0 + 2 * i + 0], g0);                            \
  _mm256_store_si256 (&r->vec[0 + 2 * i + 1], g1);                            \
  _mm256_store_si256 (&r->vec[8 + 2 * i + 0], g2);                            \
  _mm256_store_si256 (&r->vec[8 + 2 * i + 1], g3)

  f = _mm256_loadu_si256 ((__m256i *)msg);
  FROMMSG64 (0);
  FROMMSG64 (1);
  FROMMSG64 (2);
  FROMMSG64 (3);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_tomsg
 *
 * Description: Convert polynomial to 32-byte message.
 *              The coefficients of the input polynomial are assumed to
 *              lie in the invertal [0,q], i.e. the polynomial must be reduced
 *              by _gcry_mlkem_avx2_poly_reduce().
 *
 * Arguments:   - uint8_t *msg: pointer to output message
 *              - gcry_mlkem_poly *a: pointer to input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_tomsg (uint8_t *msg, const gcry_mlkem_poly *restrict a)
{
  unsigned int i;
  uint32_t small;
  __m256i f0, f1, g0, g1;
  const __m256i hq  = _mm256_set1_epi16 ((GCRY_MLKEM_Q - 1) / 2);
  const __m256i hhq = _mm256_set1_epi16 ((GCRY_MLKEM_Q - 1) / 4);

  for (i = 0; i < GCRY_MLKEM_N / 32; i++)
    {
      f0    = _mm256_load_si256 (&a->vec[2 * i + 0]);
      f1    = _mm256_load_si256 (&a->vec[2 * i + 1]);
      f0    = _mm256_sub_epi16 (hq, f0);
      f1    = _mm256_sub_epi16 (hq, f1);
      g0    = _mm256_srai_epi16 (f0, 15);
      g1    = _mm256_srai_epi16 (f1, 15);
      f0    = _mm256_xor_si256 (f0, g0);
      f1    = _mm256_xor_si256 (f1, g1);
      f0    = _mm256_sub_epi16 (f0, hhq);
      f1    = _mm256_sub_epi16 (f1, hhq);
      f0    = _mm256_packs_epi16 (f0, f1);
      f0    = _mm256_permute4x64_epi64 (f0, 0xD8);
      small = _mm256_movemask_epi8 (f0);
      memcpy (&msg[4 * i], &small, 4);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_getnoise_eta2
 *
 * Description: Sample a polynomial deterministically from a seed and a nonce,
 *              with output polynomial close to centered binomial distribution
 *              with parameter GCRY_MLKEM_ETA2
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const uint8_t *seed: pointer to input seed
 *                                     (of length GCRY_MLKEM_SYMBYTES bytes)
 *              - uint8_t nonce: one-byte input nonce
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_poly_getnoise_eta2 (gcry_mlkem_poly *r,
                                     const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                                     uint8_t nonce)
{
  gcry_err_code_t ec       = 0;
  gcry_mlkem_buf_al buf_al = {};
  ec                       = _gcry_mlkem_buf_al_create (
      &buf_al, GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4, 1);
  if (ec)
    {
      goto leave;
    }

  _gcry_mlkem_shake256_prf (
      buf_al.buf, GCRY_MLKEM_ETA2 * GCRY_MLKEM_N / 4, seed, nonce);
  _gcry_mlkem_avx2_poly_cbd_eta2 (r, (__m256i *)buf_al.buf);

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  return ec;
}

#define NOISE_NBLOCKS                                                         \
  ((param->eta1 * GCRY_MLKEM_N / 4 + GCRY_SHAKE256_RATE - 1)                  \
   / GCRY_SHAKE256_RATE)
gcry_err_code_t
_gcry_mlkem_avx2_poly_getnoise_eta1_4x (gcry_mlkem_poly *r0,
                                        gcry_mlkem_poly *r1,
                                        gcry_mlkem_poly *r2,
                                        gcry_mlkem_poly *r3,
                                        const uint8_t seed[32],
                                        uint8_t nonce0,
                                        uint8_t nonce1,
                                        uint8_t nonce2,
                                        uint8_t nonce3,
                                        gcry_mlkem_param_t const *param)
{
  gcry_err_code_t ec = 0;
  __m256i f;
  gcry_mlkem_buf_al state_al       = {};
  gcry_ml_common_keccakx4_state *state = NULL;
  byte *buf                        = NULL;
  gcry_mlkem_buf_al buf_al         = {};
  size_t buf_elem_len              = NOISE_NBLOCKS * GCRY_SHAKE256_RATE;
  /* make sure each sub structure starts memory aligned */
  size_t offset_al = buf_elem_len + (32 - (buf_elem_len % 32));

  ec = _gcry_mlkem_buf_al_create (&buf_al, 4 * offset_al, 1);
  if (ec)
    {
      goto leave;
    }
  buf = buf_al.buf;
  ec  = _gcry_mlkem_buf_al_create (
      &state_al, sizeof (gcry_ml_common_keccakx4_state), 1);
  if (ec)
    {
      goto leave;
    }
  state = (gcry_ml_common_keccakx4_state *)state_al.buf;

  f = _mm256_loadu_si256 ((__m256i *)seed);
  _mm256_store_si256 ((__m256i *)&buf[0 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[1 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[2 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[3 * offset_al], f);

  buf[0 * offset_al + 32] = nonce0;
  buf[1 * offset_al + 32] = nonce1;
  buf[2 * offset_al + 32] = nonce2;
  buf[3 * offset_al + 32] = nonce3;

  _gcry_ml_common_avx2_shake256x4_absorb_once (state,
                                           &buf[0 * offset_al],
                                           &buf[1 * offset_al],
                                           &buf[2 * offset_al],
                                           &buf[3 * offset_al],
                                           33);
  _gcry_ml_common_avx2_shake256x4_squeezeblocks (&buf[0 * offset_al],
                                             &buf[1 * offset_al],
                                             &buf[2 * offset_al],
                                             &buf[3 * offset_al],
                                             NOISE_NBLOCKS,
                                             state);

  _gcry_mlkem_avx2_poly_cbd_eta1 (r0, (__m256i *)&buf[0 * offset_al], param);
  _gcry_mlkem_avx2_poly_cbd_eta1 (r1, (__m256i *)&buf[1 * offset_al], param);
  _gcry_mlkem_avx2_poly_cbd_eta1 (r2, (__m256i *)&buf[2 * offset_al], param);
  _gcry_mlkem_avx2_poly_cbd_eta1 (r3, (__m256i *)&buf[3 * offset_al], param);

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  _gcry_mlkem_buf_al_destroy (&state_al);
  return ec;
}

gcry_err_code_t
_gcry_mlkem_avx2_poly_getnoise_eta1122_4x (gcry_mlkem_poly *r0,
                                           gcry_mlkem_poly *r1,
                                           gcry_mlkem_poly *r2,
                                           gcry_mlkem_poly *r3,
                                           const uint8_t seed[32],
                                           uint8_t nonce0,
                                           uint8_t nonce1,
                                           uint8_t nonce2,
                                           uint8_t nonce3,
                                           gcry_mlkem_param_t const *param)
{
  gcry_err_code_t ec = 0;
  __m256i f;
  gcry_mlkem_buf_al state_al       = {};
  gcry_ml_common_keccakx4_state *state = NULL;
  byte *buf                        = NULL;
  gcry_mlkem_buf_al buf_al         = {};
  size_t buf_elem_len              = NOISE_NBLOCKS * GCRY_SHAKE256_RATE;
  /* make sure each sub structure starts memory aligned */
  size_t offset_al = buf_elem_len + (32 - (buf_elem_len % 32));

  ec = _gcry_mlkem_buf_al_create (&buf_al, 4 * offset_al, 1);
  if (ec)
    {
      goto leave;
    }
  buf = buf_al.buf;
  ec  = _gcry_mlkem_buf_al_create (
      &state_al, sizeof (gcry_ml_common_keccakx4_state), 1);
  if (ec)
    {
      goto leave;
    }
  state = (gcry_ml_common_keccakx4_state *)state_al.buf;

  f = _mm256_loadu_si256 ((__m256i *)seed);
  _mm256_store_si256 ((__m256i *)&buf[0 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[1 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[2 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[3 * offset_al], f);

  buf[0 * offset_al + 32] = nonce0;
  buf[1 * offset_al + 32] = nonce1;
  buf[2 * offset_al + 32] = nonce2;
  buf[3 * offset_al + 32] = nonce3;

  _gcry_ml_common_avx2_shake256x4_absorb_once (state,
                                           &buf[0 * offset_al],
                                           &buf[1 * offset_al],
                                           &buf[2 * offset_al],
                                           &buf[3 * offset_al],
                                           33);
  _gcry_ml_common_avx2_shake256x4_squeezeblocks (&buf[0 * offset_al],
                                             &buf[1 * offset_al],
                                             &buf[2 * offset_al],
                                             &buf[3 * offset_al],
                                             NOISE_NBLOCKS,
                                             state);

  _gcry_mlkem_avx2_poly_cbd_eta1 (r0, (__m256i *)&buf[0 * offset_al], param);
  _gcry_mlkem_avx2_poly_cbd_eta1 (r1, (__m256i *)&buf[1 * offset_al], param);
  _gcry_mlkem_avx2_poly_cbd_eta2 (r2, (__m256i *)&buf[2 * offset_al]);
  _gcry_mlkem_avx2_poly_cbd_eta2 (r3, (__m256i *)&buf[3 * offset_al]);

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  _gcry_mlkem_buf_al_destroy (&state_al);
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_ntt
 *
 * Description: Computes negacyclic number-theoretic transform (NTT) of
 *              a polynomial in place.
 *              Input coefficients assumed to be in normal order,
 *              output coefficients are in special order that is natural
 *              for the vectorization. Input coefficients are assumed to be
 *              bounded by q in absolute value, output coefficients are bounded
 *              by 16118 in absolute value.
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to in/output polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_ntt (gcry_mlkem_poly *r)
{
  _gcry_mlkem_avx2_ntt_avx (r->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_invntt_tomont
 *
 * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
 *              of a polynomial in place;
 *              Input coefficients assumed to be in special order from
 *vectorized forward ntt, output in normal order. Input coefficients can be arbitrary
 *16-bit integers, output coefficients are bounded by 14870 in absolute value.
 *
 * Arguments:   - gcry_mlkem_poly *a: pointer to in/output polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_invntt_tomont (gcry_mlkem_poly *r)
{
  _gcry_mlkem_avx2_invntt_avx (r->vec, gcry_mlkem_avx2_qdata.vec);
}

void
_gcry_mlkem_avx2_poly_nttunpack (gcry_mlkem_poly *r)
{
  _gcry_mlkem_avx2_nttunpack_avx (r->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_basemul_montgomery
 *
 * Description: Multiplication of two polynomials in NTT domain.
 *              One of the input polynomials needs to have coefficients
 *              bounded by q, the other polynomial can have arbitrary
 *              coefficients. Output coefficients are bounded by 6656.
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to output polynomial
 *              - const gcry_mlkem_poly *a: pointer to first input polynomial
 *              - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_basemul_montgomery (gcry_mlkem_poly *r,
                                          const gcry_mlkem_poly *a,
                                          const gcry_mlkem_poly *b)
{
  _gcry_mlkem_avx2_basemul_avx (
      r->vec, a->vec, b->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_tomont
 *
 * Description: Inplace conversion of all coefficients of a polynomial
 *              from normal domain to Montgomery domain
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to input/output polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_tomont (gcry_mlkem_poly *r)
{
  _gcry_mlkem_avx2_tomont_avx (r->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_reduce
 *
 * Description: Applies Barrett reduction to all coefficients of a polynomial
 *              for details of the Barrett reduction see comments in reduce.c
 *
 * Arguments:   - gcry_mlkem_poly *r: pointer to input/output polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_reduce (gcry_mlkem_poly *r)
{
  _gcry_mlkem_avx2_reduce_avx (r->vec, gcry_mlkem_avx2_qdata.vec);
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_add
 *
 * Description: Add two polynomials. No modular reduction
 *              is performed.
 *
 * Arguments: - gcry_mlkem_poly *r: pointer to output polynomial
 *            - const gcry_mlkem_poly *a: pointer to first input polynomial
 *            - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_add (gcry_mlkem_poly *r,
                           const gcry_mlkem_poly *a,
                           const gcry_mlkem_poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[i]);
      f1 = _mm256_load_si256 (&b->vec[i]);
      f0 = _mm256_add_epi16 (f0, f1);
      _mm256_store_si256 (&r->vec[i], f0);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_poly_sub
 *
 * Description: Subtract two polynomials. No modular reduction
 *              is performed.
 *
 * Arguments: - gcry_mlkem_poly *r: pointer to output polynomial
 *            - const gcry_mlkem_poly *a: pointer to first input polynomial
 *            - const gcry_mlkem_poly *b: pointer to second input polynomial
 **************************************************/
void
_gcry_mlkem_avx2_poly_sub (gcry_mlkem_poly *r,
                           const gcry_mlkem_poly *a,
                           const gcry_mlkem_poly *b)
{
  unsigned int i;
  __m256i f0, f1;

  for (i = 0; i < GCRY_MLKEM_N / 16; i++)
    {
      f0 = _mm256_load_si256 (&a->vec[i]);
      f1 = _mm256_load_si256 (&b->vec[i]);
      f0 = _mm256_sub_epi16 (f0, f1);
      _mm256_store_si256 (&r->vec[i], f0);
    }
}
