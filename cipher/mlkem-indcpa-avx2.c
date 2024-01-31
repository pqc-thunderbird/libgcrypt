/* mlkem-indcpa-avx2.c
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

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "mlkem-indcpa-avx2.h"
#include "mlkem-polyvec-avx2.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-ntt-avx2.h"
#include "mlkem-cbd-avx2.h"
#include "mlkem-rejsample-avx2.h"
#include "mlkem-symmetric.h"


/*************************************************
 * Name:        pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk and the
 *              public seed used to generate the matrix A.
 *              The polynomial coefficients in pk are assumed to
 *              lie in the invertal [0,q], i.e. pk must be reduced
 *              by _gcry_mlkem_avx2_polyvec_reduce().
 *
 * Arguments:   uint8_t *r: pointer to the output serialized public key
 *              polyvec *pk: pointer to the input public-key polyvec
 *              const uint8_t *seed: pointer to the input public seed
 **************************************************/
static void
pack_pk (uint8_t *r,
         gcry_mlkem_poly *pk,
         const uint8_t seed[GCRY_MLKEM_SYMBYTES],
         const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_tobytes (r, pk, param);
  memcpy (r + param->polyvec_bytes, seed, GCRY_MLKEM_SYMBYTES);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of pack_pk
 *
 * Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
 *              - uint8_t *seed: pointer to output seed to generate matrix A
 *              - const uint8_t *packedpk: pointer to input serialized public key
 **************************************************/
static void
unpack_pk (gcry_mlkem_poly *pk,
           uint8_t seed[GCRY_MLKEM_SYMBYTES],
           const uint8_t *packedpk,
           const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_frombytes (pk, packedpk, param);
  memcpy (seed, packedpk + param->polyvec_bytes, GCRY_MLKEM_SYMBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Serialize the secret key.
 *              The polynomial coefficients in sk are assumed to
 *              lie in the invertal [0,q], i.e. sk must be reduced
 *              by _gcry_mlkem_avx2_polyvec_reduce().
 *
 * Arguments:   - uint8_t *r: pointer to output serialized secret key
 *              - polyvec *sk: pointer to input vector of polynomials (secret key)
 **************************************************/
static void
pack_sk (uint8_t *r, gcry_mlkem_poly *sk, const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_tobytes (r, sk, param);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: De-serialize the secret key; inverse of pack_sk
 *
 * Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
 *              - const uint8_t *packedsk: pointer to input serialized secret key
 **************************************************/
static void
unpack_sk (gcry_mlkem_poly *sk,
           const uint8_t *packedsk,
           const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_frombytes (sk, packedsk, param);
}

/*************************************************
 * Name:        pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v.
 *              The polynomial coefficients in b and v are assumed to
 *              lie in the invertal [0,q], i.e. b and v must be reduced
 *              by _gcry_mlkem_avx2_polyvec_reduce() and _gcry_mlkem_avx2_poly_reduce(), respectively.
 *
 * Arguments:   uint8_t *r: pointer to the output serialized ciphertext
 *              gcry_mlkem_poly *pk: pointer to the input vector of polynomials b
 *              gcry_mlkem_poly *v: pointer to the input polynomial v
 **************************************************/
static void
pack_ciphertext (uint8_t *r,
                 gcry_mlkem_poly *b,
                 gcry_mlkem_poly *v,
                 const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_compress (r, b, param);
  if (param->poly_compressed_bytes == 128)
    {
      _gcry_mlkem_avx2_poly_compress_128 (r + param->polyvec_compressed_bytes,
                                          v);
    }
  else
    {
      _gcry_mlkem_avx2_poly_compress_160 (r + param->polyvec_compressed_bytes,
                                          v);
    }
}

/*************************************************
 * Name:        unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of pack_ciphertext
 *
 * Arguments:   - gcry_mlkem_poly *b: pointer to the output vector of polynomials b
 *              - gcry_mlkem_poly *v: pointer to the output polynomial v
 *              - const uint8_t *c: pointer to the input serialized ciphertext
 **************************************************/
static void
unpack_ciphertext (gcry_mlkem_poly *b,
                   gcry_mlkem_poly *v,
                   const uint8_t *c,
                   const gcry_mlkem_param_t *param)
{
  _gcry_mlkem_avx2_polyvec_decompress (b, c, param);
  if (param->poly_compressed_bytes == 128)
    {
      _gcry_mlkem_avx2_poly_decompress_128 (
          v, c + param->polyvec_compressed_bytes);
    }
  else
    {
      _gcry_mlkem_avx2_poly_decompress_160 (
          v, c + param->polyvec_compressed_bytes);
    }
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r: pointer to output array
 *              - unsigned int len: requested number of 16-bit integers (uniform mod q)
 *              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
 *              - unsigned int buflen: length of input buffer in bytes
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
static unsigned int
_gcry_mlkem_avx2_rej_uniform (int16_t *r,
                              unsigned int len,
                              const uint8_t *buf,
                              unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while (ctr < len && pos <= buflen - 3)
    { // buflen is always at least 3
      val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
      val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
      pos += 3;

      if (val0 < GCRY_MLKEM_Q)
        r[ctr++] = val0;
      if (ctr < len && val1 < GCRY_MLKEM_Q)
        r[ctr++] = val1;
    }

  return ctr;
}

static gcry_err_code_t
gen_matrix_k2 (gcry_mlkem_poly *a,
               const uint8_t seed[32],
               int transposed,
               const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int ctr0, ctr1, ctr2, ctr3;
  __m256i f;
  gcry_mlkem_buf_al state_al       = {};
  gcry_ml_common_keccakx4_state *state = NULL;
  byte *buf                        = NULL;
  gcry_mlkem_buf_al buf_al         = {};
  size_t buf_elem_len
      = GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS * GCRY_SHAKE128_RATE;
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

  if (transposed)
    {
      buf[0 * offset_al + 32] = 0;
      buf[0 * offset_al + 33] = 0;
      buf[1 * offset_al + 32] = 0;
      buf[1 * offset_al + 33] = 1;
      buf[2 * offset_al + 32] = 1;
      buf[2 * offset_al + 33] = 0;
      buf[3 * offset_al + 32] = 1;
      buf[3 * offset_al + 33] = 1;
    }
  else
    {
      buf[0 * offset_al + 32] = 0;
      buf[0 * offset_al + 33] = 0;
      buf[1 * offset_al + 32] = 1;
      buf[1 * offset_al + 33] = 0;
      buf[2 * offset_al + 32] = 0;
      buf[2 * offset_al + 33] = 1;
      buf[3 * offset_al + 32] = 1;
      buf[3 * offset_al + 33] = 1;
    }

  _gcry_ml_common_avx2_shake128x4_absorb_once (state,
                                           &buf[0 * offset_al],
                                           &buf[1 * offset_al],
                                           &buf[2 * offset_al],
                                           &buf[3 * offset_al],
                                           34);
  _gcry_ml_common_avx2_shake128x4_squeezeblocks (
      &buf[0 * offset_al],
      &buf[1 * offset_al],
      &buf[2 * offset_al],
      &buf[3 * offset_al],
      GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS,
      state);

  ctr0 = _gcry_mlkem_avx2_rej_uniform_avx (a[0 * param->k + 0].coeffs,
                                           &buf[0 * offset_al]);
  ctr1 = _gcry_mlkem_avx2_rej_uniform_avx (a[0 * param->k + 1].coeffs,
                                           &buf[1 * offset_al]);
  ctr2 = _gcry_mlkem_avx2_rej_uniform_avx (a[1 * param->k + 0].coeffs,
                                           &buf[2 * offset_al]);
  ctr3 = _gcry_mlkem_avx2_rej_uniform_avx (a[1 * param->k + 1].coeffs,
                                           &buf[3 * offset_al]);

  while (ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N
         || ctr3 < GCRY_MLKEM_N)
    {
      _gcry_ml_common_avx2_shake128x4_squeezeblocks (&buf[0 * offset_al],
                                                 &buf[1 * offset_al],
                                                 &buf[2 * offset_al],
                                                 &buf[3 * offset_al],
                                                 1,
                                                 state);

      ctr0 += _gcry_mlkem_avx2_rej_uniform (a[0 * param->k + 0].coeffs + ctr0,
                                            GCRY_MLKEM_N - ctr0,
                                            &buf[0 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr1 += _gcry_mlkem_avx2_rej_uniform (a[0 * param->k + 1].coeffs + ctr1,
                                            GCRY_MLKEM_N - ctr1,
                                            &buf[1 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr2 += _gcry_mlkem_avx2_rej_uniform (a[1 * param->k + 0].coeffs + ctr2,
                                            GCRY_MLKEM_N - ctr2,
                                            &buf[2 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr3 += _gcry_mlkem_avx2_rej_uniform (a[1 * param->k + 1].coeffs + ctr3,
                                            GCRY_MLKEM_N - ctr3,
                                            &buf[3 * offset_al],
                                            GCRY_SHAKE128_RATE);
    }

  _gcry_mlkem_avx2_poly_nttunpack (&a[0 * param->k + 0]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[0 * param->k + 1]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[1 * param->k + 0]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[1 * param->k + 1]);

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  _gcry_mlkem_buf_al_destroy (&state_al);
  return ec;
}

static gcry_err_code_t
gen_matrix_k3 (gcry_mlkem_poly *a,
               const uint8_t seed[32],
               int transposed,
               const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int ctr0, ctr1, ctr2, ctr3;
  __m256i f;
  gcry_md_hd_t h;
  gcry_mlkem_buf_al state_al       = {};
  gcry_ml_common_keccakx4_state *state = NULL;
  byte *buf                        = NULL;
  gcry_mlkem_buf_al buf_al         = {};
  size_t buf_elem_len
      = GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS * GCRY_SHAKE128_RATE;
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

  if (transposed)
    {
      buf[0 * offset_al + 32] = 0;
      buf[0 * offset_al + 33] = 0;
      buf[1 * offset_al + 32] = 0;
      buf[1 * offset_al + 33] = 1;
      buf[2 * offset_al + 32] = 0;
      buf[2 * offset_al + 33] = 2;
      buf[3 * offset_al + 32] = 1;
      buf[3 * offset_al + 33] = 0;
    }
  else
    {
      buf[0 * offset_al + 32] = 0;
      buf[0 * offset_al + 33] = 0;
      buf[1 * offset_al + 32] = 1;
      buf[1 * offset_al + 33] = 0;
      buf[2 * offset_al + 32] = 2;
      buf[2 * offset_al + 33] = 0;
      buf[3 * offset_al + 32] = 0;
      buf[3 * offset_al + 33] = 1;
    }

  _gcry_ml_common_avx2_shake128x4_absorb_once (state,
                                           &buf[0 * offset_al],
                                           &buf[1 * offset_al],
                                           &buf[2 * offset_al],
                                           &buf[3 * offset_al],
                                           34);
  _gcry_ml_common_avx2_shake128x4_squeezeblocks (
      &buf[0 * offset_al],
      &buf[1 * offset_al],
      &buf[2 * offset_al],
      &buf[3 * offset_al],
      GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS,
      state);

  ctr0 = _gcry_mlkem_avx2_rej_uniform_avx (a[0 * param->k + 0].coeffs,
                                           &buf[0 * offset_al]);
  ctr1 = _gcry_mlkem_avx2_rej_uniform_avx (a[0 * param->k + 1].coeffs,
                                           &buf[1 * offset_al]);
  ctr2 = _gcry_mlkem_avx2_rej_uniform_avx (a[0 * param->k + 2].coeffs,
                                           &buf[2 * offset_al]);
  ctr3 = _gcry_mlkem_avx2_rej_uniform_avx (a[1 * param->k + 0].coeffs,
                                           &buf[3 * offset_al]);

  while (ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N
         || ctr3 < GCRY_MLKEM_N)
    {
      _gcry_ml_common_avx2_shake128x4_squeezeblocks (&buf[0 * offset_al],
                                                 &buf[1 * offset_al],
                                                 &buf[2 * offset_al],
                                                 &buf[3 * offset_al],
                                                 1,
                                                 state);

      ctr0 += _gcry_mlkem_avx2_rej_uniform (a[0 * param->k + 0].coeffs + ctr0,
                                            GCRY_MLKEM_N - ctr0,
                                            &buf[0 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr1 += _gcry_mlkem_avx2_rej_uniform (a[0 * param->k + 1].coeffs + ctr1,
                                            GCRY_MLKEM_N - ctr1,
                                            &buf[1 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr2 += _gcry_mlkem_avx2_rej_uniform (a[0 * param->k + 2].coeffs + ctr2,
                                            GCRY_MLKEM_N - ctr2,
                                            &buf[2 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr3 += _gcry_mlkem_avx2_rej_uniform (a[1 * param->k + 0].coeffs + ctr3,
                                            GCRY_MLKEM_N - ctr3,
                                            &buf[3 * offset_al],
                                            GCRY_SHAKE128_RATE);
    }

  _gcry_mlkem_avx2_poly_nttunpack (&a[0 * param->k + 0]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[0 * param->k + 1]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[0 * param->k + 2]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[1 * param->k + 0]);

  f = _mm256_loadu_si256 ((__m256i *)seed);
  _mm256_store_si256 ((__m256i *)&buf[0 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[1 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[2 * offset_al], f);
  _mm256_store_si256 ((__m256i *)&buf[3 * offset_al], f);

  if (transposed)
    {
      buf[0 * offset_al + 32] = 1;
      buf[0 * offset_al + 33] = 1;
      buf[1 * offset_al + 32] = 1;
      buf[1 * offset_al + 33] = 2;
      buf[2 * offset_al + 32] = 2;
      buf[2 * offset_al + 33] = 0;
      buf[3 * offset_al + 32] = 2;
      buf[3 * offset_al + 33] = 1;
    }
  else
    {
      buf[0 * offset_al + 32] = 1;
      buf[0 * offset_al + 33] = 1;
      buf[1 * offset_al + 32] = 2;
      buf[1 * offset_al + 33] = 1;
      buf[2 * offset_al + 32] = 0;
      buf[2 * offset_al + 33] = 2;
      buf[3 * offset_al + 32] = 1;
      buf[3 * offset_al + 33] = 2;
    }

  _gcry_ml_common_avx2_shake128x4_absorb_once (state,
                                           &buf[0 * offset_al],
                                           &buf[1 * offset_al],
                                           &buf[2 * offset_al],
                                           &buf[3 * offset_al],
                                           34);
  _gcry_ml_common_avx2_shake128x4_squeezeblocks (
      &buf[0 * offset_al],
      &buf[1 * offset_al],
      &buf[2 * offset_al],
      &buf[3 * offset_al],
      GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS,
      state);

  ctr0 = _gcry_mlkem_avx2_rej_uniform_avx (a[1 * param->k + 1].coeffs,
                                           &buf[0 * offset_al]);
  ctr1 = _gcry_mlkem_avx2_rej_uniform_avx (a[1 * param->k + 2].coeffs,
                                           &buf[1 * offset_al]);
  ctr2 = _gcry_mlkem_avx2_rej_uniform_avx (a[2 * param->k + 0].coeffs,
                                           &buf[2 * offset_al]);
  ctr3 = _gcry_mlkem_avx2_rej_uniform_avx (a[2 * param->k + 1].coeffs,
                                           &buf[3 * offset_al]);

  while (ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N
         || ctr3 < GCRY_MLKEM_N)
    {
      _gcry_ml_common_avx2_shake128x4_squeezeblocks (&buf[0 * offset_al],
                                                 &buf[1 * offset_al],
                                                 &buf[2 * offset_al],
                                                 &buf[3 * offset_al],
                                                 1,
                                                 state);

      ctr0 += _gcry_mlkem_avx2_rej_uniform (a[1 * param->k + 1].coeffs + ctr0,
                                            GCRY_MLKEM_N - ctr0,
                                            &buf[0 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr1 += _gcry_mlkem_avx2_rej_uniform (a[1 * param->k + 2].coeffs + ctr1,
                                            GCRY_MLKEM_N - ctr1,
                                            &buf[1 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr2 += _gcry_mlkem_avx2_rej_uniform (a[2 * param->k + 0].coeffs + ctr2,
                                            GCRY_MLKEM_N - ctr2,
                                            &buf[2 * offset_al],
                                            GCRY_SHAKE128_RATE);
      ctr3 += _gcry_mlkem_avx2_rej_uniform (a[2 * param->k + 1].coeffs + ctr3,
                                            GCRY_MLKEM_N - ctr3,
                                            &buf[3 * offset_al],
                                            GCRY_SHAKE128_RATE);
    }

  _gcry_mlkem_avx2_poly_nttunpack (&a[1 * param->k + 1]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[1 * param->k + 2]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[2 * param->k + 0]);
  _gcry_mlkem_avx2_poly_nttunpack (&a[2 * param->k + 1]);

  ec = _gcry_md_open (&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;

  f = _mm256_loadu_si256 ((__m256i *)seed);
  _mm256_store_si256 ((__m256i *)&buf[0 * offset_al], f);
  buf[0 * offset_al + 32] = 2;
  buf[0 * offset_al + 33] = 2;
  _gcry_md_write (h, buf, 34);
  ec = _gcry_mlkem_shake128_squeezeblocks (
      h, buf, GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS);
  if (ec)
    goto leave;
  ctr0 = _gcry_mlkem_avx2_rej_uniform_avx (a[2 * param->k + 2].coeffs,
                                           &buf[0 * offset_al]);
  while (ctr0 < GCRY_MLKEM_N)
    {
      ec = _gcry_mlkem_shake128_squeezeblocks (h, buf, 1);
      if (ec)
        goto leave;
      ctr0 += _gcry_mlkem_avx2_rej_uniform (a[2 * param->k + 2].coeffs + ctr0,
                                            GCRY_MLKEM_N - ctr0,
                                            &buf[0 * offset_al],
                                            GCRY_SHAKE128_RATE);
    }

  _gcry_mlkem_avx2_poly_nttunpack (&a[2 * param->k + 2]);

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  _gcry_mlkem_buf_al_destroy (&state_al);
  _gcry_md_close (h);
  return ec;
}

static gcry_err_code_t
gen_matrix_k4 (gcry_mlkem_poly *a,
               const uint8_t seed[32],
               int transposed,
               const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i, ctr0, ctr1, ctr2, ctr3;
  __m256i f;
  gcry_mlkem_buf_al state_al       = {};
  gcry_ml_common_keccakx4_state *state = NULL;
  byte *buf                        = NULL;
  gcry_mlkem_buf_al buf_al         = {};
  size_t buf_elem_len
      = GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS * GCRY_SHAKE128_RATE;
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

  for (i = 0; i < 4; i++)
    {
      f = _mm256_loadu_si256 ((__m256i *)seed);
      _mm256_store_si256 ((__m256i *)&buf[0 * offset_al], f);
      _mm256_store_si256 ((__m256i *)&buf[1 * offset_al], f);
      _mm256_store_si256 ((__m256i *)&buf[2 * offset_al], f);
      _mm256_store_si256 ((__m256i *)&buf[3 * offset_al], f);

      if (transposed)
        {
          buf[0 * offset_al + 32] = i;
          buf[0 * offset_al + 33] = 0;
          buf[1 * offset_al + 32] = i;
          buf[1 * offset_al + 33] = 1;
          buf[2 * offset_al + 32] = i;
          buf[2 * offset_al + 33] = 2;
          buf[3 * offset_al + 32] = i;
          buf[3 * offset_al + 33] = 3;
        }
      else
        {
          buf[0 * offset_al + 32] = 0;
          buf[0 * offset_al + 33] = i;
          buf[1 * offset_al + 32] = 1;
          buf[1 * offset_al + 33] = i;
          buf[2 * offset_al + 32] = 2;
          buf[2 * offset_al + 33] = i;
          buf[3 * offset_al + 32] = 3;
          buf[3 * offset_al + 33] = i;
        }

      _gcry_ml_common_avx2_shake128x4_absorb_once (state,
                                               &buf[0 * offset_al],
                                               &buf[1 * offset_al],
                                               &buf[2 * offset_al],
                                               &buf[3 * offset_al],
                                               34);
      _gcry_ml_common_avx2_shake128x4_squeezeblocks (
          &buf[0 * offset_al],
          &buf[1 * offset_al],
          &buf[2 * offset_al],
          &buf[3 * offset_al],
          GCRY_MLKEM_REJ_UNIFORM_AVX_NBLOCKS,
          state);

      ctr0 = _gcry_mlkem_avx2_rej_uniform_avx (a[i * param->k + 0].coeffs,
                                               &buf[0 * offset_al]);
      ctr1 = _gcry_mlkem_avx2_rej_uniform_avx (a[i * param->k + 1].coeffs,
                                               &buf[1 * offset_al]);
      ctr2 = _gcry_mlkem_avx2_rej_uniform_avx (a[i * param->k + 2].coeffs,
                                               &buf[2 * offset_al]);
      ctr3 = _gcry_mlkem_avx2_rej_uniform_avx (a[i * param->k + 3].coeffs,
                                               &buf[3 * offset_al]);

      while (ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N
             || ctr3 < GCRY_MLKEM_N)
        {
          _gcry_ml_common_avx2_shake128x4_squeezeblocks (&buf[0 * offset_al],
                                                     &buf[1 * offset_al],
                                                     &buf[2 * offset_al],
                                                     &buf[3 * offset_al],
                                                     1,
                                                     state);

          ctr0 += _gcry_mlkem_avx2_rej_uniform (a[i * param->k + 0].coeffs
                                                    + ctr0,
                                                GCRY_MLKEM_N - ctr0,
                                                &buf[0 * offset_al],
                                                GCRY_SHAKE128_RATE);
          ctr1 += _gcry_mlkem_avx2_rej_uniform (a[i * param->k + 1].coeffs
                                                    + ctr1,
                                                GCRY_MLKEM_N - ctr1,
                                                &buf[1 * offset_al],
                                                GCRY_SHAKE128_RATE);
          ctr2 += _gcry_mlkem_avx2_rej_uniform (a[i * param->k + 2].coeffs
                                                    + ctr2,
                                                GCRY_MLKEM_N - ctr2,
                                                &buf[2 * offset_al],
                                                GCRY_SHAKE128_RATE);
          ctr3 += _gcry_mlkem_avx2_rej_uniform (a[i * param->k + 3].coeffs
                                                    + ctr3,
                                                GCRY_MLKEM_N - ctr3,
                                                &buf[3 * offset_al],
                                                GCRY_SHAKE128_RATE);
        }

      _gcry_mlkem_avx2_poly_nttunpack (&a[i * param->k + 0]);
      _gcry_mlkem_avx2_poly_nttunpack (&a[i * param->k + 1]);
      _gcry_mlkem_avx2_poly_nttunpack (&a[i * param->k + 2]);
      _gcry_mlkem_avx2_poly_nttunpack (&a[i * param->k + 3]);
    }

leave:
  _gcry_mlkem_buf_al_destroy (&buf_al);
  _gcry_mlkem_buf_al_destroy (&state_al);
  return ec;
}

gcry_err_code_t
_gcry_mlkem_avx2_gen_matrix (gcry_mlkem_poly *a,
                             const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                             int transposed,
                             const gcry_mlkem_param_t *param)
{
  if (param->k == 2)
    {
      return gen_matrix_k2 (a, seed, transposed, param);
    }
  else if (param->k == 3)
    {
      return gen_matrix_k3 (a, seed, transposed, param);
    }
  else if (param->k == 4)
    {
      return gen_matrix_k4 (a, seed, transposed, param);
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }
}


gcry_err_code_t
_gcry_mlkem_avx2_indcpa_keypair_derand (
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t coins[GCRY_MLKEM_SYMBYTES],
    const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  byte *buf = NULL;
  const uint8_t *publicseed;
  const uint8_t *noiseseed;
  gcry_mlkem_polybuf_al a_al    = {};
  gcry_mlkem_polybuf_al e_al    = {};
  gcry_mlkem_polybuf_al pkpv_al = {};
  gcry_mlkem_polybuf_al skpv_al = {};
  gcry_mlkem_poly *a            = NULL;
  gcry_mlkem_poly *e            = NULL;
  gcry_mlkem_poly *pkpv         = NULL;
  gcry_mlkem_poly *skpv         = NULL;

  buf = xtrymalloc_secure (2 * GCRY_MLKEM_SYMBYTES);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }
  publicseed = buf;
  noiseseed  = buf + GCRY_MLKEM_SYMBYTES;

  ec = _gcry_mlkem_polybuf_al_create (
      &a_al, param->k * param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &e_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &pkpv_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &skpv_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;

  a    = (gcry_mlkem_poly *)a_al.buf;
  e    = (gcry_mlkem_poly *)e_al.buf;
  pkpv = (gcry_mlkem_poly *)pkpv_al.buf;
  skpv = (gcry_mlkem_poly *)skpv_al.buf;

  _gcry_md_hash_buffer (GCRY_MD_SHA3_512, buf, coins, GCRY_MLKEM_SYMBYTES);
  ec = _gcry_mlkem_avx2_gen_matrix (a, publicseed, 0, param);
  if (ec)
    goto leave;

  if (param->k == 2)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &skpv[0], &skpv[1], &e[0], &e[1], noiseseed, 0, 1, 2, 3, param);
      if (ec)
        goto leave;
    }
  else if (param->k == 3)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &skpv[0], &skpv[1], &skpv[2], &e[0], noiseseed, 0, 1, 2, 3, param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &e[1], &e[2], &pkpv[0], &pkpv[1], noiseseed, 4, 5, 6, 7, param);
      if (ec)
        goto leave;
    }
  else if (param->k == 4)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (&skpv[0],
                                                   &skpv[1],
                                                   &skpv[2],
                                                   &skpv[3],
                                                   noiseseed,
                                                   0,
                                                   1,
                                                   2,
                                                   3,
                                                   param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &e[0], &e[1], &e[2], &e[3], noiseseed, 4, 5, 6, 7, param);
      if (ec)
        goto leave;
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }

  _gcry_mlkem_avx2_polyvec_ntt (skpv, param);
  _gcry_mlkem_avx2_polyvec_reduce (skpv, param);
  _gcry_mlkem_avx2_polyvec_ntt (e, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    {
      ec = _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (
          &pkpv[i], &a[i * param->k], skpv, param);
      if (ec)
        goto leave;
      _gcry_mlkem_avx2_poly_tomont (&pkpv[i]);
    }

  _gcry_mlkem_avx2_polyvec_add (pkpv, pkpv, e, param);
  _gcry_mlkem_avx2_polyvec_reduce (pkpv, param);

  pack_sk (sk, skpv, param);
  pack_pk (pk, pkpv, publicseed, param);

leave:
  _gcry_mlkem_polybuf_al_destroy (&a_al);
  _gcry_mlkem_polybuf_al_destroy (&e_al);
  _gcry_mlkem_polybuf_al_destroy (&pkpv_al);
  _gcry_mlkem_polybuf_al_destroy (&skpv_al);
  xfree (buf);
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *c: pointer to output ciphertext
 *              - const uint8_t *m: pointer to input message
 *              - const uint8_t *pk: pointer to input public key
 *              - const uint8_t *coins: pointer to input random coins used as
 *seed to deterministically generate all randomness
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_indcpa_enc (uint8_t *c,
                             const uint8_t *m,
                             const uint8_t *pk,
                             const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                             const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  byte *seed = NULL;
  gcry_mlkem_poly v, k, epp;
  gcry_mlkem_polybuf_al sp_al   = {};
  gcry_mlkem_polybuf_al pkpv_al = {};
  gcry_mlkem_polybuf_al ep_al   = {};
  gcry_mlkem_polybuf_al at_al   = {};
  gcry_mlkem_polybuf_al b_al    = {};
  gcry_mlkem_poly *sp;
  gcry_mlkem_poly *pkpv;
  gcry_mlkem_poly *ep;
  gcry_mlkem_poly *at;
  gcry_mlkem_poly *b;

  seed = xtrymalloc_secure (GCRY_MLKEM_SYMBYTES);
  if (!seed)
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  ec = _gcry_mlkem_polybuf_al_create (
      &sp_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &pkpv_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &ep_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &at_al, param->k * param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &b_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  sp   = (gcry_mlkem_poly *)sp_al.buf;
  pkpv = (gcry_mlkem_poly *)pkpv_al.buf;
  ep   = (gcry_mlkem_poly *)ep_al.buf;
  at   = (gcry_mlkem_poly *)at_al.buf;
  b    = (gcry_mlkem_poly *)b_al.buf;

  unpack_pk (pkpv, seed, pk, param);
  _gcry_mlkem_avx2_poly_frommsg (&k, m);
  ec = _gcry_mlkem_avx2_gen_matrix (at, seed, 1, param);
  if (ec)
    goto leave;

  if (param->k == 2)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1122_4x (
          &sp[0], &sp[1], &ep[0], &ep[1], coins, 0, 1, 2, 3, param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta2 (&epp, coins, 4);
      if (ec)
        goto leave;
    }
  else if (param->k == 3)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &sp[0], &sp[1], &sp[2], &ep[0], coins, 0, 1, 2, 3, param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &ep[1], &ep[2], &epp, &b[0], coins, 4, 5, 6, 7, param);
      if (ec)
        goto leave;
    }

  else if (param->k == 4)
    {
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &sp[0], &sp[1], &sp[2], &sp[3], coins, 0, 1, 2, 3, param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta1_4x (
          &ep[0], &ep[1], &ep[2], &ep[3], coins, 4, 5, 6, 7, param);
      if (ec)
        goto leave;
      ec = _gcry_mlkem_avx2_poly_getnoise_eta2 (&epp, coins, 8);
      if (ec)
        goto leave;
    }

  _gcry_mlkem_avx2_polyvec_ntt (sp, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    ec = _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (
        &b[i], &at[i * param->k], sp, param);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (&v, pkpv, sp, param);
  if (ec)
    goto leave;

  _gcry_mlkem_avx2_polyvec_invntt_tomont (b, param);
  _gcry_mlkem_avx2_poly_invntt_tomont (&v);

  _gcry_mlkem_avx2_polyvec_add (b, b, ep, param);
  _gcry_mlkem_avx2_poly_add (&v, &v, &epp);
  _gcry_mlkem_avx2_poly_add (&v, &v, &k);
  _gcry_mlkem_avx2_polyvec_reduce (b, param);
  _gcry_mlkem_avx2_poly_reduce (&v);

  pack_ciphertext (c, b, &v, param);

leave:
  _gcry_mlkem_polybuf_al_destroy (&sp_al);
  _gcry_mlkem_polybuf_al_destroy (&pkpv_al);
  _gcry_mlkem_polybuf_al_destroy (&ep_al);
  _gcry_mlkem_polybuf_al_destroy (&at_al);
  _gcry_mlkem_polybuf_al_destroy (&b_al);
  xfree (seed);
  return ec;
}

/*************************************************
 * Name:        _gcry_mlkem_avx2_indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *m: pointer to output decrypted message
 *              - const uint8_t *c: pointer to input ciphertext
 *              - const uint8_t *sk: pointer to input secret key
 **************************************************/
gcry_err_code_t
_gcry_mlkem_avx2_indcpa_dec (uint8_t *m,
                             const uint8_t *c,
                             const uint8_t *sk,
                             const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;

  gcry_mlkem_polybuf_al v_al    = {};
  gcry_mlkem_polybuf_al mp_al   = {};
  gcry_mlkem_polybuf_al b_al    = {};
  gcry_mlkem_polybuf_al skpv_al = {};

  gcry_mlkem_poly *v;
  gcry_mlkem_poly *mp;
  gcry_mlkem_poly *b;
  gcry_mlkem_poly *skpv;

  ec = _gcry_mlkem_polybuf_al_create (
      &b_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (
      &skpv_al, param->k, param->k * sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (&v_al, 1, sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;
  ec = _gcry_mlkem_polybuf_al_create (&mp_al, 1, sizeof (gcry_mlkem_poly), 1);
  if (ec)
    goto leave;

  b    = (gcry_mlkem_poly *)b_al.buf;
  skpv = (gcry_mlkem_poly *)skpv_al.buf;
  v    = (gcry_mlkem_poly *)v_al.buf;
  mp   = (gcry_mlkem_poly *)mp_al.buf;

  unpack_ciphertext (b, v, c, param);
  unpack_sk (skpv, sk, param);

  _gcry_mlkem_avx2_polyvec_ntt (b, param);
  ec = _gcry_mlkem_avx2_polyvec_basemul_acc_montgomery (mp, skpv, b, param);
  if (ec)
    goto leave;
  _gcry_mlkem_avx2_poly_invntt_tomont (mp);

  _gcry_mlkem_avx2_poly_sub (mp, v, mp);
  _gcry_mlkem_avx2_poly_reduce (mp);

  _gcry_mlkem_avx2_poly_tomsg (m, mp);

leave:
  _gcry_mlkem_polybuf_al_destroy (&b_al);
  _gcry_mlkem_polybuf_al_destroy (&skpv_al);
  _gcry_mlkem_polybuf_al_destroy (&v_al);
  _gcry_mlkem_polybuf_al_destroy (&mp_al);
  return ec;
}
