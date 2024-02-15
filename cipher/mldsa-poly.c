/* mldsa-poly.c
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

#include <config.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-poly.h"
#include "mldsa-ntt.h"
#include "mldsa-reduce.h"
#include "mldsa-rounding.h"
#include "mldsa-symmetric.h"

/*************************************************
 * Name:        _gcry_mldsa_poly_reduce
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283009,6283007].
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_poly_reduce (gcry_mldsa_poly *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    a->coeffs[i] = _gcry_mldsa_reduce32 (a->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_caddq
 *
 * Description: For all coefficients of in/out polynomial add GCRY_MLDSA_Q if
 *              coefficient is negative.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_poly_caddq (gcry_mldsa_poly *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    a->coeffs[i] = _gcry_mldsa_caddq (a->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first summand
 *              - const gcry_mldsa_poly *b: pointer to second summand
 **************************************************/
void _gcry_mldsa_poly_add (gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/*************************************************
 * Name:        _gcry_mldsa_poly_sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first input polynomial
 *              - const gcry_mldsa_poly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
void _gcry_mldsa_poly_sub (gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/*************************************************
 * Name:        _gcry_mldsa_poly_shiftl
 *
 * Description: Multiply polynomial by 2^GCRY_MLDSA_D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-GCRY_MLDSA_D} in absolute value.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_poly_shiftl (gcry_mldsa_poly *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    a->coeffs[i] <<= GCRY_MLDSA_D;
}

/*************************************************
 * Name:        _gcry_mldsa_poly_ntt
 *
 * Description: Inplace forward NTT. Coefficients can grow by
 *              8*GCRY_MLDSA_Q in absolute value.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_poly_ntt (gcry_mldsa_poly *a)
{
  _gcry_mldsa_ntt (a->coeffs);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_invntt_tomont
 *
 * Description: Inplace inverse NTT and multiplication by 2^{32}.
 *              Input coefficients need to be less than GCRY_MLDSA_Q in absolute
 *              value and output coefficients are again bounded by GCRY_MLDSA_Q.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_poly_invntt_tomont (gcry_mldsa_poly *a)
{
  _gcry_mldsa_invntt_tomont (a->coeffs);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_pointwise_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first input polynomial
 *              - const gcry_mldsa_poly *b: pointer to second input polynomial
 **************************************************/
void _gcry_mldsa_poly_pointwise_montgomery (gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    c->coeffs[i] = _gcry_mldsa_montgomery_reduce ((int64_t)a->coeffs[i] * b->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_power2round
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute c0, c1 such that c mod GCRY_MLDSA_Q = c1*2^GCRY_MLDSA_D + c0
 *              with -2^{GCRY_MLDSA_D-1} < c0 <= 2^{GCRY_MLDSA_D-1}. Assumes coefficients to be
 *              standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *a1: pointer to output polynomial with coefficients c1
 *              - gcry_mldsa_poly *a0: pointer to output polynomial with coefficients c0
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_poly_power2round (gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a)
{
  unsigned int i;
  for (i = 0; i < GCRY_MLDSA_N; ++i)
    a1->coeffs[i] = _gcry_mldsa_power2round (&a0->coeffs[i], a->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_decompose
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute high and low bits c0, c1 such c mod GCRY_MLDSA_Q = c1*ALPHA + c0
 *              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (GCRY_MLDSA_Q-1)/ALPHA where we
 *              set c1 = 0 and -ALPHA/2 <= c0 = c mod GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0.
 *              Assumes coefficients to be standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *a1: pointer to output polynomial with coefficients c1
 *              - gcry_mldsa_poly *a0: pointer to output polynomial with coefficients c0
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_poly_decompose (gcry_mldsa_param_t *params,
                                 gcry_mldsa_poly *a1,
                                 gcry_mldsa_poly *a0,
                                 const gcry_mldsa_poly *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    a1->coeffs[i] = _gcry_mldsa_decompose (params, &a0->coeffs[i], a->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_make_hint
 *
 * Description: Compute hint polynomial. The coefficients of which indicate
 *              whether the low bits of the corresponding coefficient of
 *              the input polynomial overflow into the high bits.
 *
 * Arguments:   - gcry_mldsa_poly *h: pointer to output hint polynomial
 *              - const gcry_mldsa_poly *a0: pointer to low part of input polynomial
 *              - const gcry_mldsa_poly *a1: pointer to high part of input polynomial
 *
 * Returns number of 1 bits.
 **************************************************/
unsigned int _gcry_mldsa_poly_make_hint (gcry_mldsa_param_t *params,
                                         gcry_mldsa_poly *h,
                                         const gcry_mldsa_poly *a0,
                                         const gcry_mldsa_poly *a1)
{
  unsigned int i, s = 0;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    {
      h->coeffs[i] = _gcry_mldsa_make_hint (params, a0->coeffs[i], a1->coeffs[i]);
      s += h->coeffs[i];
    }

  return s;
}

/*************************************************
 * Name:        _gcry_mldsa_poly_use_hint
 *
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 *
 * Arguments:   - gcry_mldsa_poly *b: pointer to output polynomial with corrected high bits
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 *              - const gcry_mldsa_poly *h: pointer to input hint polynomial
 **************************************************/
void _gcry_mldsa_poly_use_hint (gcry_mldsa_param_t *params,
                                gcry_mldsa_poly *b,
                                const gcry_mldsa_poly *a,
                                const gcry_mldsa_poly *h)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    b->coeffs[i] = _gcry_mldsa_use_hint (params, a->coeffs[i], h->coeffs[i]);
}

/*************************************************
 * Name:        _gcry_mldsa_poly_chknorm
 *
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input coefficients were reduced by _gcry_mldsa_reduce32().
 *
 * Arguments:   - const gcry_mldsa_poly *a: pointer to polynomial
 *              - s32 B: norm bound
 *
 * Returns 0 if norm is strictly smaller than B <= (GCRY_MLDSA_Q-1)/8 and 1 otherwise.
 **************************************************/
int _gcry_mldsa_poly_chknorm (const gcry_mldsa_poly *a, s32 B)
{
  unsigned int i;
  s32 t;

  if (B > (GCRY_MLDSA_Q - 1) / 8)
    return 1;

  /* It is ok to leak which coefficient violates the bound since
     the probability for each coefficient is independent of secret
     data but we must not leak the sign of the centralized representative. */
  for (i = 0; i < GCRY_MLDSA_N; ++i)
    {
      /* Absolute value */
      t = a->coeffs[i] >> 31;
      t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

      if (t >= B)
        {
          return 1;
        }
    }

  return 0;
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Sample uniformly random coefficients in [0, GCRY_MLDSA_Q-1] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - s32 *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const byte *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static unsigned int rej_uniform (s32 *a, unsigned int len, const byte *buf, unsigned int buflen)
{
  unsigned int ctr, pos;
  u32 t;

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen)
    {
      t = buf[pos++];
      t |= (u32)buf[pos++] << 8;
      t |= (u32)buf[pos++] << 16;
      t &= 0x7FFFFF;

      if (t < GCRY_MLDSA_Q)
        a[ctr++] = t;
    }

  return ctr;
}

/*************************************************
 * Name:        _gcry_mldsa_poly_uniform
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [0,GCRY_MLDSA_Q-1] by performing rejection sampling on the
 *              output stream of SHAKE256(seed|nonce).
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to output polynomial
 *              - const byte seed[]: byte array with seed of length GCRY_MLDSA_SEEDBYTES
 *              - u16 nonce: 2-byte nonce
 **************************************************/
#define POLY_UNIFORM_NBLOCKS ((768 + GCRY_STREAM128_BLOCKBYTES - 1) / GCRY_STREAM128_BLOCKBYTES)
gcry_err_code_t _gcry_mldsa_poly_uniform (gcry_mldsa_poly *a, const byte seed[GCRY_MLDSA_SEEDBYTES], u16 nonce)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t md    = NULL;
  unsigned int i, ctr, off;
  unsigned int buflen;
  byte *buf = NULL;

  buflen = POLY_UNIFORM_NBLOCKS * GCRY_STREAM128_BLOCKBYTES;
  buf    = xtrymalloc_secure (buflen + 2);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_mldsa_shake128_stream_init (&md, seed, nonce);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake128_squeeze_nblocks (md, POLY_UNIFORM_NBLOCKS, buf);
  if (ec)
    goto leave;

  ctr = rej_uniform (a->coeffs, GCRY_MLDSA_N, buf, buflen);

  while (ctr < GCRY_MLDSA_N)
    {
      off = buflen % 3;
      for (i = 0; i < off; ++i)
        buf[i] = buf[buflen - off + i];

      ec = _gcry_mldsa_shake128_squeeze_nblocks (md, 1, buf + off);
      if (ec)
        goto leave;
      buflen = GCRY_STREAM128_BLOCKBYTES + off;
      ctr += rej_uniform (a->coeffs + ctr, GCRY_MLDSA_N - ctr, buf, buflen);
    }

leave:
  xfree (buf);
  _gcry_md_close (md);
  return ec;
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-params->eta, params->eta] by
 *              performing rejection sampling on array of random bytes.
 *
 * Arguments:   - s32 *a: pointer to output array (allocated)
 *              - unsigned int len: number of coefficients to be sampled
 *              - const byte *buf: array of random bytes
 *              - unsigned int buflen: length of array of random bytes
 *
 * Returns number of sampled coefficients. Can be smaller than len if not enough
 * random bytes were given.
 **************************************************/
static unsigned int rej_eta (gcry_mldsa_param_t *params, s32 *a, unsigned int len, const byte *buf, unsigned int buflen)
{
  unsigned int ctr, pos;
  u32 t0, t1;

  ctr = pos = 0;
  while (ctr < len && pos < buflen)
    {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

      if (params->eta == 2)
        {
          if (t0 < 15)
            {
              t0       = t0 - (205 * t0 >> 10) * 5;
              a[ctr++] = 2 - t0;
            }
          if (t1 < 15 && ctr < len)
            {
              t1       = t1 - (205 * t1 >> 10) * 5;
              a[ctr++] = 2 - t1;
            }
        }
      else if (params->eta == 4)
        {
          if (t0 < 9)
            a[ctr++] = 4 - t0;
          if (t1 < 9 && ctr < len)
            a[ctr++] = 4 - t1;
        }
    }

  return ctr;
}

/*************************************************
 * Name:        _gcry_mldsa_poly_uniform_eta
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-params->eta,params->eta] by performing rejection sampling on the
 *              output stream from SHAKE256(seed|nonce).
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to output polynomial
 *              - const byte seed[]: byte array with seed of length GCRY_MLDSA_CRHBYTES
 *              - u16 nonce: 2-byte nonce
 **************************************************/
gcry_err_code_t _gcry_mldsa_poly_uniform_eta (gcry_mldsa_param_t *params,
                                              gcry_mldsa_poly *a,
                                              const byte seed[GCRY_MLDSA_CRHBYTES],
                                              u16 nonce)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t md    = NULL;
  unsigned int ctr;
  unsigned int buflen;
  byte *buf = NULL;
  unsigned int POLY_UNIFORM_ETA_NBLOCKS;

  if (params->eta == 2)
    {
      POLY_UNIFORM_ETA_NBLOCKS = ((136 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES);
    }
  else if (params->eta == 4)
    {
      POLY_UNIFORM_ETA_NBLOCKS = ((227 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES);
    }
  buflen = POLY_UNIFORM_ETA_NBLOCKS * GCRY_STREAM256_BLOCKBYTES;
  buf    = xtrymalloc_secure (buflen);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_mldsa_shake256_stream_init (&md, seed, nonce);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256_squeeze_nblocks (md, POLY_UNIFORM_ETA_NBLOCKS, buf);
  if (ec)
    goto leave;

  ctr = rej_eta (params, a->coeffs, GCRY_MLDSA_N, buf, buflen);

  while (ctr < GCRY_MLDSA_N)
    {
      ec = _gcry_mldsa_shake256_squeeze_nblocks (md, 1, buf);
      if (ec)
        goto leave;
      ctr += rej_eta (params, a->coeffs + ctr, GCRY_MLDSA_N - ctr, buf, GCRY_STREAM256_BLOCKBYTES);
    }

leave:
  _gcry_md_close (md);
  xfree (buf);
  return ec;
}

/*************************************************
 * Name:        poly_uniform_gamma1m1
 *
 * Description: Sample polynomial with uniformly random coefficients
 *              in [-(params->gamma1 - 1), params->gamma1] by unpacking output stream
 *              of SHAKE256(seed|nonce)
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to output polynomial
 *              - const byte seed[]: byte array with seed of length GCRY_MLDSA_CRHBYTES
 *              - u16 nonce: 16-bit nonce
 **************************************************/
gcry_err_code_t _gcry_mldsa_poly_uniform_gamma1 (gcry_mldsa_param_t *params,
                                                 gcry_mldsa_poly *a,
                                                 const byte seed[GCRY_MLDSA_CRHBYTES],
                                                 u16 nonce)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t md    = NULL;
  unsigned int POLY_UNIFORM_GAMMA1_NBLOCKS
      = ((params->polyz_packedbytes + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES);
  unsigned int buflen = POLY_UNIFORM_GAMMA1_NBLOCKS * GCRY_STREAM256_BLOCKBYTES;
  byte *buf           = NULL;

  buf = xtrymalloc_secure (buflen);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_mldsa_shake256_stream_init (&md, seed, nonce);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256_squeeze_nblocks (md, POLY_UNIFORM_GAMMA1_NBLOCKS, buf);
  if (ec)
    goto leave;


  _gcry_mldsa_polyz_unpack (params, a, buf);

leave:
  xfree (buf);
  _gcry_md_close (md);
  return ec;
}

/*************************************************
 * Name:        _gcry_mldsa_poly_challenge
 *
 * Description: Implementation of H. Samples polynomial with params->tau nonzero
 *              coefficients in {-1,1} using the output stream of
 *              SHAKE256(seed).
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const byte mu[]: byte array containing seed of length GCRY_MLDSA_SEEDBYTES
 **************************************************/
gcry_err_code_t _gcry_mldsa_poly_challenge (gcry_mldsa_param_t *params,
                                            gcry_mldsa_poly *c,
                                            const byte seed[GCRY_MLDSA_SEEDBYTES])
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t hd    = NULL;
  unsigned int i, b, pos;
  uint64_t signs;
  byte *buf = NULL;

  buf = xtrymalloc_secure (GCRY_SHAKE256_RATE);
  if (!buf)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  ec = _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write (hd, seed, GCRY_MLDSA_SEEDBYTES);
  ec = _gcry_mldsa_shake256_squeeze_nblocks (hd, 1, buf);
  if (ec)
    goto leave;

  signs = 0;
  for (i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8 * i;
  pos = 8;

  for (i = 0; i < GCRY_MLDSA_N; ++i)
    c->coeffs[i] = 0;
  for (i = GCRY_MLDSA_N - params->tau; i < GCRY_MLDSA_N; ++i)
    {
      do
        {
          if (pos >= GCRY_SHAKE256_RATE)
            {
              ec = _gcry_mldsa_shake256_squeeze_nblocks (hd, 1, buf);
              if (ec)
                goto leave;
              pos = 0;
            }

          b = buf[pos++];
        }
      while (b > i);

      c->coeffs[i] = c->coeffs[b];
      c->coeffs[b] = 1 - 2 * (signs & 1);
      signs >>= 1;
    }

leave:
  xfree (buf);
  _gcry_md_close (hd);
  return ec;
}

/*************************************************
 * Name:        _gcry_mldsa_polyeta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-params->eta,params->eta].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            params->polyeta_packedbytes bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_polyeta_pack (gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a)
{
  unsigned int i;
  byte t[8];

  if (params->eta == 2)
    {
      for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
        {
          t[0] = params->eta - a->coeffs[8 * i + 0];
          t[1] = params->eta - a->coeffs[8 * i + 1];
          t[2] = params->eta - a->coeffs[8 * i + 2];
          t[3] = params->eta - a->coeffs[8 * i + 3];
          t[4] = params->eta - a->coeffs[8 * i + 4];
          t[5] = params->eta - a->coeffs[8 * i + 5];
          t[6] = params->eta - a->coeffs[8 * i + 6];
          t[7] = params->eta - a->coeffs[8 * i + 7];

          r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
          r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
          r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        }
    }
  else if (params->eta == 4)
    {
      for (i = 0; i < GCRY_MLDSA_N / 2; ++i)
        {
          t[0] = params->eta - a->coeffs[2 * i + 0];
          t[1] = params->eta - a->coeffs[2 * i + 1];
          r[i] = t[0] | (t[1] << 4);
        }
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyeta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-params->eta,params->eta].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_polyeta_unpack (gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const byte *a)
{
  unsigned int i;

  if (params->eta == 2)
    {
      for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
        {
          r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
          r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
          r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
          r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
          r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
          r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
          r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
          r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

          r->coeffs[8 * i + 0] = params->eta - r->coeffs[8 * i + 0];
          r->coeffs[8 * i + 1] = params->eta - r->coeffs[8 * i + 1];
          r->coeffs[8 * i + 2] = params->eta - r->coeffs[8 * i + 2];
          r->coeffs[8 * i + 3] = params->eta - r->coeffs[8 * i + 3];
          r->coeffs[8 * i + 4] = params->eta - r->coeffs[8 * i + 4];
          r->coeffs[8 * i + 5] = params->eta - r->coeffs[8 * i + 5];
          r->coeffs[8 * i + 6] = params->eta - r->coeffs[8 * i + 6];
          r->coeffs[8 * i + 7] = params->eta - r->coeffs[8 * i + 7];
        }
    }
  else if (params->eta == 4)
    {
      for (i = 0; i < GCRY_MLDSA_N / 2; ++i)
        {
          r->coeffs[2 * i + 0] = a[i] & 0x0F;
          r->coeffs[2 * i + 1] = a[i] >> 4;
          r->coeffs[2 * i + 0] = params->eta - r->coeffs[2 * i + 0];
          r->coeffs[2 * i + 1] = params->eta - r->coeffs[2 * i + 1];
        }
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyt1_pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            GCRY_MLDSA_POLYT1_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_polyt1_pack (byte *r, const gcry_mldsa_poly *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N / 4; ++i)
    {
      r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0);
      r[5 * i + 1] = (a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2);
      r[5 * i + 2] = (a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4);
      r[5 * i + 3] = (a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6);
      r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2);
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyt1_unpack
 *
 * Description: Unpack polynomial t1 with 10-bit coefficients.
 *              Output coefficients are standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_polyt1_unpack (gcry_mldsa_poly *r, const byte *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N / 4; ++i)
    {
      r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((u32)a[5 * i + 1] << 8)) & 0x3FF;
      r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((u32)a[5 * i + 2] << 6)) & 0x3FF;
      r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((u32)a[5 * i + 3] << 4)) & 0x3FF;
      r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((u32)a[5 * i + 4] << 2)) & 0x3FF;
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyt0_pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{GCRY_MLDSA_D-1}, 2^{GCRY_MLDSA_D-1}].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            GCRY_MLDSA_POLYT0_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_polyt0_pack (byte *r, const gcry_mldsa_poly *a)
{
  unsigned int i;
  u32 t[8];

  for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
    {
      t[0] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 0];
      t[1] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 1];
      t[2] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 2];
      t[3] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 3];
      t[4] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 4];
      t[5] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 5];
      t[6] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 6];
      t[7] = (1 << (GCRY_MLDSA_D - 1)) - a->coeffs[8 * i + 7];

      r[13 * i + 0] = t[0];
      r[13 * i + 1] = t[0] >> 8;
      r[13 * i + 1] |= t[1] << 5;
      r[13 * i + 2] = t[1] >> 3;
      r[13 * i + 3] = t[1] >> 11;
      r[13 * i + 3] |= t[2] << 2;
      r[13 * i + 4] = t[2] >> 6;
      r[13 * i + 4] |= t[3] << 7;
      r[13 * i + 5] = t[3] >> 1;
      r[13 * i + 6] = t[3] >> 9;
      r[13 * i + 6] |= t[4] << 4;
      r[13 * i + 7] = t[4] >> 4;
      r[13 * i + 8] = t[4] >> 12;
      r[13 * i + 8] |= t[5] << 1;
      r[13 * i + 9] = t[5] >> 7;
      r[13 * i + 9] |= t[6] << 6;
      r[13 * i + 10] = t[6] >> 2;
      r[13 * i + 11] = t[6] >> 10;
      r[13 * i + 11] |= t[7] << 3;
      r[13 * i + 12] = t[7] >> 5;
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyt0_unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{GCRY_MLDSA_D-1}, 2^{GCRY_MLDSA_D-1}].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_polyt0_unpack (gcry_mldsa_poly *r, const byte *a)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
    {
      r->coeffs[8 * i + 0] = a[13 * i + 0];
      r->coeffs[8 * i + 0] |= (u32)a[13 * i + 1] << 8;
      r->coeffs[8 * i + 0] &= 0x1FFF;

      r->coeffs[8 * i + 1] = a[13 * i + 1] >> 5;
      r->coeffs[8 * i + 1] |= (u32)a[13 * i + 2] << 3;
      r->coeffs[8 * i + 1] |= (u32)a[13 * i + 3] << 11;
      r->coeffs[8 * i + 1] &= 0x1FFF;

      r->coeffs[8 * i + 2] = a[13 * i + 3] >> 2;
      r->coeffs[8 * i + 2] |= (u32)a[13 * i + 4] << 6;
      r->coeffs[8 * i + 2] &= 0x1FFF;

      r->coeffs[8 * i + 3] = a[13 * i + 4] >> 7;
      r->coeffs[8 * i + 3] |= (u32)a[13 * i + 5] << 1;
      r->coeffs[8 * i + 3] |= (u32)a[13 * i + 6] << 9;
      r->coeffs[8 * i + 3] &= 0x1FFF;

      r->coeffs[8 * i + 4] = a[13 * i + 6] >> 4;
      r->coeffs[8 * i + 4] |= (u32)a[13 * i + 7] << 4;
      r->coeffs[8 * i + 4] |= (u32)a[13 * i + 8] << 12;
      r->coeffs[8 * i + 4] &= 0x1FFF;

      r->coeffs[8 * i + 5] = a[13 * i + 8] >> 1;
      r->coeffs[8 * i + 5] |= (u32)a[13 * i + 9] << 7;
      r->coeffs[8 * i + 5] &= 0x1FFF;

      r->coeffs[8 * i + 6] = a[13 * i + 9] >> 6;
      r->coeffs[8 * i + 6] |= (u32)a[13 * i + 10] << 2;
      r->coeffs[8 * i + 6] |= (u32)a[13 * i + 11] << 10;
      r->coeffs[8 * i + 6] &= 0x1FFF;

      r->coeffs[8 * i + 7] = a[13 * i + 11] >> 3;
      r->coeffs[8 * i + 7] |= (u32)a[13 * i + 12] << 5;
      r->coeffs[8 * i + 7] &= 0x1FFF;

      r->coeffs[8 * i + 0] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 0];
      r->coeffs[8 * i + 1] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 1];
      r->coeffs[8 * i + 2] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 2];
      r->coeffs[8 * i + 3] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 3];
      r->coeffs[8 * i + 4] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 4];
      r->coeffs[8 * i + 5] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 5];
      r->coeffs[8 * i + 6] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 6];
      r->coeffs[8 * i + 7] = (1 << (GCRY_MLDSA_D - 1)) - r->coeffs[8 * i + 7];
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyz_pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(params->gamma1 - 1), params->gamma1].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            params->polyz_packedbytes bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_polyz_pack (gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a)
{
  unsigned int i;
  u32 t[4];

  if (params->gamma1 == (1 << 17))
    {
      for (i = 0; i < GCRY_MLDSA_N / 4; ++i)
        {
          t[0] = params->gamma1 - a->coeffs[4 * i + 0];
          t[1] = params->gamma1 - a->coeffs[4 * i + 1];
          t[2] = params->gamma1 - a->coeffs[4 * i + 2];
          t[3] = params->gamma1 - a->coeffs[4 * i + 3];

          r[9 * i + 0] = t[0];
          r[9 * i + 1] = t[0] >> 8;
          r[9 * i + 2] = t[0] >> 16;
          r[9 * i + 2] |= t[1] << 2;
          r[9 * i + 3] = t[1] >> 6;
          r[9 * i + 4] = t[1] >> 14;
          r[9 * i + 4] |= t[2] << 4;
          r[9 * i + 5] = t[2] >> 4;
          r[9 * i + 6] = t[2] >> 12;
          r[9 * i + 6] |= t[3] << 6;
          r[9 * i + 7] = t[3] >> 2;
          r[9 * i + 8] = t[3] >> 10;
        }
    }
  else if (params->gamma1 == (1 << 19))
    {
      for (i = 0; i < GCRY_MLDSA_N / 2; ++i)
        {
          t[0] = params->gamma1 - a->coeffs[2 * i + 0];
          t[1] = params->gamma1 - a->coeffs[2 * i + 1];

          r[5 * i + 0] = t[0];
          r[5 * i + 1] = t[0] >> 8;
          r[5 * i + 2] = t[0] >> 16;
          r[5 * i + 2] |= t[1] << 4;
          r[5 * i + 3] = t[1] >> 4;
          r[5 * i + 4] = t[1] >> 12;
        }
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyz_unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(params->gamma1 - 1), params->gamma1].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_polyz_unpack (gcry_mldsa_param_t *params, gcry_mldsa_poly *r, const byte *a)
{
  unsigned int i;

  if (params->gamma1 == (1 << 17))
    {
      for (i = 0; i < GCRY_MLDSA_N / 4; ++i)
        {
          r->coeffs[4 * i + 0] = a[9 * i + 0];
          r->coeffs[4 * i + 0] |= (u32)a[9 * i + 1] << 8;
          r->coeffs[4 * i + 0] |= (u32)a[9 * i + 2] << 16;
          r->coeffs[4 * i + 0] &= 0x3FFFF;

          r->coeffs[4 * i + 1] = a[9 * i + 2] >> 2;
          r->coeffs[4 * i + 1] |= (u32)a[9 * i + 3] << 6;
          r->coeffs[4 * i + 1] |= (u32)a[9 * i + 4] << 14;
          r->coeffs[4 * i + 1] &= 0x3FFFF;

          r->coeffs[4 * i + 2] = a[9 * i + 4] >> 4;
          r->coeffs[4 * i + 2] |= (u32)a[9 * i + 5] << 4;
          r->coeffs[4 * i + 2] |= (u32)a[9 * i + 6] << 12;
          r->coeffs[4 * i + 2] &= 0x3FFFF;

          r->coeffs[4 * i + 3] = a[9 * i + 6] >> 6;
          r->coeffs[4 * i + 3] |= (u32)a[9 * i + 7] << 2;
          r->coeffs[4 * i + 3] |= (u32)a[9 * i + 8] << 10;
          r->coeffs[4 * i + 3] &= 0x3FFFF;

          r->coeffs[4 * i + 0] = params->gamma1 - r->coeffs[4 * i + 0];
          r->coeffs[4 * i + 1] = params->gamma1 - r->coeffs[4 * i + 1];
          r->coeffs[4 * i + 2] = params->gamma1 - r->coeffs[4 * i + 2];
          r->coeffs[4 * i + 3] = params->gamma1 - r->coeffs[4 * i + 3];
        }
    }
  else if (params->gamma1 == (1 << 19))
    {
      for (i = 0; i < GCRY_MLDSA_N / 2; ++i)
        {
          r->coeffs[2 * i + 0] = a[5 * i + 0];
          r->coeffs[2 * i + 0] |= (u32)a[5 * i + 1] << 8;
          r->coeffs[2 * i + 0] |= (u32)a[5 * i + 2] << 16;
          r->coeffs[2 * i + 0] &= 0xFFFFF;

          r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
          r->coeffs[2 * i + 1] |= (u32)a[5 * i + 3] << 4;
          r->coeffs[2 * i + 1] |= (u32)a[5 * i + 4] << 12;

          r->coeffs[2 * i + 0] = params->gamma1 - r->coeffs[2 * i + 0];
          r->coeffs[2 * i + 1] = params->gamma1 - r->coeffs[2 * i + 1];
        }
    }
}

/*************************************************
 * Name:        _gcry_mldsa_polyw1_pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be standard representatives.
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            params->polyw1_packedbytes bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_polyw1_pack (gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *a)
{
  unsigned int i;

  if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 88)
    {
      for (i = 0; i < GCRY_MLDSA_N / 4; ++i)
        {
          r[3 * i + 0] = a->coeffs[4 * i + 0];
          r[3 * i + 0] |= a->coeffs[4 * i + 1] << 6;
          r[3 * i + 1] = a->coeffs[4 * i + 1] >> 2;
          r[3 * i + 1] |= a->coeffs[4 * i + 2] << 4;
          r[3 * i + 2] = a->coeffs[4 * i + 2] >> 4;
          r[3 * i + 2] |= a->coeffs[4 * i + 3] << 2;
        }
    }
  else if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 32)
    {
      for (i = 0; i < GCRY_MLDSA_N / 2; ++i)
        {
          r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
        }
    }
}
