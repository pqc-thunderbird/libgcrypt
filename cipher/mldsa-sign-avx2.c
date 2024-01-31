/* mldsa-sign-avx2.c
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

#include "avx2-immintrin-support.h"
#ifdef USE_AVX2
#include "config.h"
#include "mldsa-sign.h"
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly-avx2.h"
#include "mldsa-symmetric.h"

static inline gcry_err_code_t
polyvec_matrix_expand_row (gcry_mldsa_param_t *params,
                           byte **row,
                           byte *buf,
                           const byte rho[GCRY_MLDSA_SEEDBYTES],
                           unsigned int i)
{
  gcry_err_code_t ec  = 0;
  const size_t offset = params->l * sizeof (gcry_mldsa_poly);

  switch (i)
    {
    case 0:
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row0 (
          params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 1:
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row1 (
          params, buf + offset, buf, rho);
      *row = buf + offset;
      break;
    case 2:
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row2 (
          params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 3:
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row3 (
          params, buf + offset, rho);
      *row = buf + offset;
      break;
    case 4:
      if (params->k <= 4)
        break;
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row4 (
          params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 5:
      if (params->k <= 4)
        break;
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row5 (
          params, buf + offset, buf, rho);
      *row = buf + offset;
      break;
    case 6:
      if (params->k <= 6)
        break;
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row6 (
          params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 7:
      if (params->k <= 6)
        break;
      ec = _gcry_mldsa_avx2_polyvec_matrix_expand_row7 (
          params, buf + offset, rho);
      *row = buf + offset;
      break;
    }

  return ec;
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - byte *pk: pointer to output public key (allocated
 *                             array of CRYPTO_PUBLICKEYBYTES bytes)
 *              - byte *sk: pointer to output private key (allocated
 *                             array of CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success)
 **************************************************/
gcry_err_code_t
_gcry_mldsa_avx2_keypair (gcry_mldsa_param_t *params, byte *pk, byte *sk)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  byte *seedbuf = NULL;
  const byte *rho, *rhoprime, *key;
  gcry_mldsa_polybuf_al rowbuf = {};
  byte *row                    = NULL;
  gcry_mldsa_polybuf_al s1     = {};
  gcry_mldsa_polybuf_al s2     = {};
  gcry_mldsa_polybuf_al t1     = {};
  gcry_mldsa_polybuf_al t0     = {};
  const size_t polysize        = sizeof (gcry_mldsa_poly);

  if ((ec = _gcry_mldsa_polybuf_al_create (&rowbuf, 2, params->l, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&s1, 1, params->l, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&s2, 1, params->k, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&t1, 1, 1, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&t0, 1, 1, 1)))
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  row = rowbuf.buf;

  if (!(seedbuf
        = xtrymalloc_secure (2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES)))
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  /* Get randomness for rho, rhoprime and key */
  _gcry_randomize (seedbuf, GCRY_MLDSA_SEEDBYTES, GCRY_VERY_STRONG_RANDOM);

  ec = _gcry_mldsa_shake256 (seedbuf,
                             GCRY_MLDSA_SEEDBYTES,
                             NULL,
                             0,
                             seedbuf,
                             2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  rho      = seedbuf;
  rhoprime = rho + GCRY_MLDSA_SEEDBYTES;
  key      = rhoprime + GCRY_MLDSA_CRHBYTES;

  /* Store rho, key */
  memcpy (pk, rho, GCRY_MLDSA_SEEDBYTES);
  memcpy (sk, rho, GCRY_MLDSA_SEEDBYTES);
  memcpy (sk + GCRY_MLDSA_SEEDBYTES, key, GCRY_MLDSA_SEEDBYTES);

  /* Sample short vectors s1 and s2 */
  ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
      params,
      (gcry_mldsa_poly *)&s1.buf[0 * polysize],
      (gcry_mldsa_poly *)&s1.buf[1 * polysize],
      (gcry_mldsa_poly *)&s1.buf[2 * polysize],
      (gcry_mldsa_poly *)&s1.buf[3 * polysize],
      rhoprime,
      0,
      1,
      2,
      3);
  if (ec)
    goto leave;
  if (params->k == 4 && params->l == 4)
    {
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s2.buf[0 * polysize],
          (gcry_mldsa_poly *)&s2.buf[1 * polysize],
          (gcry_mldsa_poly *)&s2.buf[2 * polysize],
          (gcry_mldsa_poly *)&s2.buf[3 * polysize],
          rhoprime,
          4,
          5,
          6,
          7);
      if (ec)
        goto leave;
    }
  else if (params->k == 6 && params->l == 5)
    {
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s1.buf[4 * polysize],
          (gcry_mldsa_poly *)&s2.buf[0 * polysize],
          (gcry_mldsa_poly *)&s2.buf[1 * polysize],
          (gcry_mldsa_poly *)&s2.buf[2 * polysize],
          rhoprime,
          4,
          5,
          6,
          7);
      if (ec)
        goto leave;
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s2.buf[3 * polysize],
          (gcry_mldsa_poly *)&s2.buf[4 * polysize],
          (gcry_mldsa_poly *)&s2.buf[5 * polysize],
          (gcry_mldsa_poly *)t0.buf,
          rhoprime,
          8,
          9,
          10,
          11);
      if (ec)
        goto leave;
    }
  else if (params->k == 8 && params->l == 7)
    {
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s1.buf[4 * polysize],
          (gcry_mldsa_poly *)&s1.buf[5 * polysize],
          (gcry_mldsa_poly *)&s1.buf[6 * polysize],
          (gcry_mldsa_poly *)&s2.buf[0 * polysize],
          rhoprime,
          4,
          5,
          6,
          7);
      if (ec)
        goto leave;
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s2.buf[1 * polysize],
          (gcry_mldsa_poly *)&s2.buf[2 * polysize],
          (gcry_mldsa_poly *)&s2.buf[3 * polysize],
          (gcry_mldsa_poly *)&s2.buf[4 * polysize],
          rhoprime,
          8,
          9,
          10,
          11);
      if (ec)
        goto leave;
      ec = _gcry_mldsa_avx2_poly_uniform_eta_4x (
          params,
          (gcry_mldsa_poly *)&s2.buf[5 * polysize],
          (gcry_mldsa_poly *)&s2.buf[6 * polysize],
          (gcry_mldsa_poly *)&s2.buf[7 * polysize],
          (gcry_mldsa_poly *)t0.buf,
          rhoprime,
          12,
          13,
          14,
          15);
      if (ec)
        goto leave;
    }
  else
    {
      ec = GPG_ERR_INV_STATE;
      goto leave;
    }
  /* Pack secret vectors */
  for (i = 0; i < params->l; i++)
    _gcry_mldsa_avx2_polyeta_pack (params,
                                   sk + 2 * GCRY_MLDSA_SEEDBYTES
                                       + GCRY_MLDSA_TRBYTES
                                       + i * params->polyeta_packedbytes,
                                   (gcry_mldsa_poly *)&s1.buf[i * polysize]);
  for (i = 0; i < params->k; i++)
    _gcry_mldsa_avx2_polyeta_pack (
        params,
        sk + 2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES
            + (params->l + i) * params->polyeta_packedbytes,
        (gcry_mldsa_poly *)&s2.buf[i * polysize]);

  /* Transform s1 */
  _gcry_mldsa_avx2_polyvecl_ntt (params, s1.buf);

  for (i = 0; i < params->k; i++)
    {
      /* Expand matrix row */
      ec = polyvec_matrix_expand_row (params, &row, rowbuf.buf, rho, i);
      if (ec)
        goto leave;

      /* Compute inner-product */
      _gcry_mldsa_avx2_polyvecl_pointwise_acc_montgomery (
          params, (gcry_mldsa_poly *)t1.buf, row, s1.buf);
      _gcry_mldsa_avx2_poly_invntt_tomont ((gcry_mldsa_poly *)t1.buf);

      /* Add error polynomial */
      _gcry_mldsa_avx2_poly_add ((gcry_mldsa_poly *)t1.buf,
                                 (gcry_mldsa_poly *)t1.buf,
                                 (gcry_mldsa_poly *)&s2.buf[i * polysize]);

      /* Round t and pack t1, t0 */
      _gcry_mldsa_avx2_poly_caddq ((gcry_mldsa_poly *)t1.buf);
      _gcry_mldsa_avx2_poly_power2round ((gcry_mldsa_poly *)t1.buf,
                                         (gcry_mldsa_poly *)t0.buf,
                                         (gcry_mldsa_poly *)t1.buf);
      _gcry_mldsa_avx2_polyt1_pack (pk + GCRY_MLDSA_SEEDBYTES
                                        + i * GCRY_MLDSA_POLYT1_PACKEDBYTES,
                                    (gcry_mldsa_poly *)t1.buf);
      _gcry_mldsa_avx2_polyt0_pack (
          sk + 2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES
              + (params->l + params->k) * params->polyeta_packedbytes
              + i * GCRY_MLDSA_POLYT0_PACKEDBYTES,
          (gcry_mldsa_poly *)t0.buf);
    }

  /* Compute H(rho, t1) and store in secret key */
  ec = _gcry_mldsa_shake256 (pk,
                             params->public_key_bytes,
                             NULL,
                             0,
                             sk + 2 * GCRY_MLDSA_SEEDBYTES,
                             GCRY_MLDSA_TRBYTES);
  if (ec)
    goto leave;

leave:
  xfree (seedbuf);
  _gcry_mldsa_polybuf_al_destroy (&rowbuf);
  _gcry_mldsa_polybuf_al_destroy (&s1);
  _gcry_mldsa_polybuf_al_destroy (&s2);
  _gcry_mldsa_polybuf_al_destroy (&t1);
  _gcry_mldsa_polybuf_al_destroy (&t0);
  return 0;
}

/*************************************************
 * Name:        _gcry_mldsa_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - byte *sig: pointer to output signature (of length CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - byte *m: pointer to message to be signed
 *              - size_t mlen: length of message
 *              - byte *sk: pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
gcry_err_code_t
_gcry_mldsa_avx2_sign (gcry_mldsa_param_t *params,
                       byte *sig,
                       size_t *siglen,
                       const byte *m,
                       size_t mlen,
                       const byte *sk)
{
  gcry_err_code_t ec = 0;
  unsigned int i, n, pos;
  byte *seedbuf = NULL;
  byte *rho, *tr, *key, *mu, *rhoprime, *hint;
  byte *hintbuf              = NULL;
  u64 nonce                  = 0;
  gcry_mldsa_polybuf_al mat  = {};
  gcry_mldsa_polybuf_al s1   = {};
  gcry_mldsa_polybuf_al z    = {};
  gcry_mldsa_polybuf_al t0   = {};
  gcry_mldsa_polybuf_al s2   = {};
  gcry_mldsa_polybuf_al w1   = {};
  gcry_mldsa_polybuf_al tmpv = {};
  gcry_mldsa_polybuf_al c    = {};
  gcry_mldsa_polybuf_al tmp  = {};

  const size_t polysize = sizeof (gcry_mldsa_poly);
  gcry_md_hd_t hd       = NULL;

  if ((ec = _gcry_mldsa_polybuf_al_create (&mat, params->k, params->l, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&s1, 1, params->l, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&z, 1, params->l, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&tmpv, 1, params->k, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&t0, 1, params->k, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&s2, 1, params->k, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&w1, 1, params->k, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&c, 1, 1, 1))
      || (ec = _gcry_mldsa_polybuf_al_create (&tmp, 1, 1, 1)))
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  if (!(seedbuf
        = xtrymalloc_secure (2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES
                             + 2 * GCRY_MLDSA_CRHBYTES)))
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }
  if (!(hintbuf = xtrymalloc_secure (GCRY_MLDSA_N)))
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  hint = sig + params->ctildebytes + params->l * params->polyz_packedbytes;

  rho      = seedbuf;
  tr       = rho + GCRY_MLDSA_SEEDBYTES;
  key      = tr + GCRY_MLDSA_TRBYTES;
  mu       = key + GCRY_MLDSA_SEEDBYTES;
  rhoprime = mu + GCRY_MLDSA_CRHBYTES;
  _gcry_mldsa_avx2_unpack_sk (
      params, rho, tr, key, t0.buf, s1.buf, s2.buf, sk);

  /* Compute CRH(tr, msg) */
  ec = _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write (hd, tr, GCRY_MLDSA_TRBYTES);
  _gcry_md_write (hd, m, mlen);
  ec = _gcry_md_extract (hd, GCRY_MD_SHAKE256, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;
  _gcry_md_close (hd);

  ec = _gcry_mldsa_shake256 (key,
                             GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES,
                             NULL,
                             0,
                             rhoprime,
                             GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  /* Expand matrix and transform vectors */
  ec = _gcry_mldsa_avx2_polyvec_matrix_expand (params, mat.buf, rho);
  if (ec)
    goto leave;
  _gcry_mldsa_avx2_polyvecl_ntt (params, s1.buf);
  _gcry_mldsa_avx2_polyveck_ntt (params, s2.buf);
  _gcry_mldsa_avx2_polyveck_ntt (params, t0.buf);

rej:
  /* Sample intermediate vector y */
  if (params->l == 4)
    {
      ec = _gcry_mldsa_avx2_poly_uniform_gamma1_4x (params,
                                                    &z.buf[0 * polysize],
                                                    &z.buf[1 * polysize],
                                                    &z.buf[2 * polysize],
                                                    &z.buf[3 * polysize],
                                                    rhoprime,
                                                    nonce,
                                                    nonce + 1,
                                                    nonce + 2,
                                                    nonce + 3);
      if (ec)
        goto leave;
      nonce += 4;
    }
  else if (params->l == 5)
    {
      ec = _gcry_mldsa_avx2_poly_uniform_gamma1_4x (params,
                                                    &z.buf[0 * polysize],
                                                    &z.buf[1 * polysize],
                                                    &z.buf[2 * polysize],
                                                    &z.buf[3 * polysize],
                                                    rhoprime,
                                                    nonce,
                                                    nonce + 1,
                                                    nonce + 2,
                                                    nonce + 3);
      if (ec)
        goto leave;
      ec = _gcry_mldsa_avx2_poly_uniform_gamma1 (
          params,
          (gcry_mldsa_poly *)&z.buf[4 * polysize],
          rhoprime,
          nonce + 4);
      if (ec)
        goto leave;
      nonce += 5;
    }
  else if (params->l == 7)
    {

      ec = _gcry_mldsa_avx2_poly_uniform_gamma1_4x (params,
                                                    &z.buf[0 * polysize],
                                                    &z.buf[1 * polysize],
                                                    &z.buf[2 * polysize],
                                                    &z.buf[3 * polysize],
                                                    rhoprime,
                                                    nonce,
                                                    nonce + 1,
                                                    nonce + 2,
                                                    nonce + 3);
      if (ec)
        goto leave;
      ec = _gcry_mldsa_avx2_poly_uniform_gamma1_4x (params,
                                                    &z.buf[4 * polysize],
                                                    &z.buf[5 * polysize],
                                                    &z.buf[6 * polysize],
                                                    tmp.buf,
                                                    rhoprime,
                                                    nonce + 4,
                                                    nonce + 5,
                                                    nonce + 6,
                                                    0);
      if (ec)
        goto leave;
      nonce += 7;
    }
  else
    {
      return GPG_ERR_INV_STATE;
    }

  /* Matrix-vector product */
  memcpy (tmpv.buf, z.buf, params->l * polysize);
  _gcry_mldsa_avx2_polyvecl_ntt (params, tmpv.buf);
  _gcry_mldsa_avx2_polyvec_matrix_pointwise_montgomery (
      params, w1.buf, mat.buf, tmpv.buf);
  _gcry_mldsa_avx2_polyveck_invntt_tomont (params, w1.buf);

  /* Decompose w and call the random oracle */
  _gcry_mldsa_avx2_polyveck_caddq (params, w1.buf);
  _gcry_mldsa_avx2_polyveck_decompose (params, w1.buf, tmpv.buf, w1.buf);
  _gcry_mldsa_avx2_polyveck_pack_w1 (params, sig, w1.buf);

  ec = _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write (hd, mu, GCRY_MLDSA_CRHBYTES);
  _gcry_md_write (hd, sig, params->k * params->polyw1_packedbytes);
  ec = _gcry_md_extract (hd, GCRY_MD_SHAKE256, sig, params->ctildebytes);
  if (ec)
    goto leave;
  _gcry_md_close (hd);
  ec = _gcry_mldsa_poly_challenge (params, (gcry_mldsa_poly *)c.buf, sig);
  if (ec)
    goto leave;
  _gcry_mldsa_avx2_poly_ntt ((gcry_mldsa_poly *)c.buf);

  /* Compute z, reject if it reveals secret */
  for (i = 0; i < params->l; i++)
    {
      _gcry_mldsa_avx2_poly_pointwise_montgomery (
          (gcry_mldsa_poly *)tmp.buf,
          (gcry_mldsa_poly *)c.buf,
          (gcry_mldsa_poly *)&s1.buf[i * polysize]);
      _gcry_mldsa_avx2_poly_invntt_tomont ((gcry_mldsa_poly *)tmp.buf);
      _gcry_mldsa_avx2_poly_add ((gcry_mldsa_poly *)&z.buf[i * polysize],
                                 (gcry_mldsa_poly *)&z.buf[i * polysize],
                                 (gcry_mldsa_poly *)tmp.buf);
      _gcry_mldsa_avx2_poly_reduce ((gcry_mldsa_poly *)&z.buf[i * polysize]);
      if (_gcry_mldsa_avx2_poly_chknorm (
              (gcry_mldsa_poly *)&z.buf[i * polysize],
              params->gamma1 - params->beta))
        goto rej;
    }

  /* Zero hint vector in signature */
  pos = 0;
  memset (hint, 0, params->omega);

  for (i = 0; i < params->k; i++)
    {
      /* Check that subtracting cs2 does not change high bits of w and low bits
       * do not reveal secret information */
      _gcry_mldsa_avx2_poly_pointwise_montgomery (
          (gcry_mldsa_poly *)tmp.buf,
          (gcry_mldsa_poly *)c.buf,
          (gcry_mldsa_poly *)&s2.buf[i * polysize]);
      _gcry_mldsa_avx2_poly_invntt_tomont ((gcry_mldsa_poly *)tmp.buf);
      _gcry_mldsa_avx2_poly_sub ((gcry_mldsa_poly *)&tmpv.buf[i * polysize],
                                 (gcry_mldsa_poly *)&tmpv.buf[i * polysize],
                                 (gcry_mldsa_poly *)tmp.buf);
      _gcry_mldsa_avx2_poly_reduce (
          (gcry_mldsa_poly *)&tmpv.buf[i * polysize]);
      if (_gcry_mldsa_avx2_poly_chknorm (
              (gcry_mldsa_poly *)&tmpv.buf[i * polysize],
              params->gamma2 - params->beta))
        goto rej;

      /* Compute hints */
      _gcry_mldsa_avx2_poly_pointwise_montgomery (
          (gcry_mldsa_poly *)tmp.buf,
          (gcry_mldsa_poly *)c.buf,
          (gcry_mldsa_poly *)&t0.buf[i * polysize]);
      _gcry_mldsa_avx2_poly_invntt_tomont ((gcry_mldsa_poly *)tmp.buf);
      _gcry_mldsa_avx2_poly_reduce ((gcry_mldsa_poly *)tmp.buf);
      if (_gcry_mldsa_avx2_poly_chknorm ((gcry_mldsa_poly *)tmp.buf,
                                         params->gamma2))
        goto rej;

      _gcry_mldsa_avx2_poly_add ((gcry_mldsa_poly *)&tmpv.buf[i * polysize],
                                 (gcry_mldsa_poly *)&tmpv.buf[i * polysize],
                                 (gcry_mldsa_poly *)tmp.buf);
      n = _gcry_mldsa_avx2_poly_make_hint (
          params,
          hintbuf,
          (gcry_mldsa_poly *)&tmpv.buf[i * polysize],
          (gcry_mldsa_poly *)&w1.buf[i * polysize]);
      if (pos + n > params->omega)
        goto rej;

      /* Store hints in signature */
      memcpy (&hint[pos], hintbuf, n);
      hint[params->omega + i] = pos = pos + n;
    }

  /* Pack z into signature */
  for (i = 0; i < params->l; i++)
    _gcry_mldsa_avx2_polyz_pack (params,
                                 sig + params->ctildebytes
                                     + i * params->polyz_packedbytes,
                                 (gcry_mldsa_poly *)&z.buf[i * polysize]);

  *siglen = params->signature_bytes;

leave:
  xfree (seedbuf);
  xfree (hintbuf);
  _gcry_mldsa_polybuf_al_destroy (&mat);
  _gcry_mldsa_polybuf_al_destroy (&s1);
  _gcry_mldsa_polybuf_al_destroy (&s2);
  _gcry_mldsa_polybuf_al_destroy (&t0);
  _gcry_mldsa_polybuf_al_destroy (&w1);
  _gcry_mldsa_polybuf_al_destroy (&z);
  _gcry_mldsa_polybuf_al_destroy (&tmpv);
  _gcry_mldsa_polybuf_al_destroy (&c);
  _gcry_mldsa_polybuf_al_destroy (&tmp);
  return ec;
}


/*************************************************
 * Name:        _gcry_mldsa_verify
 *
 * Description: Verifies signature.
 *
 * Arguments:   - byte *m: pointer to input signature
 *              - size_t siglen: length of signature
 *              - const byte *m: pointer to message
 *              - size_t mlen: length of message
 *              - const byte *pk: pointer to bit-packed public key
 *
 * Returns 0 if signature could be verified correctly and -1 otherwise
 **************************************************/
gcry_err_code_t
_gcry_mldsa_avx2_verify (gcry_mldsa_param_t *params,
                         const byte *sig,
                         size_t siglen,
                         const byte *m,
                         size_t mlen,
                         const byte *pk)
{
  gcry_err_code_t ec = 0;
  unsigned int i, j, pos = 0;
  gcry_mldsa_buf_al buf = {};
  byte *mu              = NULL;
  const byte *hint
      = sig + params->ctildebytes + params->l * params->polyz_packedbytes;
  gcry_mldsa_polybuf_al rowbuf = {};
  byte *row                    = NULL;
  gcry_mldsa_polybuf_al z      = {};
  gcry_mldsa_polybuf_al c      = {};
  gcry_mldsa_polybuf_al w1     = {};
  gcry_mldsa_polybuf_al h      = {};
  const size_t polysize        = sizeof (gcry_mldsa_poly);

  if (siglen != params->signature_bytes)
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  if ((ec = _gcry_mldsa_polybuf_al_create (&rowbuf, 2, params->l, 0))
      || (ec = _gcry_mldsa_polybuf_al_create (&z, 1, params->l, 0))
      || (ec = _gcry_mldsa_polybuf_al_create (&c, 1, 1, 0))
      || (ec = _gcry_mldsa_polybuf_al_create (&w1, 1, 1, 0))
      || (ec = _gcry_mldsa_polybuf_al_create (&h, 1, 1, 0)))
    {
      ec = gpg_err_code_from_syserror ();
      goto leave;
    }

  row = rowbuf.buf;

  /* _gcry_mldsa_avx2_polyw1_pack writes additional 14 bytes */
  ec = _gcry_mldsa_buf_al_create (
      &buf, params->k * params->polyw1_packedbytes + 14, 0);
  if (ec)
    goto leave;

  if (!(mu = xtrymalloc (GCRY_MLDSA_CRHBYTES)))
    {
      ec = gpg_error_from_syserror ();
      goto leave;
    }

  ec = _gcry_mldsa_shake256 (
      pk, params->public_key_bytes, NULL, 0, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256 (
      mu, GCRY_MLDSA_CRHBYTES, m, mlen, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  /* Expand challenge */
  ec = _gcry_mldsa_poly_challenge (params, (gcry_mldsa_poly *)c.buf, sig);
  if (ec)
    goto leave;
  _gcry_mldsa_avx2_poly_ntt ((gcry_mldsa_poly *)c.buf);

  /* Unpack z; shortness follows from unpacking */
  for (i = 0; i < params->l; i++)
    {
      _gcry_mldsa_avx2_polyz_unpack (params,
                                     (gcry_mldsa_poly *)&z.buf[i * polysize],
                                     sig + params->ctildebytes
                                         + i * params->polyz_packedbytes);
      _gcry_mldsa_avx2_poly_ntt ((gcry_mldsa_poly *)&z.buf[i * polysize]);
    }

  for (i = 0; i < params->k; i++)
    {
      /* Expand matrix row */
      ec = polyvec_matrix_expand_row (params, &row, rowbuf.buf, pk, i);
      if (ec)
        goto leave;

      /* Compute i-th row of Az - c2^Dt1 */
      _gcry_mldsa_avx2_polyvecl_pointwise_acc_montgomery (
          params, (gcry_mldsa_poly *)w1.buf, row, z.buf);

      _gcry_mldsa_avx2_polyt1_unpack ((gcry_mldsa_poly *)h.buf,
                                      pk + GCRY_MLDSA_SEEDBYTES
                                          + i * GCRY_MLDSA_POLYT1_PACKEDBYTES);
      poly_shiftl ((gcry_mldsa_poly *)h.buf);
      _gcry_mldsa_avx2_poly_ntt ((gcry_mldsa_poly *)h.buf);
      _gcry_mldsa_avx2_poly_pointwise_montgomery ((gcry_mldsa_poly *)h.buf,
                                                  (gcry_mldsa_poly *)c.buf,
                                                  (gcry_mldsa_poly *)h.buf);

      _gcry_mldsa_avx2_poly_sub ((gcry_mldsa_poly *)w1.buf,
                                 (gcry_mldsa_poly *)w1.buf,
                                 (gcry_mldsa_poly *)h.buf);
      _gcry_mldsa_avx2_poly_reduce ((gcry_mldsa_poly *)w1.buf);
      _gcry_mldsa_avx2_poly_invntt_tomont ((gcry_mldsa_poly *)w1.buf);

      /* Get hint polynomial and reconstruct w1 */
      memset (h.buf, 0, polysize);
      if (hint[params->omega + i] < pos
          || hint[params->omega + i] > params->omega)
        {
          ec = GPG_ERR_BAD_SIGNATURE;
          goto leave;
        }

      for (j = pos; j < hint[params->omega + i]; ++j)
        {
          /* Coefficients are ordered for strong unforgeability */
          if (j > pos && hint[j] <= hint[j - 1])
            {
              ec = GPG_ERR_BAD_SIGNATURE;
              goto leave;
            }
          h.buf[hint[j] * sizeof (s32)] = 1;
        }
      pos = hint[params->omega + i];

      _gcry_mldsa_avx2_poly_caddq ((gcry_mldsa_poly *)w1.buf);
      _gcry_mldsa_avx2_poly_use_hint (params,
                                      (gcry_mldsa_poly *)w1.buf,
                                      (gcry_mldsa_poly *)w1.buf,
                                      (gcry_mldsa_poly *)h.buf);
      _gcry_mldsa_avx2_polyw1_pack (params,
                                    buf.buf + i * params->polyw1_packedbytes,
                                    (gcry_mldsa_poly *)w1.buf);
    }

  /* Extra indices are zero for strong unforgeability */
  for (j = pos; j < params->omega; ++j)
    if (hint[j])
      {
        ec = GPG_ERR_BAD_SIGNATURE;
        goto leave;
      }

  /* Call random oracle and verify challenge */
  ec = _gcry_mldsa_shake256 (mu,
                             GCRY_MLDSA_CRHBYTES,
                             buf.buf,
                             params->k * params->polyw1_packedbytes,
                             buf.buf,
                             params->ctildebytes);
  if (ec)
    goto leave;

  for (i = 0; i < params->ctildebytes; ++i)
    {
      if (buf.buf[i] != sig[i])
        {
          ec = GPG_ERR_BAD_SIGNATURE;
          goto leave;
        }
    }

leave:
  xfree (mu);
  _gcry_mldsa_polybuf_al_destroy (&rowbuf);
  _gcry_mldsa_polybuf_al_destroy (&z);
  _gcry_mldsa_polybuf_al_destroy (&c);
  _gcry_mldsa_polybuf_al_destroy (&w1);
  _gcry_mldsa_polybuf_al_destroy (&h);
  _gcry_mldsa_buf_al_destroy (&buf);
  return ec;
}
#endif
