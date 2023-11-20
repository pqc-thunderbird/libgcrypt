#include <config.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-sign.h"
#include "mldsa-packing.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly.h"
#include "mldsa-symmetric.h"
#include "g10lib.h"

/*************************************************
 * Name:        _gcry_mldsa_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - byte *pk: pointer to output public key (allocated
 *                             array of params->public_key_bytes bytes)
 *              - byte *sk: pointer to output private key (allocated
 *                             array of params->secret_key_bytes bytes)
 *
 * Returns 0 (success)
 **************************************************/
gcry_err_code_t _gcry_mldsa_keypair(gcry_mldsa_param_t *params, byte *pk, byte *sk)
{
  gcry_err_code_t ec = 0;
  byte seedbuf[2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES]; /* TODO: dynamic allocation */
  byte tr[GCRY_MLDSA_TRBYTES]; /* TODO: dynamic allocation */
  const byte *rho, *rhoprime, *key;

  gcry_mldsa_polyvec *mat  = NULL;
  gcry_mldsa_polyvec s1    = {.vec = NULL};
  gcry_mldsa_polyvec s1hat = {.vec = NULL};

  gcry_mldsa_polyvec s2 = {.vec = NULL};
  gcry_mldsa_polyvec t1 = {.vec = NULL};
  gcry_mldsa_polyvec t0 = {.vec = NULL};

  if ((ec = _gcry_mldsa_polymatrix_create(&mat, params->k, params->l))
      || (ec = _gcry_mldsa_polyvec_create(&s1, params->l)) || (ec = _gcry_mldsa_polyvec_create(&s1hat, params->l))
      || (ec = _gcry_mldsa_polyvec_create(&s2, params->k)) || (ec = _gcry_mldsa_polyvec_create(&t1, params->k))
      || (ec = _gcry_mldsa_polyvec_create(&t0, params->k)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  /* Get randomness for rho, rhoprime and key */
  _gcry_randomize(seedbuf, GCRY_MLDSA_SEEDBYTES, GCRY_VERY_STRONG_RANDOM);

  ec = _gcry_mldsa_shake256(
      seedbuf, GCRY_MLDSA_SEEDBYTES, NULL, 0, seedbuf, 2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  rho      = seedbuf;
  rhoprime = rho + GCRY_MLDSA_SEEDBYTES;
  key      = rhoprime + GCRY_MLDSA_CRHBYTES;

  /* Expand matrix */
  ec = _gcry_mldsa_polyvec_matrix_expand(params, mat, rho);
  if (ec)
    goto leave;

  /* Sample short vectors s1 and s2 */
  ec = _gcry_mldsa_polyvecl_uniform_eta(params, &s1, rhoprime, 0);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_polyveck_uniform_eta(params, &s2, rhoprime, params->l);
  if (ec)
    goto leave;

  /* Matrix-vector multiplication */
  ec = _gcry_mldsa_polyvec_copy(&s1hat, &s1, params->l);
  if (ec)
    goto leave;
  _gcry_mldsa_polyvecl_ntt(params, &s1hat);
  _gcry_mldsa_polyvec_matrix_pointwise_montgomery(params, &t1, mat, &s1hat);
  _gcry_mldsa_polyveck_reduce(params, &t1);
  _gcry_mldsa_polyveck_invntt_tomont(params, &t1);

  /* Add error vector s2 */
  _gcry_mldsa_polyveck_add(params, &t1, &t1, &s2);

  /* Extract t1 and write public key */
  _gcry_mldsa_polyveck_caddq(params, &t1);
  _gcry_mldsa_polyveck_power2round(params, &t1, &t0, &t1);
  _gcry_mldsa_pack_pk(params, pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  ec = _gcry_mldsa_shake256(pk, params->public_key_bytes, NULL, 0, tr, GCRY_MLDSA_TRBYTES);
  if (ec)
    goto leave;
  _gcry_mldsa_pack_sk(params, sk, rho, tr, key, &t0, &s1, &s2);

leave:
  _gcry_mldsa_polymatrix_destroy(&mat, params->k);
  _gcry_mldsa_polyvec_destroy(&s1);
  _gcry_mldsa_polyvec_destroy(&s1hat);
  _gcry_mldsa_polyvec_destroy(&s2);
  _gcry_mldsa_polyvec_destroy(&t1);
  _gcry_mldsa_polyvec_destroy(&t0);
  return ec;
}

/*************************************************
 * Name:        _gcry_mldsa_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - byte *sig:   pointer to output signature (of length params->signature_bytes)
 *              - size_t *siglen: pointer to output length of signature
 *              - byte *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - byte *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success)
 **************************************************/
gcry_err_code_t _gcry_mldsa_sign(
    gcry_mldsa_param_t *params, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk)
{
  gcry_err_code_t ec = 0;

  unsigned int n;
  byte seedbuf[2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES + 2 * GCRY_MLDSA_CRHBYTES];
  byte *rho, *tr, *key, *mu, *rhoprime;
  u16 nonce = 0;
  gcry_mldsa_poly cp;
  gcry_md_hd_t hd;

  gcry_mldsa_polyvec *mat = NULL;
  gcry_mldsa_polyvec s1   = {.vec = NULL};
  gcry_mldsa_polyvec y    = {.vec = NULL};
  gcry_mldsa_polyvec z    = {.vec = NULL};

  gcry_mldsa_polyvec t0 = {.vec = NULL};
  gcry_mldsa_polyvec s2 = {.vec = NULL};
  gcry_mldsa_polyvec w1 = {.vec = NULL};
  gcry_mldsa_polyvec w0 = {.vec = NULL};
  gcry_mldsa_polyvec h  = {.vec = NULL};

  if ((ec = _gcry_mldsa_polymatrix_create(&mat, params->k, params->l))
      || (ec = _gcry_mldsa_polyvec_create(&s1, params->l)) || (ec = _gcry_mldsa_polyvec_create(&y, params->l))
      || (ec = _gcry_mldsa_polyvec_create(&z, params->l)) || (ec = _gcry_mldsa_polyvec_create(&t0, params->k))
      || (ec = _gcry_mldsa_polyvec_create(&s2, params->k)) || (ec = _gcry_mldsa_polyvec_create(&w1, params->k))
      || (ec = _gcry_mldsa_polyvec_create(&w0, params->k)) || (ec = _gcry_mldsa_polyvec_create(&h, params->k)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  rho      = seedbuf;
  tr       = rho + GCRY_MLDSA_SEEDBYTES;
  key      = tr + GCRY_MLDSA_TRBYTES;
  mu       = key + GCRY_MLDSA_SEEDBYTES;
  rhoprime = mu + GCRY_MLDSA_CRHBYTES;
  _gcry_mldsa_unpack_sk(params, rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(hd, tr, GCRY_MLDSA_TRBYTES);
  _gcry_md_write(hd, m, mlen);
  _gcry_md_extract(hd, GCRY_MD_SHAKE256, mu, GCRY_MLDSA_CRHBYTES);
  _gcry_md_close(hd);

  ec = _gcry_mldsa_shake256(key, GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES, NULL, 0, rhoprime, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  /* Expand matrix and transform vectors */
  ec = _gcry_mldsa_polyvec_matrix_expand(params, mat, rho);
  if (ec)
    goto leave;
  _gcry_mldsa_polyvecl_ntt(params, &s1);
  _gcry_mldsa_polyveck_ntt(params, &s2);
  _gcry_mldsa_polyveck_ntt(params, &t0);

rej:
  /* Sample intermediate vector y */
  ec = _gcry_mldsa_polyvecl_uniform_gamma1(params, &y, rhoprime, nonce++);
  if (ec)
    goto leave;

  /* Matrix-vector multiplication */
  ec = _gcry_mldsa_polyvec_copy(&z, &y, params->l);
  if (ec)
    goto leave;
  _gcry_mldsa_polyvecl_ntt(params, &z);
  _gcry_mldsa_polyvec_matrix_pointwise_montgomery(params, &w1, mat, &z);
  _gcry_mldsa_polyveck_reduce(params, &w1);
  _gcry_mldsa_polyveck_invntt_tomont(params, &w1);

  /* Decompose w and call the random oracle */
  _gcry_mldsa_polyveck_caddq(params, &w1);
  _gcry_mldsa_polyveck_decompose(params, &w1, &w0, &w1);
  _gcry_mldsa_polyveck_pack_w1(params, sig, &w1);

  ec = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, mu, GCRY_MLDSA_CRHBYTES);
  _gcry_md_write(hd, sig, params->k * params->polyw1_packedbytes);
  ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, sig, GCRY_MLDSA_SEEDBYTES);
  if (ec)
    goto leave;
  _gcry_md_close(hd);
  ec = _gcry_mldsa_poly_challenge(params, &cp, sig);
  if (ec)
    goto leave;
  _gcry_mldsa_poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  _gcry_mldsa_polyvecl_pointwise_poly_montgomery(params, &z, &cp, &s1);
  _gcry_mldsa_polyvecl_invntt_tomont(params, &z);
  _gcry_mldsa_polyvecl_add(params, &z, &z, &y);
  _gcry_mldsa_polyvecl_reduce(params, &z);
  if (_gcry_mldsa_polyvecl_chknorm(params, &z, params->gamma1 - params->beta))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  _gcry_mldsa_polyveck_pointwise_poly_montgomery(params, &h, &cp, &s2);
  _gcry_mldsa_polyveck_invntt_tomont(params, &h);
  _gcry_mldsa_polyveck_sub(params, &w0, &w0, &h);
  _gcry_mldsa_polyveck_reduce(params, &w0);
  if (_gcry_mldsa_polyveck_chknorm(params, &w0, params->gamma2 - params->beta))
    goto rej;

  /* Compute hints for w1 */
  _gcry_mldsa_polyveck_pointwise_poly_montgomery(params, &h, &cp, &t0);
  _gcry_mldsa_polyveck_invntt_tomont(params, &h);
  _gcry_mldsa_polyveck_reduce(params, &h);
  if (_gcry_mldsa_polyveck_chknorm(params, &h, params->gamma2))
    goto rej;

  _gcry_mldsa_polyveck_add(params, &w0, &w0, &h);
  n = _gcry_mldsa_polyveck_make_hint(params, &h, &w0, &w1);
  if (n > params->omega)
    goto rej;

  /* Write signature */
  _gcry_mldsa_pack_sig(params, sig, sig, &z, &h);
  *siglen = params->signature_bytes;

leave:
  _gcry_mldsa_polymatrix_destroy(&mat, params->k);
  _gcry_mldsa_polyvec_destroy(&s1);
  _gcry_mldsa_polyvec_destroy(&y);
  _gcry_mldsa_polyvec_destroy(&z);
  _gcry_mldsa_polyvec_destroy(&t0);
  _gcry_mldsa_polyvec_destroy(&s2);
  _gcry_mldsa_polyvec_destroy(&w1);
  _gcry_mldsa_polyvec_destroy(&w0);
  _gcry_mldsa_polyvec_destroy(&h);
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
gcry_err_code_t _gcry_mldsa_verify(
    gcry_mldsa_param_t *params, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  byte *buf = NULL;
  byte rho[GCRY_MLDSA_SEEDBYTES];
  byte mu[GCRY_MLDSA_CRHBYTES];
  byte c[GCRY_MLDSA_SEEDBYTES];
  byte c2[GCRY_MLDSA_SEEDBYTES];
  gcry_mldsa_poly cp;

  gcry_mldsa_polyvec *mat = NULL;
  gcry_mldsa_polyvec z    = {.vec = NULL};

  gcry_mldsa_polyvec t1 = {.vec = NULL};
  gcry_mldsa_polyvec w1 = {.vec = NULL};
  gcry_mldsa_polyvec h  = {.vec = NULL};

  if (!(buf = xtrymalloc(sizeof(*buf) * (params->k * params->polyw1_packedbytes))))
    {
      return gpg_error_from_syserror();
    }

  if (siglen != params->signature_bytes)
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  if ((ec = _gcry_mldsa_polymatrix_create(&mat, params->k, params->l))
      || (ec = _gcry_mldsa_polyvec_create(&z, params->l)) || (ec = _gcry_mldsa_polyvec_create(&t1, params->k))
      || (ec = _gcry_mldsa_polyvec_create(&w1, params->k)) || (ec = _gcry_mldsa_polyvec_create(&h, params->k)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  _gcry_mldsa_unpack_pk(params, rho, &t1, pk);
  if (_gcry_mldsa_unpack_sig(params, c, &z, &h, sig))
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  if (_gcry_mldsa_polyvecl_chknorm(params, &z, params->gamma1 - params->beta))
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  /* Compute CRH(H(rho, t1), msg) */
  ec = _gcry_mldsa_shake256(pk, params->public_key_bytes, NULL, 0, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256(mu, GCRY_MLDSA_CRHBYTES, m, mlen, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;


  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  ec = _gcry_mldsa_poly_challenge(params, &cp, c);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_polyvec_matrix_expand(params, mat, rho);
  if (ec)
    goto leave;

  _gcry_mldsa_polyvecl_ntt(params, &z);
  _gcry_mldsa_polyvec_matrix_pointwise_montgomery(params, &w1, mat, &z);

  _gcry_mldsa_poly_ntt(&cp);
  _gcry_mldsa_polyveck_shiftl(params, &t1);
  _gcry_mldsa_polyveck_ntt(params, &t1);
  _gcry_mldsa_polyveck_pointwise_poly_montgomery(params, &t1, &cp, &t1);

  _gcry_mldsa_polyveck_sub(params, &w1, &w1, &t1);
  _gcry_mldsa_polyveck_reduce(params, &w1);
  _gcry_mldsa_polyveck_invntt_tomont(params, &w1);

  /* Reconstruct w1 */
  _gcry_mldsa_polyveck_caddq(params, &w1);
  _gcry_mldsa_polyveck_use_hint(params, &w1, &w1, &h);
  _gcry_mldsa_polyveck_pack_w1(params, buf, &w1);

  /* Call random oracle and verify challenge */
  ec = _gcry_mldsa_shake256(
      mu, GCRY_MLDSA_CRHBYTES, buf, params->k * params->polyw1_packedbytes, c2, GCRY_MLDSA_SEEDBYTES);
  if (ec)
    goto leave;

  for (i = 0; i < GCRY_MLDSA_SEEDBYTES; ++i)
    if (c[i] != c2[i])
      {
        ec = GPG_ERR_BAD_SIGNATURE;
        goto leave;
      }

leave:
  xfree(buf);
  _gcry_mldsa_polymatrix_destroy(&mat, params->k);
  _gcry_mldsa_polyvec_destroy(&z);
  _gcry_mldsa_polyvec_destroy(&t1);
  _gcry_mldsa_polyvec_destroy(&w1);
  _gcry_mldsa_polyvec_destroy(&h);
  return ec;
}
