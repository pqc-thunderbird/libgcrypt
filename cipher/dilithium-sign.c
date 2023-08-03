#include <config.h>
#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-sign.h"
#include "dilithium-packing.h"
#include "dilithium-polyvec.h"
#include "dilithium-poly.h"
#include "dilithium-symmetric.h"
#include "g10lib.h"

/*************************************************
* Name:        _gcry_dilithium_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of params->public_key_bytes bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of params->secret_key_bytes bytes)
*
* Returns 0 (success)
**************************************************/
gcry_error_t _gcry_dilithium_keypair(gcry_dilithium_param_t *params, uint8_t *pk, uint8_t *sk) {
  gcry_error_t ec = 0;
  uint8_t seedbuf[2*GCRY_DILITHIUM_SEEDBYTES + GCRY_DILITHIUM_CRHBYTES];
  uint8_t tr[GCRY_DILITHIUM_SEEDBYTES];
  const uint8_t *rho, *rhoprime, *key;

  //polyvecl mat[params->k];
  //polyvecl s1, s1hat;
  gcry_dilithium_polyvec *mat = NULL;
  gcry_dilithium_polyvec s1 = {.vec = NULL};
  gcry_dilithium_polyvec s1hat = {.vec = NULL};

  // polyveck s2, t1, t0;
  gcry_dilithium_polyvec s2 = {.vec = NULL};
  gcry_dilithium_polyvec t1 = {.vec = NULL};
  gcry_dilithium_polyvec t0 = {.vec = NULL};

  if ((ec = _gcry_dilithium_polymatrix_create(&mat, params->k, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&s1, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&s1hat, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&s2, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&t1, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&t0, params->k)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }

  /* Get randomness for rho, rhoprime and key */
  //randombytes(seedbuf, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_randomize(seedbuf, GCRY_DILITHIUM_SEEDBYTES, GCRY_VERY_STRONG_RANDOM);
  //shake256(seedbuf, 2*GCRY_DILITHIUM_SEEDBYTES + GCRY_DILITHIUM_CRHBYTES, seedbuf, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_dilithium_shake256(seedbuf, GCRY_DILITHIUM_SEEDBYTES, NULL, 0, seedbuf, 2*GCRY_DILITHIUM_SEEDBYTES + GCRY_DILITHIUM_CRHBYTES);

  rho = seedbuf;
  rhoprime = rho + GCRY_DILITHIUM_SEEDBYTES;
  key = rhoprime + GCRY_DILITHIUM_CRHBYTES;

  /* Expand matrix */
  _gcry_dilithium_polyvec_matrix_expand(params, mat, rho);

  /* Sample short vectors s1 and s2 */
  _gcry_dilithium_polyvecl_uniform_eta(params, &s1, rhoprime, 0);
  _gcry_dilithium_polyveck_uniform_eta(params, &s2, rhoprime, params->l);

  /* Matrix-vector multiplication */
  //s1hat = s1;
  _gcry_dilithium_polyvec_copy(&s1hat, &s1, params->l);
  _gcry_dilithium_polyvecl_ntt(params, &s1hat);
  _gcry_dilithium_polyvec_matrix_pointwise_montgomery(params, &t1, mat, &s1hat);
  _gcry_dilithium_polyveck_reduce(params, &t1);
  _gcry_dilithium_polyveck_invntt_tomont(params, &t1);

  /* Add error vector s2 */
  _gcry_dilithium_polyveck_add(params, &t1, &t1, &s2);

  /* Extract t1 and write public key */
  _gcry_dilithium_polyveck_caddq(params, &t1);
  _gcry_dilithium_polyveck_power2round(params, &t1, &t0, &t1);
  _gcry_dilithium_pack_pk(params, pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  //shake256(tr, GCRY_DILITHIUM_SEEDBYTES, pk, params->public_key_bytes);
  _gcry_dilithium_shake256(pk, params->public_key_bytes, NULL, 0, tr, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_dilithium_pack_sk(params, sk, rho, tr, key, &t0, &s1, &s2);

leave:
  _gcry_dilithium_polymatrix_destroy(&mat, params->k);
  _gcry_dilithium_polyvec_destroy(&s1);
  _gcry_dilithium_polyvec_destroy(&s1hat);
  _gcry_dilithium_polyvec_destroy(&s2);
  _gcry_dilithium_polyvec_destroy(&t1);
  _gcry_dilithium_polyvec_destroy(&t0);
  return ec;
}

/*************************************************
* Name:        _gcry_dilithium_sign
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length params->signature_bytes)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
gcry_error_t _gcry_dilithium_sign(gcry_dilithium_param_t *params,
                          uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  gcry_error_t ec = 0;

  unsigned int n;
  uint8_t seedbuf[3*GCRY_DILITHIUM_SEEDBYTES + 2*GCRY_DILITHIUM_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  gcry_dilithium_poly cp;
  gcry_md_hd_t hd;

  //polyvecl mat[params->k], s1, y, z;
  gcry_dilithium_polyvec *mat = NULL;
  gcry_dilithium_polyvec s1 = {.vec = NULL};
  gcry_dilithium_polyvec y = {.vec = NULL};
  gcry_dilithium_polyvec z = {.vec = NULL};

  // polyveck t0, s2, w1, w0, h;
  gcry_dilithium_polyvec t0 = {.vec = NULL};
  gcry_dilithium_polyvec s2 = {.vec = NULL};
  gcry_dilithium_polyvec w1 = {.vec = NULL};
  gcry_dilithium_polyvec w0 = {.vec = NULL};
  gcry_dilithium_polyvec h = {.vec = NULL};

  if ((ec = _gcry_dilithium_polymatrix_create(&mat, params->k, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&s1, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&y, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&z, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&t0, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&s2, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&w1, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&w0, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&h, params->k)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }

  rho = seedbuf;
  tr = rho + GCRY_DILITHIUM_SEEDBYTES;
  key = tr + GCRY_DILITHIUM_SEEDBYTES;
  mu = key + GCRY_DILITHIUM_SEEDBYTES;
  rhoprime = mu + GCRY_DILITHIUM_CRHBYTES;
  _gcry_dilithium_unpack_sk(params, rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(hd, tr, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_md_write(hd, m, mlen);
  _gcry_md_extract(hd, GCRY_MD_SHAKE256, mu, GCRY_DILITHIUM_CRHBYTES);
  _gcry_md_close(hd);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  //randombytes(rhoprime, GCRY_DILITHIUM_CRHBYTES);
  _gcry_randomize(rhoprime, GCRY_DILITHIUM_CRHBYTES, GCRY_VERY_STRONG_RANDOM);
#else
  //shake256(rhoprime, GCRY_DILITHIUM_CRHBYTES, key, GCRY_DILITHIUM_SEEDBYTES + GCRY_DILITHIUM_CRHBYTES);
  _gcry_dilithium_shake256(key, GCRY_DILITHIUM_SEEDBYTES + GCRY_DILITHIUM_CRHBYTES, NULL, 0, rhoprime, GCRY_DILITHIUM_CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  _gcry_dilithium_polyvec_matrix_expand(params, mat, rho);
  _gcry_dilithium_polyvecl_ntt(params, &s1);
  _gcry_dilithium_polyveck_ntt(params, &s2);
  _gcry_dilithium_polyveck_ntt(params, &t0);

rej:
  /* Sample intermediate vector y */
  _gcry_dilithium_polyvecl_uniform_gamma1(params, &y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  //z = y;
  _gcry_dilithium_polyvec_copy(&z, &y, params->l);
  _gcry_dilithium_polyvecl_ntt(params, &z);
  _gcry_dilithium_polyvec_matrix_pointwise_montgomery(params, &w1, mat, &z);
  _gcry_dilithium_polyveck_reduce(params, &w1);
  _gcry_dilithium_polyveck_invntt_tomont(params, &w1);

  /* Decompose w and call the random oracle */
  _gcry_dilithium_polyveck_caddq(params, &w1);
  _gcry_dilithium_polyveck_decompose(params, &w1, &w0, &w1);
  _gcry_dilithium_polyveck_pack_w1(params, sig, &w1);

  _gcry_md_open (&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  _gcry_md_write(hd, mu, GCRY_DILITHIUM_CRHBYTES);
  _gcry_md_write(hd, sig, params->k*params->polyw1_packedbytes);
  _gcry_md_extract(hd, GCRY_MD_SHAKE256, sig, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_md_close(hd);
  _gcry_dilithium_poly_challenge(params, &cp, sig);
  _gcry_dilithium_poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  _gcry_dilithium_polyvecl_pointwise_poly_montgomery(params, &z, &cp, &s1);
  _gcry_dilithium_polyvecl_invntt_tomont(params, &z);
  _gcry_dilithium_polyvecl_add(params, &z, &z, &y);
  _gcry_dilithium_polyvecl_reduce(params, &z);
  if(_gcry_dilithium_polyvecl_chknorm(params, &z, params->gamma1 - params->beta))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  _gcry_dilithium_polyveck_pointwise_poly_montgomery(params, &h, &cp, &s2);
  _gcry_dilithium_polyveck_invntt_tomont(params, &h);
  _gcry_dilithium_polyveck_sub(params, &w0, &w0, &h);
  _gcry_dilithium_polyveck_reduce(params, &w0);
  if(_gcry_dilithium_polyveck_chknorm(params, &w0, params->gamma2 - params->beta))
    goto rej;

  /* Compute hints for w1 */
  _gcry_dilithium_polyveck_pointwise_poly_montgomery(params, &h, &cp, &t0);
  _gcry_dilithium_polyveck_invntt_tomont(params, &h);
  _gcry_dilithium_polyveck_reduce(params, &h);
  if(_gcry_dilithium_polyveck_chknorm(params, &h, params->gamma2))
    goto rej;

  _gcry_dilithium_polyveck_add(params, &w0, &w0, &h);
  n = _gcry_dilithium_polyveck_make_hint(params, &h, &w0, &w1);
  if(n > params->omega)
    goto rej;

  /* Write signature */
  _gcry_dilithium_pack_sig(params, sig, sig, &z, &h);
  *siglen = params->signature_bytes;

leave:
  _gcry_dilithium_polymatrix_destroy(&mat, params->k);
  _gcry_dilithium_polyvec_destroy(&s1);
  _gcry_dilithium_polyvec_destroy(&y);
  _gcry_dilithium_polyvec_destroy(&z);
  _gcry_dilithium_polyvec_destroy(&t0);
  _gcry_dilithium_polyvec_destroy(&s2);
  _gcry_dilithium_polyvec_destroy(&w1);
  _gcry_dilithium_polyvec_destroy(&w0);
  _gcry_dilithium_polyvec_destroy(&h);
  return ec;
}

/*************************************************
* Name:        _gcry_dilithium_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
gcry_error_t _gcry_dilithium_verify(gcry_dilithium_param_t *params,
                       const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  gcry_error_t ec = 0;
  unsigned int i;
  //uint8_t buf[params->k*params->polyw1_packedbytes];
  uint8_t *buf;
  uint8_t rho[GCRY_DILITHIUM_SEEDBYTES];
  uint8_t mu[GCRY_DILITHIUM_CRHBYTES];
  uint8_t c[GCRY_DILITHIUM_SEEDBYTES];
  uint8_t c2[GCRY_DILITHIUM_SEEDBYTES];
  gcry_dilithium_poly cp;

  //polyvecl mat[params->k], z;
  gcry_dilithium_polyvec *mat = NULL;
  gcry_dilithium_polyvec z = {.vec = NULL};

  // polyveck t1, w1, h;
  gcry_dilithium_polyvec t1 = {.vec = NULL};
  gcry_dilithium_polyvec w1 = {.vec = NULL};
  gcry_dilithium_polyvec h = {.vec = NULL};

    if (!(buf = xtrymalloc(sizeof(*buf) * (params->k*params->polyw1_packedbytes))))
  {
    return gpg_error_from_syserror();
  }

  if(siglen != params->signature_bytes)
  {
    ec = GPG_ERR_BAD_SIGNATURE;
    goto leave;
  }

  if ((ec = _gcry_dilithium_polymatrix_create(&mat, params->k, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&z, params->l))
    || (ec = _gcry_dilithium_polyvec_create(&t1, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&w1, params->k))
    || (ec = _gcry_dilithium_polyvec_create(&h, params->k)))
  {
    ec = gpg_err_code_from_syserror();
    goto leave;
  }

  _gcry_dilithium_unpack_pk(params, rho, &t1, pk);
  if(_gcry_dilithium_unpack_sig(params, c, &z, &h, sig))
  {
    ec = GPG_ERR_BAD_SIGNATURE;
    goto leave;
  }
  if(_gcry_dilithium_polyvecl_chknorm(params, &z, params->gamma1 - params->beta))
  {
    ec = GPG_ERR_BAD_SIGNATURE;
    goto leave;
  }

  /* Compute CRH(H(rho, t1), msg) */

  //shake256(mu, GCRY_DILITHIUM_SEEDBYTES, pk, params->public_key_bytes);
  //shake256_init(&state);
  //shake256_absorb(&state, mu, GCRY_DILITHIUM_SEEDBYTES);
  //shake256_absorb(&state, m, mlen);
  //shake256_finalize(&state);
  //shake256_squeeze(mu, GCRY_DILITHIUM_CRHBYTES, &state);
  _gcry_dilithium_shake256(pk, params->public_key_bytes, NULL, 0, mu, GCRY_DILITHIUM_SEEDBYTES);
  _gcry_dilithium_shake256(mu, GCRY_DILITHIUM_SEEDBYTES, m, mlen, mu, GCRY_DILITHIUM_CRHBYTES);


  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  _gcry_dilithium_poly_challenge(params, &cp, c);
  _gcry_dilithium_polyvec_matrix_expand(params, mat, rho);

  _gcry_dilithium_polyvecl_ntt(params, &z);
  _gcry_dilithium_polyvec_matrix_pointwise_montgomery(params, &w1, mat, &z);

  _gcry_dilithium_poly_ntt(&cp);
  _gcry_dilithium_polyveck_shiftl(params, &t1);
  _gcry_dilithium_polyveck_ntt(params, &t1);
  _gcry_dilithium_polyveck_pointwise_poly_montgomery(params, &t1, &cp, &t1);

  _gcry_dilithium_polyveck_sub(params, &w1, &w1, &t1);
  _gcry_dilithium_polyveck_reduce(params, &w1);
  _gcry_dilithium_polyveck_invntt_tomont(params, &w1);

  /* Reconstruct w1 */
  _gcry_dilithium_polyveck_caddq(params, &w1);
  _gcry_dilithium_polyveck_use_hint(params, &w1, &w1, &h);
  _gcry_dilithium_polyveck_pack_w1(params, buf, &w1);

  /* Call random oracle and verify challenge */
  //shake256_init(&state);
  //shake256_absorb(&state, mu, GCRY_DILITHIUM_CRHBYTES);
  //shake256_absorb(&state, buf, params->k*params->polyw1_packedbytes);
  //shake256_finalize(&state);
  //shake256_squeeze(c2, GCRY_DILITHIUM_SEEDBYTES, &state);
  _gcry_dilithium_shake256(mu, GCRY_DILITHIUM_CRHBYTES, buf, params->k*params->polyw1_packedbytes, c2, GCRY_DILITHIUM_SEEDBYTES);

  for(i = 0; i < GCRY_DILITHIUM_SEEDBYTES; ++i)
    if(c[i] != c2[i])
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

leave:
  xfree(buf);
  _gcry_dilithium_polymatrix_destroy(&mat, params->k);
  _gcry_dilithium_polyvec_destroy(&z);
  _gcry_dilithium_polyvec_destroy(&t1);
  _gcry_dilithium_polyvec_destroy(&w1);
  _gcry_dilithium_polyvec_destroy(&h);
  return ec;
}
