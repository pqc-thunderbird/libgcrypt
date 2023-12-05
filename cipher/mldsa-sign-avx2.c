#include "config.h"

#include <stdint.h>
#include <string.h>
#include "mldsa-align-avx2.h"
#include "mldsa-params.h"
#include "mldsa-params-avx2.h"
#include "mldsa-sign-avx2.h"
#include "mldsa-packing-avx2.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly-avx2.h"
#include "mldsa-randombytes-avx2.h"
#include "mldsa-symmetric-avx2.h"
#include "mldsa-fips202-avx2.h"

static inline void polyvec_matrix_expand_row(gcry_mldsa_param_t *params, byte **row, byte* buf, const uint8_t rho[GCRY_MLDSA_SEEDBYTES], unsigned int i) {
  const size_t offset = params->l * sizeof(gcry_mldsa_poly);
  switch(i) {
    case 0:
      polyvec_matrix_expand_row0(params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 1:
      polyvec_matrix_expand_row1(params, buf + offset, buf, rho);
      *row = buf + offset;
      break;
    case 2:
      polyvec_matrix_expand_row2(params, buf, buf + offset, rho);
      *row = buf;
      break;
    case 3:
      polyvec_matrix_expand_row3(params, buf + offset, buf, rho);
      *row = buf + offset;
      break;
    case 4:
      if(params->k <= 4)
        break;
      polyvec_matrix_expand_row4(params, buf, buf + 1, rho);
      *row = buf;
      break;
    case 5:
      if(params->k <= 4)
        break;
      polyvec_matrix_expand_row5(params, buf + 1, buf, rho);
      *row = buf + 1;
      break;
    case 6:
      if(params->k <= 6)
        break;
      polyvec_matrix_expand_row6(params, buf, buf + 1, rho);
      *row = buf;
      break;
    case 7:
      if(params->k <= 4)
        break;
      polyvec_matrix_expand_row7(params, buf + 1, buf, rho);
      *row = buf + 1;
      break;
  }
}

/*************************************************
* Name:        _gcry_mldsa_keypair_avx2
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
gcry_err_code_t _gcry_mldsa_keypair_avx2(gcry_mldsa_param_t *params, uint8_t *pk, uint8_t *sk) {
  gcry_err_code_t ec = 0;
  unsigned int i;
  byte *seedbuf = NULL;
  const uint8_t *rho, *rhoprime, *key;
  gcry_mldsa_polybuf_al rowbuf = {};
  byte *row = NULL;
  gcry_mldsa_polybuf_al s1 = {};
  gcry_mldsa_polybuf_al s2 = {};
  gcry_mldsa_polybuf_al t1 = {};
  gcry_mldsa_polybuf_al t0 = {};
  const size_t polysize = sizeof(gcry_mldsa_poly);

  if((ec = _gcry_mldsa_polybuf_al_create(&rowbuf, 2, params->l))
  || (ec = _gcry_mldsa_polybuf_al_create(&s1, 1, params->l))
  || (ec = _gcry_mldsa_polybuf_al_create(&s2, 1, params->k))
  || (ec = _gcry_mldsa_polybuf_al_create(&t1, 1, 1))
  || (ec = _gcry_mldsa_polybuf_al_create(&t0, 1, 1))
  )
  {
      ec = gpg_err_code_from_syserror();
      goto leave;
  }

  row = rowbuf.buf;

  if (!(seedbuf = xtrymalloc_secure(2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES)))
  {
    ec = gpg_error_from_syserror();
    goto leave;
  }

  /* Get randomness for rho, rhoprime and key */
  _gcry_randomize(seedbuf, GCRY_MLDSA_SEEDBYTES, GCRY_VERY_STRONG_RANDOM);

  ec = _gcry_mldsa_shake256(
      seedbuf, GCRY_MLDSA_SEEDBYTES, NULL, 0, seedbuf, 2 * GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  rho = seedbuf;
  rhoprime = rho + GCRY_MLDSA_SEEDBYTES;
  key = rhoprime + GCRY_MLDSA_CRHBYTES;

  /* Store rho, key */
  memcpy(pk, rho, GCRY_MLDSA_SEEDBYTES);
  memcpy(sk, rho, GCRY_MLDSA_SEEDBYTES);
  memcpy(sk + GCRY_MLDSA_SEEDBYTES, key, GCRY_MLDSA_SEEDBYTES);

  /* Sample short vectors s1 and s2 */
  poly_uniform_eta_4x(&s1.buf[0 * polysize], &s1.buf[1 * polysize], &s1.buf[2 * polysize], &s1.buf[3 * polysize], rhoprime, 0, 1, 2, 3);
  if(params->k == 4 && params->l == 4)
  {
    poly_uniform_eta_4x(&s2.buf[0 * polysize], &s2.buf[1 * polysize], &s2.buf[2 * polysize], &s2.buf[3 * polysize], rhoprime, 4, 5, 6, 7);
  }
  else if (params->k == 6 && params->l == 5)
  {
    poly_uniform_eta_4x(&s1.buf[4 * polysize], &s2.buf[0 * polysize], &s2.buf[1 * polysize], &s2.buf[2 * polysize], rhoprime, 4, 5, 6, 7);
    poly_uniform_eta_4x(&s2.buf[3 * polysize], &s2.buf[4 * polysize], &s2.buf[5 * polysize], t0.buf, rhoprime, 8, 9, 10, 11);
  }
  else if (params->k == 8 && params->l == 7)
  {
    poly_uniform_eta_4x(&s1.buf[4 * polysize], &s1.buf[5 * polysize], &s1.buf[6 * polysize], &s2.buf[0 * polysize], rhoprime, 4, 5, 6, 7);
    poly_uniform_eta_4x(&s2.buf[1 * polysize], &s2.buf[2 * polysize], &s2.buf[3 * polysize], &s2.buf[4 * polysize], rhoprime, 8, 9, 10, 11);
    poly_uniform_eta_4x(&s2.buf[5 * polysize], &s2.buf[6 * polysize], &s2.buf[7 * polysize], t0.buf, rhoprime, 12, 13, 14, 15);
  }
  else {
    ec = GPG_ERR_INV_STATE;
    goto leave;
  }
  /* Pack secret vectors */
  for(i = 0; i < params->l; i++)
    polyeta_pack(sk + 2*GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES + i*params->polyeta_packedbytes, &s1.buf[i * polysize]);
  for(i = 0; i < params->k; i++)
    polyeta_pack(sk + 2*GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES + (params->l + i)*params->polyeta_packedbytes, &s2.buf[i * polysize]);

  /* Transform s1 */
  polyvecl_ntt(params, s1.buf);

  for(i = 0; i < params->k; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(params, &row, rowbuf.buf, rho, i);

    /* Compute inner-product */
    polyvecl_pointwise_acc_montgomery(t1.buf, row, s1.buf);
    poly_invntt_tomont(t1.buf);

    /* Add error polynomial */
    poly_add(t1.buf, t1.buf, &s2.buf[i * polysize]);

    /* Round t and pack t1, t0 */
    poly_caddq(t1.buf);
    poly_power2round(t1.buf, t0.buf, t1.buf);
    polyt1_pack(pk + GCRY_MLDSA_SEEDBYTES + i*GCRY_MLDSA_POLYT1_PACKEDBYTES, t1.buf);
    polyt0_pack(sk + 2*GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES + (params->l+params->k)*params->polyeta_packedbytes + i*GCRY_MLDSA_POLYT0_PACKEDBYTES, t0.buf);
  }

  /* Compute H(rho, t1) and store in secret key */
  /* TODO */
  ec = _gcry_mldsa_shake256(pk, params->public_key_bytes, NULL, 0, sk + 2*GCRY_MLDSA_SEEDBYTES, GCRY_MLDSA_TRBYTES);
  if (ec)
    goto leave;

leave:
  xfree(seedbuf);
  _gcry_mldsa_polybuf_al_destroy(&rowbuf);
  _gcry_mldsa_polybuf_al_destroy(&s1);
  _gcry_mldsa_polybuf_al_destroy(&s2);
  _gcry_mldsa_polybuf_al_destroy(&t1);
  _gcry_mldsa_polybuf_al_destroy(&t0);
  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig: pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(gcry_mldsa_param_t *params, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
  gcry_err_code_t ec = 0;
  unsigned int i, n, pos;
  byte *seedbuf = NULL;
  byte *rho, *tr, *key, *mu, *rhoprime, *hint;
  byte *hintbuf = NULL;
  uint64_t nonce = 0;
  gcry_mldsa_polybuf_al mat = {};
  gcry_mldsa_polybuf_al s1 = {};
  gcry_mldsa_polybuf_al z = {};
  gcry_mldsa_polybuf_al t0 = {};
  gcry_mldsa_polybuf_al s2 = {};
  gcry_mldsa_polybuf_al w1 = {};
  gcry_mldsa_polybuf_al tmpv = {};
  gcry_mldsa_poly c, tmp;
  // union {
  //   polyvecl y;
  //   polyveck w0;
  // } tmpv;
  const size_t polysize = sizeof(gcry_mldsa_poly);
  gcry_md_hd_t hd = NULL;

  if(
    (ec =  _gcry_mldsa_polybuf_al_create(&mat, params->k, params->l))
    || (ec =  _gcry_mldsa_polybuf_al_create(&s1, 1, params->l))
    || (ec =  _gcry_mldsa_polybuf_al_create(&z, 1, params->l))
    || (ec =  _gcry_mldsa_polybuf_al_create(&tmpv, 1, params->k))
    || (ec =  _gcry_mldsa_polybuf_al_create(&t0, 1, params->k))
    || (ec =  _gcry_mldsa_polybuf_al_create(&s2, 1, params->k))
    || (ec =  _gcry_mldsa_polybuf_al_create(&w1, 1, params->k))
  )
  {
      ec = gpg_err_code_from_syserror();
      goto leave;
  }

  if (!(seedbuf = xtrymalloc_secure(2*GCRY_MLDSA_SEEDBYTES + GCRY_MLDSA_TRBYTES + 2*GCRY_MLDSA_CRHBYTES)))
  {
    ec = gpg_error_from_syserror();
    goto leave;
  }
  if (!(hintbuf = xtrymalloc_secure(GCRY_MLDSA_N)))
  {
    ec = gpg_error_from_syserror();
    goto leave;
  }

  hint = sig + params->ctildebytes + params->l*params->polyz_packedbytes;

  rho = seedbuf;
  tr = rho + GCRY_MLDSA_SEEDBYTES;
  key = tr + GCRY_MLDSA_TRBYTES;
  mu = key + GCRY_MLDSA_SEEDBYTES;
  rhoprime = mu + GCRY_MLDSA_CRHBYTES;
  unpack_sk(params, rho, tr, key, t0.buf, s1.buf, s2.buf, sk);

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
  polyvec_matrix_expand(params, mat.buf, rho);
  polyvecl_ntt(params, s1.buf);
  polyveck_ntt(params, s2.buf);
  polyveck_ntt(params, t0.buf);

rej:
  /* Sample intermediate vector y */
if(params->l == 4)
{
  poly_uniform_gamma1_4x(&z.buf[0 * polysize], &z.buf[1 * polysize], &z.buf[2 * polysize], &z.buf[3 * polysize],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  nonce += 4;
}
else if (params->l == 5)
{
  poly_uniform_gamma1_4x(&z.buf[0 * polysize], &z.buf[1 * polysize], &z.buf[2 * polysize], &z.buf[3 * polysize],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1(&z.buf[4 * polysize], rhoprime, nonce + 4);
  nonce += 5;
 } else if(params->l == 7)
 {

  poly_uniform_gamma1_4x(&z.buf[0 * polysize], &z.buf[1 * polysize], &z.buf[2 * polysize], &z.buf[3 * polysize],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1_4x(&z.buf[4 * polysize], &z.buf[5 * polysize], &z.buf[6 * polysize], &tmp,
                         rhoprime, nonce + 4, nonce + 5, nonce + 6, 0);
  nonce += 7;
}
else {
  return GPG_ERR_INV_STATE;
}

  /* Matrix-vector product */
  memcpy(tmpv.buf, z.buf, params->l * polysize);
  polyvecl_ntt(params, tmpv.buf);
  polyvec_matrix_pointwise_montgomery(params, w1.buf, mat.buf, tmpv.buf);
  polyveck_invntt_tomont(params, w1.buf);

  /* Decompose w and call the random oracle */
  polyveck_caddq(params, w1.buf);
  polyveck_decompose(params, w1.buf, tmpv.buf, w1.buf);
  polyveck_pack_w1(params, sig, w1.buf);

  ec = _gcry_md_open(&hd, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);
  if (ec)
    goto leave;
  _gcry_md_write(hd, mu, GCRY_MLDSA_CRHBYTES);
  _gcry_md_write(hd, sig, params->k * params->polyw1_packedbytes);
  ec = _gcry_md_extract(hd, GCRY_MD_SHAKE256, sig, params->ctildebytes);
  if (ec)
    goto leave;
  _gcry_md_close(hd);
  poly_challenge(&c, sig);
  poly_ntt(&c);

  /* Compute z, reject if it reveals secret */
  for(i = 0; i < params->l; i++) {
    poly_pointwise_montgomery(&tmp, &c, &s1.buf[i * polysize]);
    poly_invntt_tomont(&tmp);
    poly_add(&z.buf[i * polysize], &z.buf[i * polysize], &tmp);
    poly_reduce(&z.buf[i * polysize]);
    if(poly_chknorm(&z.buf[i * polysize], params->gamma1 - params->beta))
      goto rej;
  }

  /* Zero hint vector in signature */
  pos = 0;
  memset(hint, 0, params->omega);

  for(i = 0; i < params->k; i++) {
    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    poly_pointwise_montgomery(&tmp, &c, &s2.buf[i * polysize]);
    poly_invntt_tomont(&tmp);
    poly_sub(&tmpv.buf[i * polysize], &tmpv.buf[i * polysize], &tmp);
    poly_reduce(&tmpv.buf[i * polysize]);
    if(poly_chknorm(&tmpv.buf[i * polysize], params->gamma2 - params->beta))
      goto rej;

    /* Compute hints */
    poly_pointwise_montgomery(&tmp, &c, &t0.buf[i * polysize]);
    poly_invntt_tomont(&tmp);
    poly_reduce(&tmp);
    if(poly_chknorm(&tmp, params->gamma2))
      goto rej;

    poly_add(&tmpv.buf[i * polysize], &tmpv.buf[i * polysize], &tmp);
    n = poly_make_hint(hintbuf, &tmpv.buf[i * polysize], &w1.buf[i * polysize]);
    if(pos + n > params->omega)
      goto rej;

    /* Store hints in signature */
    memcpy(&hint[pos], hintbuf, n);
    hint[params->omega + i] = pos = pos + n;
  }

  /* Pack z into signature */
  for(i = 0; i < params->l; i++)
    polyz_pack(sig + params->ctildebytes + i*params->polyz_packedbytes, &z.buf[i * polysize]);

  *siglen = params->signature_bytes;

leave:
  xfree(seedbuf);
  xfree(hintbuf);
  _gcry_mldsa_polybuf_al_destroy(&mat);
  _gcry_mldsa_polybuf_al_destroy(&s1);
  _gcry_mldsa_polybuf_al_destroy(&s2);
  _gcry_mldsa_polybuf_al_destroy(&t0);
  _gcry_mldsa_polybuf_al_destroy(&w1);
  _gcry_mldsa_polybuf_al_destroy(&z);
  _gcry_mldsa_polybuf_al_destroy(&tmpv);
  return ec;
}


/*************************************************
* Name:        crypto_sign_verify
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
int crypto_sign_verify(gcry_mldsa_param_t *params, const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
  gcry_err_code_t ec = 0;
  unsigned int i, j, pos = 0;
  gcry_mldsa_buf_al buf = {};
  byte *mu = NULL;
  const uint8_t *hint = sig + params->ctildebytes + params->l*params->polyz_packedbytes;
  gcry_mldsa_polybuf_al rowbuf = {};
  byte *row = NULL;
  gcry_mldsa_polybuf_al z = {};
  gcry_mldsa_polybuf_al c = {};
  gcry_mldsa_polybuf_al w1 = {};
  gcry_mldsa_polybuf_al h = {};
  const size_t polysize = sizeof(gcry_mldsa_poly);

  if(siglen != params->signature_bytes)
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  if(
    (ec =   _gcry_mldsa_polybuf_al_create(&rowbuf, 2, params->l))
    || (ec =   _gcry_mldsa_polybuf_al_create(&z, 1, params->l))
    || (ec =   _gcry_mldsa_polybuf_al_create(&c, 1, 1))
    || (ec =   _gcry_mldsa_polybuf_al_create(&w1, 1, 1))
    || (ec =   _gcry_mldsa_polybuf_al_create(&h, 1, 1))
  )
  {
      ec = gpg_err_code_from_syserror();
      goto leave;
  }

  row = rowbuf.buf;

  /* polyw1_pack writes additional 14 bytes */
  _gcry_mldsa_buf_al_create(&buf, params->k*params->polyw1_packedbytes+14);

  if (!(mu = xtrymalloc_secure(GCRY_MLDSA_CRHBYTES)))
  {
    ec = gpg_error_from_syserror();
    goto leave;
  }

  ec = _gcry_mldsa_shake256(pk, params->public_key_bytes, NULL, 0, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256(mu, GCRY_MLDSA_CRHBYTES, m, mlen, mu, GCRY_MLDSA_CRHBYTES);
  if (ec)
    goto leave;

  /* Expand challenge */
  poly_challenge(c.buf, sig);
  poly_ntt(c.buf);

  /* Unpack z; shortness follows from unpacking */
  for(i = 0; i < params->l; i++) {
    polyz_unpack(&z.buf[i * polysize], sig + params->ctildebytes + i*params->polyz_packedbytes);
    poly_ntt(&z.buf[i * polysize]);
  }

  for(i = 0; i < params->k; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(params, &row, rowbuf.buf, pk, i);

    /* Compute i-th row of Az - c2^Dt1 */
    polyvecl_pointwise_acc_montgomery(w1.buf, row, z.buf);

    polyt1_unpack(h.buf, pk + GCRY_MLDSA_SEEDBYTES + i*GCRY_MLDSA_POLYT1_PACKEDBYTES);
    poly_shiftl(h.buf);
    poly_ntt(h.buf);
    poly_pointwise_montgomery(h.buf, c.buf, h.buf);

    poly_sub(w1.buf, w1.buf, h.buf);
    poly_reduce(w1.buf);
    poly_invntt_tomont(w1.buf);

    /* Get hint polynomial and reconstruct w1 */
    memset(h.buf, 0, polysize);
    if(hint[params->omega + i] < pos || hint[params->omega + i] > params->omega)
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

    for(j = pos; j < hint[params->omega + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > pos && hint[j] <= hint[j-1])
      {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
      }
          h.buf[hint[j] * sizeof(s32)] = 1;
    }
    pos = hint[params->omega + i];

    poly_caddq(w1.buf);
    poly_use_hint(w1.buf, w1.buf, h.buf);
    polyw1_pack(buf.buf + i*params->polyw1_packedbytes, w1.buf);
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = pos; j < params->omega; ++j)
    if(hint[j])
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }

  /* Call random oracle and verify challenge */
  ec = _gcry_mldsa_shake256(
      mu, GCRY_MLDSA_CRHBYTES, buf.buf, params->k * params->polyw1_packedbytes, buf.buf, params->ctildebytes);
  if (ec)
    goto leave;

  for(i = 0; i < params->ctildebytes; ++i)
  {
    if(buf.buf[i] != sig[i])
    {
      ec = GPG_ERR_BAD_SIGNATURE;
      goto leave;
    }
  }

leave:
  xfree(mu);
  _gcry_mldsa_polybuf_al_destroy(&rowbuf);
  _gcry_mldsa_polybuf_al_destroy(&z);
  _gcry_mldsa_polybuf_al_destroy(&c);
  _gcry_mldsa_polybuf_al_destroy(&w1);
  _gcry_mldsa_polybuf_al_destroy(&h);
  _gcry_mldsa_buf_al_destroy(&buf);
  return ec;
}
