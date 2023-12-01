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

static inline void polyvec_matrix_expand_row(gcry_mldsa_param_t *params, byte **row, byte* buf, const uint8_t rho[SEEDBYTES], unsigned int i) {
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

  _gcry_mldsa_polybuf_al_create(&rowbuf, 2, params->l);
  _gcry_mldsa_polybuf_al_create(&s1, 1, params->l);
  _gcry_mldsa_polybuf_al_create(&s2, 1, params->k);
  _gcry_mldsa_polybuf_al_create(&t1, 1, 1);
  _gcry_mldsa_polybuf_al_create(&t0, 1, 1);
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
  polyvecl_ntt(s1.buf);

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
  unsigned int i, n, pos;
  uint8_t seedbuf[2*SEEDBYTES + TRBYTES + RNDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *rnd, *mu, *rhoprime;
  uint8_t hintbuf[N];
  uint8_t *hint = sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES;
  uint64_t nonce = 0;
  polyvecl mat[K], s1, z;
  polyveck t0, s2, w1;
  gcry_mldsa_poly c, tmp;
  union {
    polyvecl y;
    polyveck w0;
  } tmpv;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + TRBYTES;
  rnd = key + SEEDBYTES;
  mu = rnd + RNDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, TRBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rnd, RNDBYTES);
#else
  memset(rnd, 0, RNDBYTES);
#endif
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + RNDBYTES + CRHBYTES);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(params, mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
#if L == 4
  poly_uniform_gamma1_4x(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  nonce += 4;
#elif L == 5
  poly_uniform_gamma1_4x(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1(&z.vec[4], rhoprime, nonce + 4);
  nonce += 5;
#elif L == 7
  poly_uniform_gamma1_4x(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
                         rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
  poly_uniform_gamma1_4x(&z.vec[4], &z.vec[5], &z.vec[6], &tmp,
                         rhoprime, nonce + 4, nonce + 5, nonce + 6, 0);
  nonce += 7;
#else
#error
#endif

  /* Matrix-vector product */
  tmpv.y = z;
  polyvecl_ntt(&tmpv.y);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &tmpv.y);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &tmpv.w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, CTILDEBYTES, &state);
  poly_challenge(&c, sig);
  poly_ntt(&c);

  /* Compute z, reject if it reveals secret */
  for(i = 0; i < L; i++) {
    poly_pointwise_montgomery(&tmp, &c, &s1.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_add(&z.vec[i], &z.vec[i], &tmp);
    poly_reduce(&z.vec[i]);
    if(poly_chknorm(&z.vec[i], GAMMA1 - BETA))
      goto rej;
  }

  /* Zero hint vector in signature */
  pos = 0;
  memset(hint, 0, OMEGA);

  for(i = 0; i < K; i++) {
    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    poly_pointwise_montgomery(&tmp, &c, &s2.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_sub(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
    poly_reduce(&tmpv.w0.vec[i]);
    if(poly_chknorm(&tmpv.w0.vec[i], GAMMA2 - BETA))
      goto rej;

    /* Compute hints */
    poly_pointwise_montgomery(&tmp, &c, &t0.vec[i]);
    poly_invntt_tomont(&tmp);
    poly_reduce(&tmp);
    if(poly_chknorm(&tmp, GAMMA2))
      goto rej;

    poly_add(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
    n = poly_make_hint(hintbuf, &tmpv.w0.vec[i], &w1.vec[i]);
    if(pos + n > OMEGA)
      goto rej;

    /* Store hints in signature */
    memcpy(&hint[pos], hintbuf, n);
    hint[OMEGA + i] = pos = pos + n;
  }

  /* Pack z into signature */
  for(i = 0; i < L; i++)
    polyz_pack(sig + CTILDEBYTES + i*POLYZ_PACKEDBYTES, &z.vec[i]);

  *siglen = CRYPTO_BYTES;
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(gcry_mldsa_param_t *params, uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(params, sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0;
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
  unsigned int i, j, pos = 0;
  /* polyw1_pack writes additional 14 bytes */
  ALIGNED_UINT8(K*POLYW1_PACKEDBYTES+14) buf;
  uint8_t mu[CRHBYTES];
  const uint8_t *hint = sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES;
  polyvecl rowbuf[2];
  polyvecl *row = rowbuf;
  polyvecl z;
  gcry_mldsa_poly c, w1, h;
  keccak_state state;

  if(siglen != CRYPTO_BYTES)
    return -1;

  /* Compute CRH(H(rho, t1), msg) */
  shake256(mu, CRHBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

  /* Expand challenge */
  poly_challenge(&c, sig);
  poly_ntt(&c);

  /* Unpack z; shortness follows from unpacking */
  for(i = 0; i < L; i++) {
    polyz_unpack(&z.vec[i], sig + CTILDEBYTES + i*POLYZ_PACKEDBYTES);
    poly_ntt(&z.vec[i]);
  }

  for(i = 0; i < K; i++) {
    /* Expand matrix row */
    polyvec_matrix_expand_row(params, &row, rowbuf, pk, i);

    /* Compute i-th row of Az - c2^Dt1 */
    polyvecl_pointwise_acc_montgomery(&w1, row, &z);

    polyt1_unpack(&h, pk + SEEDBYTES + i*POLYT1_PACKEDBYTES);
    poly_shiftl(&h);
    poly_ntt(&h);
    poly_pointwise_montgomery(&h, &c, &h);

    poly_sub(&w1, &w1, &h);
    poly_reduce(&w1);
    poly_invntt_tomont(&w1);

    /* Get hint polynomial and reconstruct w1 */
    memset(h.vec, 0, sizeof(gcry_mldsa_poly));
    if(hint[OMEGA + i] < pos || hint[OMEGA + i] > OMEGA)
      return -1;

    for(j = pos; j < hint[OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > pos && hint[j] <= hint[j-1]) return -1;
      h.coeffs[hint[j]] = 1;
    }
    pos = hint[OMEGA + i];

    poly_caddq(&w1);
    poly_use_hint(&w1, &w1, &h);
    polyw1_pack(buf.coeffs + i*POLYW1_PACKEDBYTES, &w1);
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = pos; j < OMEGA; ++j)
    if(hint[j]) return -1;

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf.coeffs, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(buf.coeffs, CTILDEBYTES, &state);
  for(i = 0; i < CTILDEBYTES; ++i)
    if(buf.coeffs[i] != sig[i])
      return -1;

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(gcry_mldsa_param_t *params, uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk) {
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(params, sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
