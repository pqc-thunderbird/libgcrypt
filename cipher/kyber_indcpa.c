#include <stddef.h>
#include <stdint.h>
#include "kyber_params.h"
#include "kyber_indcpa.h"
#include "kyber_polyvec.h"
#include "kyber_poly.h"
#include "kyber_ntt.h"
#include "kyber_symmetric.h"

/*************************************************
 * Name:        pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   uint8_t *r: pointer to the output serialized public key
 *              gcry_kyber_polyvec *pk: pointer to the input public-key
 *gcry_kyber_polyvec const uint8_t *seed: pointer to the input public seed
 **************************************************/
static void pack_pk(uint8_t *r,
                    gcry_kyber_polyvec *pk,
                    const uint8_t seed[GCRY_KYBER_SYMBYTES],
                    gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_tobytes(r, pk, param);
  memcpy(r + param->polyvec_bytes, seed, GCRY_KYBER_SYMBYTES);
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of pack_pk
 *
 * Arguments:   - gcry_kyber_polyvec *pk: pointer to output public-key
 *polynomial vector
 *              - uint8_t *seed: pointer to output seed to generate matrix A
 *              - const uint8_t *packedpk: pointer to input serialized public
 *key
 **************************************************/
static void unpack_pk(gcry_kyber_polyvec *pk,
                      uint8_t seed[GCRY_KYBER_SYMBYTES],
                      const uint8_t *packedpk,
                      gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_frombytes(pk, packedpk, param);
  memcpy(seed, packedpk + param->polyvec_bytes, GCRY_KYBER_SYMBYTES);
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - uint8_t *r: pointer to output serialized secret key
 *              - gcry_kyber_polyvec *sk: pointer to input vector of
 *polynomials (secret key)
 **************************************************/
static void pack_sk(uint8_t *r,
                    gcry_kyber_polyvec *sk,
                    gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_tobytes(r, sk, param);
}

/*************************************************
 * Name:        unpack_sk
 *
 * Description: De-serialize the secret key; inverse of pack_sk
 *
 * Arguments:   - gcry_kyber_polyvec *sk: pointer to output vector of
 *polynomials (secret key)
 *              - const uint8_t *packedsk: pointer to input serialized secret
 *key
 **************************************************/
static void unpack_sk(gcry_kyber_polyvec *sk,
                      const uint8_t *packedsk,
                      gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_frombytes(sk, packedsk, param);
}

/*************************************************
 * Name:        pack_ciphertext
 *
 * Description: Serialize the ciphertext as concatenation of the
 *              compressed and serialized vector of polynomials b
 *              and the compressed and serialized polynomial v
 *
 * Arguments:   uint8_t *r: pointer to the output serialized ciphertext
 *              poly *pk: pointer to the input vector of polynomials b
 *              poly *v: pointer to the input polynomial v
 **************************************************/
static void pack_ciphertext(uint8_t *r,
                            gcry_kyber_polyvec *b,
                            poly *v,
                            gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_compress(r, b, param);
  poly_compress(r + param->polyvec_compressed_bytes, v, param);
}

/*************************************************
 * Name:        unpack_ciphertext
 *
 * Description: De-serialize and decompress ciphertext from a byte array;
 *              approximate inverse of pack_ciphertext
 *
 * Arguments:   - gcry_kyber_polyvec *b: pointer to the output vector of
 *polynomials b
 *              - poly *v: pointer to the output polynomial v
 *              - const uint8_t *c: pointer to the input serialized ciphertext
 **************************************************/
static void unpack_ciphertext(gcry_kyber_polyvec *b,
                              poly *v,
                              const uint8_t *c,
                              gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec_decompress(b, c, param);
  poly_decompress(v, c + param->polyvec_compressed_bytes, param);
}

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r: pointer to output buffer
 *              - unsigned int len: requested number of 16-bit integers
 *(uniform mod q)
 *              - const uint8_t *buf: pointer to input buffer (assumed to be
 *uniformly random bytes)
 *              - unsigned int buflen: length of input buffer in bytes
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen)
    {
      val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
      val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
      pos += 3;

      if (val0 < KYBER_Q)
        r[ctr++] = val0;
      if (ctr < len && val1 < KYBER_Q)
        r[ctr++] = val1;
    }

  return ctr;
}

#define gen_a(A, B, param) gen_matrix(A, B, 0, param)
#define gen_at(A, B, param) gen_matrix(A, B, 1, param)

/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - gcry_kyber_polyvec *a: pointer to ouptput matrix A
 *              - const uint8_t *seed: pointer to input seed
 *              - int transposed: boolean deciding whether A or A^T is
 *generated
 **************************************************/
#define GEN_MATRIX_NBLOCKS                                                    \
  ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)
// Not static for benchmarking
gcry_err_code_t gen_matrix(gcry_kyber_polyvec *a,
                           const uint8_t seed[GCRY_KYBER_SYMBYTES],
                           int transposed,
                           gcry_kyber_param_t const *param)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
  gcry_err_code_t ec = 0;

  for (i = 0; i < param->k; i++)
    {
      for (j = 0; j < param->k; j++)
        {

          gcry_md_hd_t h;
          if ((ec = _gcry_md_open(&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE)))
            {
              return ec;
            }
          if (transposed)
            {
              _gcry_kyber_shake128_absorb(h, seed, i, j);
            }
          else
            {
              _gcry_kyber_shake128_absorb(h, seed, j, i);

            }

          _gcry_kyber_shake128_squeezeblocks(h, buf, GEN_MATRIX_NBLOCKS);
          buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;

          ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

          while (ctr < KYBER_N)
            {
              off = buflen % 3;
              for (k = 0; k < off; k++)
                {
                  buf[k] = buf[buflen - off + k];
                }

              _gcry_kyber_shake128_squeezeblocks(h, buf + off, 1);
              buflen = off + XOF_BLOCKBYTES;
              ctr += rej_uniform(
                  a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }

        _gcry_md_close(h);
        }
    }
  return 0;
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
gcry_error_t indcpa_keypair(uint8_t *pk,
                            uint8_t *sk,
                            gcry_kyber_param_t const *param,
                            uint8_t *coins)
{
  unsigned int i;
  uint8_t buf[2 * GCRY_KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed  = buf + GCRY_KYBER_SYMBYTES;
  uint8_t nonce             = 0;
  gcry_kyber_polyvec *a = NULL, e = {.vec = NULL}, pkpv = {.vec = NULL},
                     skpv = {.vec = NULL};
  gcry_error_t ec         = 0;

  if ((ec = gcry_kyber_polymatrix_create(&a, param))
      || (ec = gcry_kyber_polyvec_create(&e, param))
      || (ec = gcry_kyber_polyvec_create(&pkpv, param))
      || (ec = gcry_kyber_polyvec_create(&skpv, param)))
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }


  _gcry_md_hash_buffer(GCRY_MD_SHA3_512, buf, coins, GCRY_KYBER_SYMBYTES);

  if ((ec = gen_a(a, publicseed, param)))
    {
      goto leave;
    }

  for (i = 0; i < param->k; i++)
    {
      poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++, param);
    }
  for (i = 0; i < param->k; i++)
    {
      poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++, param);
    }

  gcry_kyber_polyvec_ntt(&skpv, param);
  gcry_kyber_polyvec_ntt(&e, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    {
      gcry_kyber_polyvec_basemul_acc_montgomery(
          &pkpv.vec[i], &a[i], &skpv, param);
      poly_tomont(&pkpv.vec[i]);
    }

  gcry_kyber_polyvec_add(&pkpv, &pkpv, &e, param);
  gcry_kyber_polyvec_reduce(&pkpv, param);

  pack_sk(sk, &skpv, param);
  pack_pk(pk, &pkpv, publicseed, param);
leave:
  gcry_kyber_polymatrix_destroy(&a, param);
  gcry_kyber_polyvec_destroy(&e);
  gcry_kyber_polyvec_destroy(&pkpv);
  gcry_kyber_polyvec_destroy(&skpv);

  return ec;
}

/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *c: pointer to output ciphertext
 *                            (of length KYBER_INDCPA_BYTES bytes)
 *              - const uint8_t *m: pointer to input message
 *                                  (of length GCRY_KYBER_INDCPA_MSGBYTES
 *bytes)
 *              - const uint8_t *pk: pointer to input public key
 *                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
 *              - const uint8_t *coins: pointer to input random coins used as
 *seed (of length GCRY_KYBER_SYMBYTES) to deterministically generate all
 *randomness
 **************************************************/
gcry_error_t indcpa_enc(uint8_t *c,
                        const uint8_t *m,
                        const uint8_t *pk,
                        const uint8_t coins[GCRY_KYBER_SYMBYTES],
                        gcry_kyber_param_t const *param)
{
  unsigned int i;
  uint8_t seed[GCRY_KYBER_SYMBYTES];
  uint8_t nonce         = 0;
  gcry_kyber_polyvec sp = {.vec = NULL}, pkpv = {.vec = NULL},
                     ep = {.vec = NULL}, *at = NULL, b = {.vec = NULL};
  gcry_error_t ec = 0;
  poly v, k, epp;

  if ((ec = gcry_kyber_polyvec_create(&sp, param))
      || (ec = gcry_kyber_polyvec_create(&pkpv, param))
      || (ec = gcry_kyber_polyvec_create(&ep, param))
      || (ec = gcry_kyber_polyvec_create(&b, param))
      || (ec = gcry_kyber_polymatrix_create(&at, param)))
    {
      ec = gpg_err_code_from_syserror();
      goto end;
    }


  unpack_pk(&pkpv, seed, pk, param);
  poly_frommsg(&k, m);
  if ((ec = gen_at(at, seed, param)))
    {
      goto end;
    }

  for (i = 0; i < param->k; i++)
    {
      poly_getnoise_eta1(sp.vec + i, coins, nonce++, param);
    }
  for (i = 0; i < param->k; i++)
    {
      poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    }
  poly_getnoise_eta2(&epp, coins, nonce++);

  gcry_kyber_polyvec_ntt(&sp, param);

  // matrix-vector multiplication
  for (i = 0; i < param->k; i++)
    {
      gcry_kyber_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp, param);
    }

  gcry_kyber_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, param);

  gcry_kyber_polyvec_invntt_tomont(&b, param);
  poly_invntt_tomont(&v);

  gcry_kyber_polyvec_add(&b, &b, &ep, param);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  gcry_kyber_polyvec_reduce(&b, param);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v, param);
end:

  gcry_kyber_polyvec_destroy(&sp);
  gcry_kyber_polyvec_destroy(&pkpv);
  gcry_kyber_polyvec_destroy(&ep);
  gcry_kyber_polyvec_destroy(&b);
  gcry_kyber_polymatrix_destroy(&at, param);

  return ec;
}

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *m: pointer to output decrypted message
 *                            (of length GCRY_KYBER_INDCPA_MSGBYTES)
 *              - const uint8_t *c: pointer to input ciphertext
 *                                  (of length KYBER_INDCPA_BYTES)
 *              - const uint8_t *sk: pointer to input secret key
 *                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
 **************************************************/
gcry_error_t indcpa_dec(uint8_t *m,
                        const uint8_t *c,
                        const uint8_t *sk,
                        gcry_kyber_param_t const *param)
{
  gcry_kyber_polyvec b = {.vec = NULL}, skpv = {.vec = NULL};
  poly v, mp;
  gcry_error_t ec = 0;

  if ((ec = gcry_kyber_polyvec_create(&b, param))
      || (ec = gcry_kyber_polyvec_create(&skpv, param)))
    {
      ec = gpg_error_from_syserror();
      goto end;
    }

  unpack_ciphertext(&b, &v, c, param);
  unpack_sk(&skpv, sk, param);

  gcry_kyber_polyvec_ntt(&b, param);
  gcry_kyber_polyvec_basemul_acc_montgomery(&mp, &skpv, &b, param);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
end:
  gcry_kyber_polyvec_destroy(&skpv);
  gcry_kyber_polyvec_destroy(&b);
  return ec;
}