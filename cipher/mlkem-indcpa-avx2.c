#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "mlkem-align-avx2.h"
#include "mlkem-params-avx2.h"
#include "mlkem-indcpa-avx2.h"
#include "mlkem-polyvec-avx2.h"
#include "mlkem-poly-avx2.h"
#include "mlkem-ntt-avx2.h"
#include "mlkem-cbd-avx2.h"
#include "mlkem-rejsample-avx2.h"
#include "mlkem-symmetric-avx2.h"


/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk and the
*              public seed used to generate the matrix A.
*              The polynomial coefficients in pk are assumed to
*              lie in the invertal [0,q], i.e. pk must be reduced
*              by polyvec_reduce().
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t *r,
                    polyvec *pk,
                    const uint8_t seed[GCRY_MLKEM_SYMBYTES],
                    const gcry_mlkem_param_t *param)
{
  polyvec_tobytes(r, pk, param);
  memcpy(r+param->polyvec_bytes, seed, GCRY_MLKEM_SYMBYTES);
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
static void unpack_pk(polyvec *pk,
                      uint8_t seed[GCRY_MLKEM_SYMBYTES],
                      const uint8_t *packedpk,
                      const gcry_mlkem_param_t *param)
{
  polyvec_frombytes(pk, packedpk, param);
  memcpy(seed, packedpk+param->polyvec_bytes, GCRY_MLKEM_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key.
*              The polynomial coefficients in sk are assumed to
*              lie in the invertal [0,q], i.e. sk must be reduced
*              by polyvec_reduce().
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t *r, polyvec *sk, const gcry_mlkem_param_t *param)
{
  polyvec_tobytes(r, sk, param);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t *packedsk, const gcry_mlkem_param_t *param)
{
  polyvec_frombytes(sk, packedsk, param);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v.
*              The polynomial coefficients in b and v are assumed to
*              lie in the invertal [0,q], i.e. b and v must be reduced
*              by polyvec_reduce() and poly_reduce(), respectively.
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t *r, polyvec *b, poly *v, const gcry_mlkem_param_t *param)
{
  polyvec_compress(r, b, param);
  if(param->poly_compressed_bytes == 128)
  {
    poly_compress_128(r+param->polyvec_compressed_bytes, v);
  }
  else {
    poly_compress_160(r+param->polyvec_compressed_bytes, v);
  }
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t *c, const gcry_mlkem_param_t *param)
{
  polyvec_decompress(b, c, param);
  if(param->poly_compressed_bytes == 128)
  {
    poly_decompress_128(v, c+param->polyvec_compressed_bytes);
  }
  else {
    poly_decompress_160(v, c+param->polyvec_compressed_bytes);
  }
}

/*************************************************
* Name:        rej_uniform
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
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < GCRY_MLKEM_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < GCRY_MLKEM_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

static void gen_matrix_k2(polyvec *a, const uint8_t seed[32], int transposed, const gcry_mlkem_param_t *param)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  gcry_mlkem_keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 1;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 1;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 1;
  }

  _gcry_mlkem_avx2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[1].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N || ctr3 < GCRY_MLKEM_N) {
    _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, GCRY_MLKEM_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, GCRY_MLKEM_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[1].vec[0].coeffs + ctr2, GCRY_MLKEM_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[1].coeffs + ctr3, GCRY_MLKEM_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[1].vec[0]);
  poly_nttunpack(&a[1].vec[1]);
}

static void gen_matrix_k3(polyvec *a, const uint8_t seed[32], int transposed, const gcry_mlkem_param_t *param)
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  gcry_mlkem_keccakx4_state state;
  keccak_state state1x;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 0;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 0;
  }
  else {
    buf[0].coeffs[32] = 0;
    buf[0].coeffs[33] = 0;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 0;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 0;
    buf[3].coeffs[33] = 1;
  }

  _gcry_mlkem_avx2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[0].vec[0].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[0].vec[1].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[0].vec[2].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[1].vec[0].coeffs, buf[3].coeffs);

  while(ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N || ctr3 < GCRY_MLKEM_N) {
    _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[0].vec[0].coeffs + ctr0, GCRY_MLKEM_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[0].vec[1].coeffs + ctr1, GCRY_MLKEM_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[0].vec[2].coeffs + ctr2, GCRY_MLKEM_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[1].vec[0].coeffs + ctr3, GCRY_MLKEM_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[0].vec[0]);
  poly_nttunpack(&a[0].vec[1]);
  poly_nttunpack(&a[0].vec[2]);
  poly_nttunpack(&a[1].vec[0]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  if(transposed) {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 1;
    buf[1].coeffs[33] = 2;
    buf[2].coeffs[32] = 2;
    buf[2].coeffs[33] = 0;
    buf[3].coeffs[32] = 2;
    buf[3].coeffs[33] = 1;
  }
  else {
    buf[0].coeffs[32] = 1;
    buf[0].coeffs[33] = 1;
    buf[1].coeffs[32] = 2;
    buf[1].coeffs[33] = 1;
    buf[2].coeffs[32] = 0;
    buf[2].coeffs[33] = 2;
    buf[3].coeffs[32] = 1;
    buf[3].coeffs[33] = 2;
  }

  _gcry_mlkem_avx2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(a[1].vec[1].coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(a[1].vec[2].coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(a[2].vec[0].coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(a[2].vec[1].coeffs, buf[3].coeffs);

  while(ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N || ctr3 < GCRY_MLKEM_N) {
    _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(a[1].vec[1].coeffs + ctr0, GCRY_MLKEM_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(a[1].vec[2].coeffs + ctr1, GCRY_MLKEM_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(a[2].vec[0].coeffs + ctr2, GCRY_MLKEM_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(a[2].vec[1].coeffs + ctr3, GCRY_MLKEM_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[1].vec[1]);
  poly_nttunpack(&a[1].vec[2]);
  poly_nttunpack(&a[2].vec[0]);
  poly_nttunpack(&a[2].vec[1]);

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  buf[0].coeffs[32] = 2;
  buf[0].coeffs[33] = 2;
  shake128_absorb_once(&state1x, buf[0].coeffs, 34);
  shake128_squeezeblocks(buf[0].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state1x);
  ctr0 = rej_uniform_avx(a[2].vec[2].coeffs, buf[0].coeffs);
  while(ctr0 < GCRY_MLKEM_N) {
    shake128_squeezeblocks(buf[0].coeffs, 1, &state1x);
    ctr0 += rej_uniform(a[2].vec[2].coeffs + ctr0, GCRY_MLKEM_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(&a[2].vec[2]);
}

static void gen_matrix_k4(polyvec *a, const uint8_t seed[32], int transposed, const gcry_mlkem_param_t *param)
{
  unsigned int i, ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  gcry_mlkem_keccakx4_state state;

  for(i=0;i<4;i++) {
    f = _mm256_loadu_si256((__m256i *)seed);
    _mm256_store_si256(buf[0].vec, f);
    _mm256_store_si256(buf[1].vec, f);
    _mm256_store_si256(buf[2].vec, f);
    _mm256_store_si256(buf[3].vec, f);

    if(transposed) {
      buf[0].coeffs[32] = i;
      buf[0].coeffs[33] = 0;
      buf[1].coeffs[32] = i;
      buf[1].coeffs[33] = 1;
      buf[2].coeffs[32] = i;
      buf[2].coeffs[33] = 2;
      buf[3].coeffs[32] = i;
      buf[3].coeffs[33] = 3;
    }
    else {
      buf[0].coeffs[32] = 0;
      buf[0].coeffs[33] = i;
      buf[1].coeffs[32] = 1;
      buf[1].coeffs[33] = i;
      buf[2].coeffs[32] = 2;
      buf[2].coeffs[33] = i;
      buf[3].coeffs[32] = 3;
      buf[3].coeffs[33] = i;
    }

    _gcry_mlkem_avx2_shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
    _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

    ctr0 = rej_uniform_avx(a[i].vec[0].coeffs, buf[0].coeffs);
    ctr1 = rej_uniform_avx(a[i].vec[1].coeffs, buf[1].coeffs);
    ctr2 = rej_uniform_avx(a[i].vec[2].coeffs, buf[2].coeffs);
    ctr3 = rej_uniform_avx(a[i].vec[3].coeffs, buf[3].coeffs);

    while(ctr0 < GCRY_MLKEM_N || ctr1 < GCRY_MLKEM_N || ctr2 < GCRY_MLKEM_N || ctr3 < GCRY_MLKEM_N) {
      _gcry_mlkem_avx2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

      ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0, GCRY_MLKEM_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
      ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1, GCRY_MLKEM_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
      ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2, GCRY_MLKEM_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
      ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3, GCRY_MLKEM_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
    }

    poly_nttunpack(&a[i].vec[0]);
    poly_nttunpack(&a[i].vec[1]);
    poly_nttunpack(&a[i].vec[2]);
    poly_nttunpack(&a[i].vec[3]);
  }
}

void gen_matrix(polyvec *a, const uint8_t seed[GCRY_MLKEM_SYMBYTES], int transposed, const gcry_mlkem_param_t *param)
{
  if(param->k == 2)
  {
    gen_matrix_k2(a, seed, transposed, param);
  }
  if(param->k == 3)
  {
    gen_matrix_k3(a, seed, transposed, param);
  }
  if(param->k == 4)
  {
    gen_matrix_k4(a, seed, transposed, param);
  }
}


gcry_err_code_t indcpa_keypair_derand(uint8_t *pk,
                           uint8_t *sk,
                           const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                           const gcry_mlkem_param_t *param)
{
  gcry_err_code_t ec = 0;
  unsigned int i;
  uint8_t buf[2*GCRY_MLKEM_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + GCRY_MLKEM_SYMBYTES;
  //polyvec a[param->k];
  // polyvec e;
  // polyvec pkpv, skpv;

  gcry_mlkem_polyvec_al a_al;
  gcry_mlkem_polyvec_al e_al;
  gcry_mlkem_polyvec_al pkpv_al;
  gcry_mlkem_polyvec_al skpv_al;
  _gcry_mlkem_polyvec_al_create(&a_al, param->k * param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&e_al, param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&pkpv_al, param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&skpv_al, param->k, param->k * sizeof(poly), 1);
  polyvec *a = a_al.vec;
  polyvec *e = e_al.vec;
  polyvec *pkpv = pkpv_al.vec;
  polyvec *skpv = skpv_al.vec;

  hash_g(buf, coins, GCRY_MLKEM_SYMBYTES);

  gen_matrix(a, publicseed, 0, param);

  if(param->k == 2)
  {
    poly_getnoise_eta1_4x(skpv->vec+0, skpv->vec+1, e->vec+0, e->vec+1, noiseseed, 0, 1, 2, 3, param);
  }
  else if(param->k == 3)
  {
    poly_getnoise_eta1_4x(skpv->vec+0, skpv->vec+1, skpv->vec+2, e->vec+0, noiseseed, 0, 1, 2, 3, param);
    poly_getnoise_eta1_4x(e->vec+1, e->vec+2, pkpv->vec+0, pkpv->vec+1, noiseseed, 4, 5, 6, 7, param);
  }
  else if(param->k == 4)
  {
    poly_getnoise_eta1_4x(skpv->vec+0, skpv->vec+1, skpv->vec+2, skpv->vec+3, noiseseed,  0, 1, 2, 3, param);
    poly_getnoise_eta1_4x(e->vec+0, e->vec+1, e->vec+2, e->vec+3, noiseseed, 4, 5, 6, 7, param);
  }
  else {
    // TODO err
  }

  polyvec_ntt(skpv, param);
  polyvec_reduce(skpv, param);
  polyvec_ntt(e, param);

  // matrix-vector multiplication
  for(i=0;i<param->k;i++) {
    polyvec_basemul_acc_montgomery(&pkpv->vec[i], &a[i], skpv, param);
    poly_tomont(&pkpv->vec[i]);
  }

  polyvec_add(pkpv, pkpv, e, param);
  polyvec_reduce(pkpv, param);

  pack_sk(sk, skpv, param);
  pack_pk(pk, pkpv, publicseed, param);

  _gcry_mlkem_polyvec_al_destroy(&a_al);
  _gcry_mlkem_polyvec_al_destroy(&e_al);
  _gcry_mlkem_polyvec_al_destroy(&pkpv_al);
  _gcry_mlkem_polyvec_al_destroy(&skpv_al);
  return ec;
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*              - const uint8_t *m: pointer to input message
*              - const uint8_t *pk: pointer to input public key
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t *c,
                const uint8_t *m,
                const uint8_t *pk,
                const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                const gcry_mlkem_param_t *param)
{
  unsigned int i;
  uint8_t seed[GCRY_MLKEM_SYMBYTES];
  //polyvec sp, pkpv, ep, at[param->k], b;
  poly v, k, epp;



  gcry_mlkem_polyvec_al sp_al;
  gcry_mlkem_polyvec_al pkpv_al;
  gcry_mlkem_polyvec_al ep_al;
  gcry_mlkem_polyvec_al at_al;
  gcry_mlkem_polyvec_al b_al;
  _gcry_mlkem_polyvec_al_create(&sp_al, param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&pkpv_al, param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&ep_al, param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&at_al, param->k * param->k, param->k * sizeof(poly), 1);
  _gcry_mlkem_polyvec_al_create(&b_al, param->k, param->k * sizeof(poly), 1);

  polyvec *sp = sp_al.vec;
  polyvec *pkpv = pkpv_al.vec;
  polyvec *ep = ep_al.vec;
  polyvec *at = at_al.vec;
  polyvec *b = b_al.vec;


  unpack_pk(pkpv, seed, pk, param);
  poly_frommsg(&k, m);
  gen_matrix(at, seed, 1, param);

if(param->k == 2)
{
  poly_getnoise_eta1122_4x(sp->vec+0, sp->vec+1, ep->vec+0, ep->vec+1, coins, 0, 1, 2, 3, param);
  poly_getnoise_eta2(&epp, coins, 4);
}
else if(param->k == 3)
{
  poly_getnoise_eta1_4x(sp->vec+0, sp->vec+1, sp->vec+2, ep->vec+0, coins, 0, 1, 2, 3, param);
  poly_getnoise_eta1_4x(ep->vec+1, ep->vec+2, &epp, b->vec+0, coins,  4, 5, 6, 7, param);
}
else if(param->k == 4)
{
  poly_getnoise_eta1_4x(sp->vec+0, sp->vec+1, sp->vec+2, sp->vec+3, coins, 0, 1, 2, 3, param);
  poly_getnoise_eta1_4x(ep->vec+0, ep->vec+1, ep->vec+2, ep->vec+3, coins, 4, 5, 6, 7, param);
  poly_getnoise_eta2(&epp, coins, 8);
}

  polyvec_ntt(sp, param);

  // matrix-vector multiplication
  for(i=0;i<param->k;i++)
    polyvec_basemul_acc_montgomery(&b->vec[i], &at[i], sp, param);
  polyvec_basemul_acc_montgomery(&v, pkpv, sp, param);

  polyvec_invntt_tomont(b, param);
  poly_invntt_tomont(&v);

  polyvec_add(b, b, ep, param);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(b, param);
  poly_reduce(&v);

  pack_ciphertext(c, b, &v, param);

  _gcry_mlkem_polyvec_al_destroy(&sp_al);
  _gcry_mlkem_polyvec_al_destroy(&pkpv_al);
  _gcry_mlkem_polyvec_al_destroy(&ep_al);
  _gcry_mlkem_polyvec_al_destroy(&at_al);
  _gcry_mlkem_polyvec_al_destroy(&b_al);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*              - const uint8_t *c: pointer to input ciphertext
*              - const uint8_t *sk: pointer to input secret key
**************************************************/
void indcpa_dec(uint8_t *m,
                const uint8_t *c,
                const uint8_t *sk,
                const gcry_mlkem_param_t *param)
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c, param);
  unpack_sk(&skpv, sk, param);

  polyvec_ntt(&b, param);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b, param);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
