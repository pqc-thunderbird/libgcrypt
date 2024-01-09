#include "mldsa-poly-avx2.h"
#ifdef USE_AVX2
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "config.h"
#include "types.h"
#include "mldsa-symmetric.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-ntt-avx2.h"
#include "mldsa-rounding-avx2.h"
#include "mldsa-rejsample-avx2.h"
#include "mldsa-consts-avx2.h"
#include "mldsa-fips202x4-avx2.h"
#include "mldsa-polyvec.h"


#define REJ_UNIFORM_NBLOCKS ((768 + GCRY_STREAM128_BLOCKBYTES - 1) / GCRY_STREAM128_BLOCKBYTES)
#define REJ_UNIFORM_BUFLEN (REJ_UNIFORM_NBLOCKS * GCRY_STREAM128_BLOCKBYTES)

#define _mm256_blendv_epi32(a, b, mask)                                                                                \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), _mm256_castsi256_ps(b), _mm256_castsi256_ps(mask)))

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_reduce
 *
 * Description: Inplace reduction of all coefficients of polynomial to
 *              representative in [-6283009,6283007]. Assumes input
 *              coefficients to be at most 2^31 - 2^22 - 1 in absolute value.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_reduce(gcry_mldsa_poly *a)
{
  unsigned int i;
  __m256i f, g;
  const __m256i q   = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
  const __m256i off = _mm256_set1_epi32(1 << 22);

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      g = _mm256_add_epi32(f, off);
      g = _mm256_srai_epi32(g, 23);
      g = _mm256_mullo_epi32(g, q);
      f = _mm256_sub_epi32(f, g);
      _mm256_store_si256(&a->vec[i], f);
    }
}

/*************************************************
 * Name:        poly_addq
 *
 * Description: For all coefficients of in/out polynomial add GCRY_MLDSA_Q if
 *              coefficient is negative.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_caddq(gcry_mldsa_poly *a)
{
  unsigned int i;
  __m256i f, g;
  const __m256i q    = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
  const __m256i zero = _mm256_setzero_si256();

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      g = _mm256_blendv_epi32(zero, q, f);
      f = _mm256_add_epi32(f, g);
      _mm256_store_si256(&a->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_add
 *
 * Description: Add polynomials. No modular reduction is performed.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first summand
 *              - const gcry_mldsa_poly *b: pointer to second summand
 **************************************************/
void _gcry_mldsa_avx2_poly_add(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{
  unsigned int i;
  __m256i f, g;

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      g = _mm256_load_si256(&b->vec[i]);
      f = _mm256_add_epi32(f, g);
      _mm256_store_si256(&c->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_sub
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first input polynomial
 *              - const gcry_mldsa_poly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_sub(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{
  unsigned int i;
  __m256i f, g;

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      g = _mm256_load_si256(&b->vec[i]);
      f = _mm256_sub_epi32(f, g);
      _mm256_store_si256(&c->vec[i], f);
    }
}

/*************************************************
 * Name:        poly_shiftl
 *
 * Description: Multiply polynomial by 2^GCRY_MLDSA_D without modular reduction. Assumes
 *              input coefficients to be less than 2^{31-GCRY_MLDSA_D} in absolute value.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void poly_shiftl(gcry_mldsa_poly *a)
{
  unsigned int i;
  __m256i f;

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      f = _mm256_slli_epi32(f, GCRY_MLDSA_D);
      _mm256_store_si256(&a->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_ntt
 *
 * Description: Inplace forward NTT. Coefficients can grow by up to
 *              8*GCRY_MLDSA_Q in absolute value.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_ntt(gcry_mldsa_poly *a)
{

  _gcry_mldsa_avx2_ntt_avx(a->vec, qdata.vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_invntt_tomont
 *
 * Description: Inplace inverse NTT and multiplication by 2^{32}.
 *              Input coefficients need to be less than GCRY_MLDSA_Q in absolute
 *              value and output coefficients are again bounded by GCRY_MLDSA_Q.
 *
 * Arguments:   - gcry_mldsa_poly *a: pointer to input/output polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_invntt_tomont(gcry_mldsa_poly *a)
{

  _gcry_mldsa_avx2_invntt_avx(a->vec, qdata.vec);
}

void _gcry_mldsa_avx2_poly_nttunpack(byte *a)
{

  _gcry_mldsa_avx2_nttunpack_avx(((gcry_mldsa_poly *)a)->vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_pointwise_montgomery
 *
 * Description: Pointwise multiplication of polynomials in NTT domain
 *              representation and multiplication of resulting polynomial
 *              by 2^{-32}.
 *
 * Arguments:   - gcry_mldsa_poly *c: pointer to output polynomial
 *              - const gcry_mldsa_poly *a: pointer to first input polynomial
 *              - const gcry_mldsa_poly *b: pointer to second input polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_pointwise_montgomery(gcry_mldsa_poly *c, const gcry_mldsa_poly *a, const gcry_mldsa_poly *b)
{

  _gcry_mldsa_avx2_pointwise_avx(c->vec, a->vec, b->vec, qdata.vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_power2round
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute c0, c1 such that c mod^+ GCRY_MLDSA_Q = c1*2^GCRY_MLDSA_D + c0
 *              with -2^{GCRY_MLDSA_D-1} < c0 <= 2^{GCRY_MLDSA_D-1}. Assumes coefficients to be
 *              positive standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *a1: pointer to output polynomial with coefficients c1
 *              - gcry_mldsa_poly *a0: pointer to output polynomial with coefficients c0
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_power2round(gcry_mldsa_poly *a1, gcry_mldsa_poly *a0, const gcry_mldsa_poly *a)
{

  _gcry_mldsa_avx2_power2round_avx(a1->vec, a0->vec, a->vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_decompose
 *
 * Description: For all coefficients c of the input polynomial,
 *              compute high and low bits c0, c1 such c mod^+ GCRY_MLDSA_Q = c1*ALPHA + c0
 *              with -ALPHA/2 < c0 <= ALPHA/2 except if c1 = (GCRY_MLDSA_Q-1)/ALPHA where we
 *              set c1 = 0 and -ALPHA/2 <= c0 = c mod GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0.
 *              Assumes coefficients to be positive standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *a1: pointer to output polynomial with coefficients c1
 *              - gcry_mldsa_poly *a0: pointer to output polynomial with coefficients c0
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_decompose(gcry_mldsa_param_t *params,
                                     gcry_mldsa_poly *a1,
                                     gcry_mldsa_poly *a0,
                                     const gcry_mldsa_poly *a)
{
  _gcry_mldsa_avx2_decompose_avx(params, a1->vec, a0->vec, a->vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_make_hint
 *
 * Description: Compute hint array. The coefficients of which are the
 *              indices of the coefficients of the input polynomial
 *              whose low bits overflow into the high bits.
 *
 * Arguments:   - byte *h: pointer to output hint array (preallocated of length GCRY_MLDSA_N)
 *              - const gcry_mldsa_poly *a0: pointer to low part of input polynomial
 *              - const gcry_mldsa_poly *a1: pointer to high part of input polynomial
 *
 * Returns number of hints, i.e. length of hint array.
 **************************************************/
unsigned int _gcry_mldsa_avx2_poly_make_hint(gcry_mldsa_param_t *params,
                                             byte hint[GCRY_MLDSA_N],
                                             const gcry_mldsa_poly *a0,
                                             const gcry_mldsa_poly *a1)
{
  unsigned int r;

  r = _gcry_mldsa_avx2_make_hint_avx(params, hint, a0->vec, a1->vec);
  return r;
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_use_hint
 *
 * Description: Use hint polynomial to correct the high bits of a polynomial.
 *
 * Arguments:   - gcry_mldsa_poly *b: pointer to output polynomial with corrected high bits
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 *              - const gcry_mldsa_poly *h: pointer to input hint polynomial
 **************************************************/
void _gcry_mldsa_avx2_poly_use_hint(gcry_mldsa_param_t *params,
                                    gcry_mldsa_poly *b,
                                    const gcry_mldsa_poly *a,
                                    const gcry_mldsa_poly *h)
{
  _gcry_mldsa_avx2_use_hint_avx(params, b->vec, a->vec, h->vec);
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_poly_chknorm
 *
 * Description: Check infinity norm of polynomial against given bound.
 *              Assumes input polynomial to be reduced by _gcry_mldsa_avx2_poly_reduce().
 *
 * Arguments:   - const gcry_mldsa_poly *a: pointer to polynomial
 *              - s32 B: norm bound
 *
 * Returns 0 if norm is strictly smaller than B <= (GCRY_MLDSA_Q-1)/8 and 1 otherwise.
 **************************************************/
int _gcry_mldsa_avx2_poly_chknorm(const gcry_mldsa_poly *a, s32 B)
{
  unsigned int i;
  int r;
  __m256i f, t;
  const __m256i bound = _mm256_set1_epi32(B - 1);

  if (B > (GCRY_MLDSA_Q - 1) / 8)
    return 1;

  t = _mm256_setzero_si256();
  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a->vec[i]);
      f = _mm256_abs_epi32(f);
      f = _mm256_cmpgt_epi32(f, bound);
      t = _mm256_or_si256(t, f);
    }

  r = 1 - _mm256_testz_si256(t, t);
  return r;
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
static unsigned int rej_uniform(s32 *a, unsigned int len, const byte *buf, unsigned int buflen)
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

gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_4x(
    byte *a0, byte *a1, byte *a2, byte *a3, const byte seed[32], u16 nonce0, u16 nonce1, u16 nonce2, u16 nonce3)
{
  gcry_err_code_t ec = 0;
  unsigned int ctr0, ctr1, ctr2, ctr3;
  gcry_mldsa_buf_al buf = {};
  size_t offset_al;

  size_t buf_elem_len     = REJ_UNIFORM_BUFLEN + 8;
  gcry_mldsa_buf_al state = {};
  __m256i f;

  /* make sure each sub structure starts memory aligned */
  offset_al = buf_elem_len + (128 - (buf_elem_len % 128));
  ec        = _gcry_mldsa_buf_al_create(&buf, 4 * offset_al);
  if (ec)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  ec = _gcry_mldsa_buf_al_create(&state, sizeof(gcry_mldsa_keccakx4_state));
  if (ec)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256((__m256i *)&buf.buf[0 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[1 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[2 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[3 * offset_al], f);

  buf.buf[0 * offset_al + GCRY_MLDSA_SEEDBYTES + 0] = nonce0;
  buf.buf[0 * offset_al + GCRY_MLDSA_SEEDBYTES + 1] = nonce0 >> 8;
  buf.buf[1 * offset_al + GCRY_MLDSA_SEEDBYTES + 0] = nonce1;
  buf.buf[1 * offset_al + GCRY_MLDSA_SEEDBYTES + 1] = nonce1 >> 8;
  buf.buf[2 * offset_al + GCRY_MLDSA_SEEDBYTES + 0] = nonce2;
  buf.buf[2 * offset_al + GCRY_MLDSA_SEEDBYTES + 1] = nonce2 >> 8;
  buf.buf[3 * offset_al + GCRY_MLDSA_SEEDBYTES + 0] = nonce3;
  buf.buf[3 * offset_al + GCRY_MLDSA_SEEDBYTES + 1] = nonce3 >> 8;

  _gcry_mldsa_avx2_shake128x4_absorb_once((gcry_mldsa_keccakx4_state*)state.buf,
                                          &buf.buf[0 * offset_al],
                                          &buf.buf[1 * offset_al],
                                          &buf.buf[2 * offset_al],
                                          &buf.buf[3 * offset_al],
                                          GCRY_MLDSA_SEEDBYTES + 2);
  _gcry_mldsa_avx2_shake128x4_squeezeblocks(&buf.buf[0 * offset_al],
                                            &buf.buf[1 * offset_al],
                                            &buf.buf[2 * offset_al],
                                            &buf.buf[3 * offset_al],
                                            REJ_UNIFORM_NBLOCKS,
                                            (gcry_mldsa_keccakx4_state*)state.buf);

  ctr0 = _gcry_mldsa_avx2_rej_uniform_avx(((gcry_mldsa_poly *)a0)->coeffs, &buf.buf[0 * offset_al]);
  ctr1 = _gcry_mldsa_avx2_rej_uniform_avx(((gcry_mldsa_poly *)a1)->coeffs, &buf.buf[1 * offset_al]);
  ctr2 = _gcry_mldsa_avx2_rej_uniform_avx(((gcry_mldsa_poly *)a2)->coeffs, &buf.buf[2 * offset_al]);
  ctr3 = _gcry_mldsa_avx2_rej_uniform_avx(((gcry_mldsa_poly *)a3)->coeffs, &buf.buf[3 * offset_al]);

  while (ctr0 < GCRY_MLDSA_N || ctr1 < GCRY_MLDSA_N || ctr2 < GCRY_MLDSA_N || ctr3 < GCRY_MLDSA_N)
    {
      _gcry_mldsa_avx2_shake128x4_squeezeblocks(&buf.buf[0 * offset_al],
                                                &buf.buf[1 * offset_al],
                                                &buf.buf[2 * offset_al],
                                                &buf.buf[3 * offset_al],
                                                1,
                                                (gcry_mldsa_keccakx4_state*)state.buf);

      ctr0 += rej_uniform(
          ((gcry_mldsa_poly *)a0)->coeffs + ctr0, GCRY_MLDSA_N - ctr0, &buf.buf[0 * offset_al], GCRY_SHAKE128_RATE);
      ctr1 += rej_uniform(
          ((gcry_mldsa_poly *)a1)->coeffs + ctr1, GCRY_MLDSA_N - ctr1, &buf.buf[1 * offset_al], GCRY_SHAKE128_RATE);
      ctr2 += rej_uniform(
          ((gcry_mldsa_poly *)a2)->coeffs + ctr2, GCRY_MLDSA_N - ctr2, &buf.buf[2 * offset_al], GCRY_SHAKE128_RATE);
      ctr3 += rej_uniform(
          ((gcry_mldsa_poly *)a3)->coeffs + ctr3, GCRY_MLDSA_N - ctr3, &buf.buf[3 * offset_al], GCRY_SHAKE128_RATE);
    }

leave:
  _gcry_mldsa_buf_al_destroy(&buf);
  _gcry_mldsa_buf_al_destroy(&state);
  return ec;
}

/*************************************************
 * Name:        rej_eta
 *
 * Description: Sample uniformly random coefficients in [-ETA, ETA] by
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
static unsigned int rej_eta2(s32 *a, unsigned int len, const byte *buf, unsigned int buflen)
{
  unsigned int ctr, pos;
  u32 t0, t1;

  ctr = pos = 0;
  while (ctr < len && pos < buflen)
    {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

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
  return ctr;
}
static unsigned int rej_eta4(s32 *a, unsigned int len, const byte *buf, unsigned int buflen)
{
  unsigned int ctr, pos;
  u32 t0, t1;

  ctr = pos = 0;
  while (ctr < len && pos < buflen)
    {
      t0 = buf[pos] & 0x0F;
      t1 = buf[pos++] >> 4;

      if (t0 < 9)
        a[ctr++] = 4 - t0;
      if (t1 < 9 && ctr < len)
        a[ctr++] = 4 - t1;
    }
  return ctr;
}

gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_eta_4x(gcry_mldsa_param_t *params,
                                                     gcry_mldsa_poly *a0,
                                                     gcry_mldsa_poly *a1,
                                                     gcry_mldsa_poly *a2,
                                                     gcry_mldsa_poly *a3,
                                                     const byte seed[64],
                                                     u16 nonce0,
                                                     u16 nonce1,
                                                     u16 nonce2,
                                                     u16 nonce3)
{
  gcry_err_code_t ec = 0;
  unsigned int ctr0, ctr1, ctr2, ctr3;
  size_t REJ_UNIFORM_ETA_BUFLEN;
  size_t offset_al;
  size_t REJ_UNIFORM_ETA_NBLOCKS;
  gcry_mldsa_buf_al buf = {};
  __m256i f;
  gcry_mldsa_buf_al state = {};


  if (params->eta == 2)
    {
      REJ_UNIFORM_ETA_NBLOCKS = (136 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES;
    }
  else
    {
      REJ_UNIFORM_ETA_NBLOCKS = (227 + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES;
    }

  REJ_UNIFORM_ETA_BUFLEN = REJ_UNIFORM_ETA_NBLOCKS * GCRY_STREAM256_BLOCKBYTES;

  /* make sure each sub structure starts memory aligned */
  offset_al = REJ_UNIFORM_ETA_BUFLEN + (128 - (REJ_UNIFORM_ETA_BUFLEN % 128));
  ec        = _gcry_mldsa_buf_al_create(&buf, 4 * offset_al);
  if (ec)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
  ec = _gcry_mldsa_buf_al_create(&state, sizeof(gcry_mldsa_keccakx4_state));
  if (ec)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256((__m256i *)&buf.buf[0 * offset_al + 0 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[1 * offset_al + 0 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[2 * offset_al + 0 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[3 * offset_al + 0 * sizeof(__m256i)], f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256((__m256i *)&buf.buf[0 * offset_al + 1 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[1 * offset_al + 1 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[2 * offset_al + 1 * sizeof(__m256i)], f);
  _mm256_store_si256((__m256i *)&buf.buf[3 * offset_al + 1 * sizeof(__m256i)], f);

  buf.buf[0 * offset_al + 64] = nonce0;
  buf.buf[0 * offset_al + 65] = nonce0 >> 8;
  buf.buf[1 * offset_al + 64] = nonce1;
  buf.buf[1 * offset_al + 65] = nonce1 >> 8;
  buf.buf[2 * offset_al + 64] = nonce2;
  buf.buf[2 * offset_al + 65] = nonce2 >> 8;
  buf.buf[3 * offset_al + 64] = nonce3;
  buf.buf[3 * offset_al + 65] = nonce3 >> 8;

  _gcry_mldsa_avx2_shake256x4_absorb_once((gcry_mldsa_keccakx4_state *)state.buf,
                                          &buf.buf[0 * offset_al],
                                          &buf.buf[1 * offset_al],
                                          &buf.buf[2 * offset_al],
                                          &buf.buf[3 * offset_al],
                                          66);
  _gcry_mldsa_avx2_shake256x4_squeezeblocks(&buf.buf[0 * offset_al],
                                            &buf.buf[1 * offset_al],
                                            &buf.buf[2 * offset_al],
                                            &buf.buf[3 * offset_al],
                                            REJ_UNIFORM_ETA_NBLOCKS,
                                            (gcry_mldsa_keccakx4_state *)state.buf);

  if (params->eta == 2)
    {
      ctr0 = _gcry_mldsa_avx2_rej_eta_avx_eta2(a0->coeffs, &buf.buf[0 * offset_al]);
      ctr1 = _gcry_mldsa_avx2_rej_eta_avx_eta2(a1->coeffs, &buf.buf[1 * offset_al]);
      ctr2 = _gcry_mldsa_avx2_rej_eta_avx_eta2(a2->coeffs, &buf.buf[2 * offset_al]);
      ctr3 = _gcry_mldsa_avx2_rej_eta_avx_eta2(a3->coeffs, &buf.buf[3 * offset_al]);
    }
  else
    {
      ctr0 = _gcry_mldsa_avx2_rej_eta_avx_eta4(a0->coeffs, &buf.buf[0 * offset_al]);
      ctr1 = _gcry_mldsa_avx2_rej_eta_avx_eta4(a1->coeffs, &buf.buf[1 * offset_al]);
      ctr2 = _gcry_mldsa_avx2_rej_eta_avx_eta4(a2->coeffs, &buf.buf[2 * offset_al]);
      ctr3 = _gcry_mldsa_avx2_rej_eta_avx_eta4(a3->coeffs, &buf.buf[3 * offset_al]);
    }

  while (ctr0 < GCRY_MLDSA_N || ctr1 < GCRY_MLDSA_N || ctr2 < GCRY_MLDSA_N || ctr3 < GCRY_MLDSA_N)
    {
      _gcry_mldsa_avx2_shake256x4_squeezeblocks(&buf.buf[0 * offset_al],
                                                &buf.buf[1 * offset_al],
                                                &buf.buf[2 * offset_al],
                                                &buf.buf[3 * offset_al],
                                                1,
                                                (gcry_mldsa_keccakx4_state *)state.buf);
      if (params->eta == 2)
        {
          ctr0 += rej_eta2(a0->coeffs + ctr0, GCRY_MLDSA_N - ctr0, &buf.buf[0 * offset_al], GCRY_SHAKE256_RATE);
          ctr1 += rej_eta2(a1->coeffs + ctr1, GCRY_MLDSA_N - ctr1, &buf.buf[1 * offset_al], GCRY_SHAKE256_RATE);
          ctr2 += rej_eta2(a2->coeffs + ctr2, GCRY_MLDSA_N - ctr2, &buf.buf[2 * offset_al], GCRY_SHAKE256_RATE);
          ctr3 += rej_eta2(a3->coeffs + ctr3, GCRY_MLDSA_N - ctr3, &buf.buf[3 * offset_al], GCRY_SHAKE256_RATE);
        }
      else
        {
          ctr0 += rej_eta4(a0->coeffs + ctr0, GCRY_MLDSA_N - ctr0, &buf.buf[0 * offset_al], GCRY_SHAKE256_RATE);
          ctr1 += rej_eta4(a1->coeffs + ctr1, GCRY_MLDSA_N - ctr1, &buf.buf[1 * offset_al], GCRY_SHAKE256_RATE);
          ctr2 += rej_eta4(a2->coeffs + ctr2, GCRY_MLDSA_N - ctr2, &buf.buf[2 * offset_al], GCRY_SHAKE256_RATE);
          ctr3 += rej_eta4(a3->coeffs + ctr3, GCRY_MLDSA_N - ctr3, &buf.buf[3 * offset_al], GCRY_SHAKE256_RATE);
        }
    }

leave:
  _gcry_mldsa_buf_al_destroy(&buf);
  _gcry_mldsa_buf_al_destroy(&state);
  return ec;
}


gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_gamma1(gcry_mldsa_param_t *params,
                                                     gcry_mldsa_poly *a,
                                                     const byte seed[GCRY_MLDSA_CRHBYTES],
                                                     u16 nonce)
{
  gcry_err_code_t ec = 0;
  gcry_md_hd_t md    = NULL;

  const size_t POLY_UNIFORM_GAMMA1_NBLOCKS
      = (params->polyz_packedbytes + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES;

  gcry_mldsa_buf_al buf = {};
  /* _gcry_mldsa_avx2_polyz_unpack reads 14 additional bytes */
  _gcry_mldsa_buf_al_create(&buf, POLY_UNIFORM_GAMMA1_NBLOCKS * GCRY_STREAM256_BLOCKBYTES + 14);

  ec = _gcry_mldsa_shake256_stream_init(&md, seed, nonce);
  if (ec)
    goto leave;
  ec = _gcry_mldsa_shake256_squeeze_nblocks(md, POLY_UNIFORM_GAMMA1_NBLOCKS, buf.buf);
  if (ec)
    goto leave;

  _gcry_mldsa_avx2_polyz_unpack(params, a, buf.buf);

leave:
  _gcry_md_close(md);
  _gcry_mldsa_buf_al_destroy(&buf);
  return ec;
}

gcry_err_code_t _gcry_mldsa_avx2_poly_uniform_gamma1_4x(gcry_mldsa_param_t *params,
                                                        byte *a0,
                                                        byte *a1,
                                                        byte *a2,
                                                        byte *a3,
                                                        const byte seed[64],
                                                        u16 nonce0,
                                                        u16 nonce1,
                                                        u16 nonce2,
                                                        u16 nonce3)
{
  gcry_err_code_t ec = 0;
  const size_t POLY_UNIFORM_GAMMA1_NBLOCKS
      = (params->polyz_packedbytes + GCRY_STREAM256_BLOCKBYTES - 1) / GCRY_STREAM256_BLOCKBYTES;
  size_t buf_elem_len   = POLY_UNIFORM_GAMMA1_NBLOCKS * GCRY_STREAM256_BLOCKBYTES + 14;
  gcry_mldsa_buf_al buf = {};
  size_t offset_al;

  gcry_mldsa_buf_al state = {};
  __m256i f;

  /* make sure each sub structure starts memory aligned */
  offset_al = buf_elem_len + (128 - (buf_elem_len % 128));
  ec        = _gcry_mldsa_buf_al_create(&buf, 4 * offset_al);
  if (ec)
    {
      ec = gpg_err_code_from_syserror();
      goto leave;
    }
    ec = _gcry_mldsa_buf_al_create(&state, sizeof(gcry_mldsa_keccakx4_state));
if (ec)
{
  ec = gpg_err_code_from_syserror();
  goto leave;
}

  f = _mm256_loadu_si256((__m256i *)&seed[0]);
  _mm256_store_si256((__m256i *)&buf.buf[0 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[1 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[2 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[3 * offset_al], f);
  f = _mm256_loadu_si256((__m256i *)&seed[32]);
  _mm256_store_si256((__m256i *)&buf.buf[0 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[1 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[2 * offset_al], f);
  _mm256_store_si256((__m256i *)&buf.buf[3 * offset_al], f);

  buf.buf[0 * offset_al + 64] = nonce0;
  buf.buf[0 * offset_al + 65] = nonce0 >> 8;
  buf.buf[1 * offset_al + 64] = nonce1;
  buf.buf[1 * offset_al + 65] = nonce1 >> 8;
  buf.buf[2 * offset_al + 64] = nonce2;
  buf.buf[2 * offset_al + 65] = nonce2 >> 8;
  buf.buf[3 * offset_al + 64] = nonce3;
  buf.buf[3 * offset_al + 65] = nonce3 >> 8;

  _gcry_mldsa_avx2_shake256x4_absorb_once(
      (gcry_mldsa_keccakx4_state*)state.buf	, &buf.buf[0 * offset_al], &buf.buf[1 * offset_al], &buf.buf[2 * offset_al], &buf.buf[3 * offset_al], 66);
  _gcry_mldsa_avx2_shake256x4_squeezeblocks(&buf.buf[0 * offset_al],
                                            &buf.buf[1 * offset_al],
                                            &buf.buf[2 * offset_al],
                                            &buf.buf[3 * offset_al],
                                            POLY_UNIFORM_GAMMA1_NBLOCKS,
                                            (gcry_mldsa_keccakx4_state*)state.buf	);

  _gcry_mldsa_avx2_polyz_unpack(params, (gcry_mldsa_poly *)a0, &buf.buf[0 * offset_al]);
  _gcry_mldsa_avx2_polyz_unpack(params, (gcry_mldsa_poly *)a1, &buf.buf[1 * offset_al]);
  _gcry_mldsa_avx2_polyz_unpack(params, (gcry_mldsa_poly *)a2, &buf.buf[2 * offset_al]);
  _gcry_mldsa_avx2_polyz_unpack(params, (gcry_mldsa_poly *)a3, &buf.buf[3 * offset_al]);

leave:
  _gcry_mldsa_buf_al_destroy(&buf);
  _gcry_mldsa_buf_al_destroy(&state);
  return ec;
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_polyeta_pack
 *
 * Description: Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            POLYETA_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyeta_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *restrict a)
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
  else
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
 * Name:        _gcry_mldsa_avx2_polyeta_unpack
 *
 * Description: Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyeta_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *restrict r, const byte *a)
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
  else
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
 * Name:        _gcry_mldsa_avx2_polyt1_pack
 *
 * Description: Bit-pack polynomial t1 with coefficients fitting in 10 bits.
 *              Input coefficients are assumed to be positive standard representatives.
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            GCRY_MLDSA_POLYT1_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyt1_pack(byte r[GCRY_MLDSA_POLYT1_PACKEDBYTES], const gcry_mldsa_poly *restrict a)
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
 * Name:        _gcry_mldsa_avx2_polyt1_unpack
 *
 * Description: Unpack polynomial t1 with 10-bit coefficients.
 *              Output coefficients are positive standard representatives.
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyt1_unpack(gcry_mldsa_poly *restrict r, const byte a[GCRY_MLDSA_POLYT1_PACKEDBYTES])
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
 * Name:        _gcry_mldsa_avx2_polyt0_pack
 *
 * Description: Bit-pack polynomial t0 with coefficients in ]-2^{GCRY_MLDSA_D-1}, 2^{GCRY_MLDSA_D-1}].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            GCRY_MLDSA_POLYT0_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyt0_pack(byte r[GCRY_MLDSA_POLYT0_PACKEDBYTES], const gcry_mldsa_poly *restrict a)
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
 * Name:        _gcry_mldsa_avx2_polyt0_unpack
 *
 * Description: Unpack polynomial t0 with coefficients in ]-2^{GCRY_MLDSA_D-1}, 2^{GCRY_MLDSA_D-1}].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyt0_unpack(gcry_mldsa_poly *restrict r, const byte a[GCRY_MLDSA_POLYT0_PACKEDBYTES])
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
 * Name:        _gcry_mldsa_avx2_polyz_pack
 *
 * Description: Bit-pack polynomial with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            POLYZ_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyz_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *restrict a)
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
  else
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

static void polyz_unpack_17(gcry_mldsa_poly *restrict r, const byte *a)
{
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(
      -1, 9, 8, 7, -1, 7, 6, 5, -1, 5, 4, 3, -1, 3, 2, 1, -1, 8, 7, 6, -1, 6, 5, 4, -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set_epi32(6, 4, 2, 0, 6, 4, 2, 0);
  const __m256i mask     = _mm256_set1_epi32(0x3FFFF);
  const __m256i gamma1   = _mm256_set1_epi32(1 << 17);

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_loadu_si256((__m256i *)&a[18 * i]);
      f = _mm256_permute4x64_epi64(f, 0x94);
      f = _mm256_shuffle_epi8(f, shufbidx);
      f = _mm256_srlv_epi32(f, srlvdidx);
      f = _mm256_and_si256(f, mask);
      f = _mm256_sub_epi32(gamma1, f);
      _mm256_store_si256(&r->vec[i], f);
    }
}

static void polyz_unpack_19(gcry_mldsa_poly *restrict r, const byte *a)
{
  unsigned int i;
  __m256i f;
  const __m256i shufbidx = _mm256_set_epi8(
      -1, 11, 10, 9, -1, 9, 8, 7, -1, 6, 5, 4, -1, 4, 3, 2, -1, 9, 8, 7, -1, 7, 6, 5, -1, 4, 3, 2, -1, 2, 1, 0);
  const __m256i srlvdidx = _mm256_set1_epi64x((u64)4 << 32);
  const __m256i mask     = _mm256_set1_epi32(0xFFFFF);
  const __m256i gamma1   = _mm256_set1_epi32(1 << 19);

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_loadu_si256((__m256i *)&a[20 * i]);
      f = _mm256_permute4x64_epi64(f, 0x94);
      f = _mm256_shuffle_epi8(f, shufbidx);
      f = _mm256_srlv_epi32(f, srlvdidx);
      f = _mm256_and_si256(f, mask);
      f = _mm256_sub_epi32(gamma1, f);
      _mm256_store_si256(&r->vec[i], f);
    }
}

/*************************************************
 * Name:        _gcry_mldsa_avx2_polyz_unpack
 *
 * Description: Unpack polynomial z with coefficients
 *              in [-(GAMMA1 - 1), GAMMA1].
 *
 * Arguments:   - gcry_mldsa_poly *r: pointer to output polynomial
 *              - const byte *a: byte array with bit-packed polynomial
 **************************************************/

void _gcry_mldsa_avx2_polyz_unpack(gcry_mldsa_param_t *params, gcry_mldsa_poly *restrict r, const byte *a)
{
  if (params->gamma1 == (1 << 17))
    {
      polyz_unpack_17(r, a);
    }
  else
    {
      polyz_unpack_19(r, a);
    }
}


static void polyw1_pack_88(byte *r, const gcry_mldsa_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3;
  const __m256i shift1    = _mm256_set1_epi16((64 << 8) + 1);
  const __m256i shift2    = _mm256_set1_epi32((4096 << 16) + 1);
  const __m256i shufdidx1 = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
  const __m256i shufdidx2 = _mm256_set_epi32(-1, -1, 6, 5, 4, 2, 1, 0);
  const __m256i shufbidx  = _mm256_set_epi8(
      -1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0, -1, -1, -1, -1, 14, 13, 12, 10, 9, 8, 6, 5, 4, 2, 1, 0);

  for (i = 0; i < GCRY_MLDSA_N / 32; i++)
    {
      f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
      f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
      f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
      f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
      f0 = _mm256_packus_epi32(f0, f1);
      f1 = _mm256_packus_epi32(f2, f3);
      f0 = _mm256_packus_epi16(f0, f1);
      f0 = _mm256_maddubs_epi16(f0, shift1);
      f0 = _mm256_madd_epi16(f0, shift2);
      f0 = _mm256_permutevar8x32_epi32(f0, shufdidx1);
      f0 = _mm256_shuffle_epi8(f0, shufbidx);
      f0 = _mm256_permutevar8x32_epi32(f0, shufdidx2);
      _mm256_storeu_si256((__m256i *)&r[24 * i], f0);
    }
}

static void polyw1_pack_32(byte *r, const gcry_mldsa_poly *restrict a)
{
  unsigned int i;
  __m256i f0, f1, f2, f3, f4, f5, f6, f7;
  const __m256i shift    = _mm256_set1_epi16((16 << 8) + 1);
  const __m256i shufbidx = _mm256_set_epi8(
      15, 14, 7, 6, 13, 12, 5, 4, 11, 10, 3, 2, 9, 8, 1, 0, 15, 14, 7, 6, 13, 12, 5, 4, 11, 10, 3, 2, 9, 8, 1, 0);

  for (i = 0; i < GCRY_MLDSA_N / 64; ++i)
    {
      f0 = _mm256_load_si256(&a->vec[8 * i + 0]);
      f1 = _mm256_load_si256(&a->vec[8 * i + 1]);
      f2 = _mm256_load_si256(&a->vec[8 * i + 2]);
      f3 = _mm256_load_si256(&a->vec[8 * i + 3]);
      f4 = _mm256_load_si256(&a->vec[8 * i + 4]);
      f5 = _mm256_load_si256(&a->vec[8 * i + 5]);
      f6 = _mm256_load_si256(&a->vec[8 * i + 6]);
      f7 = _mm256_load_si256(&a->vec[8 * i + 7]);
      f0 = _mm256_packus_epi32(f0, f1);
      f1 = _mm256_packus_epi32(f2, f3);
      f2 = _mm256_packus_epi32(f4, f5);
      f3 = _mm256_packus_epi32(f6, f7);
      f0 = _mm256_packus_epi16(f0, f1);
      f1 = _mm256_packus_epi16(f2, f3);
      f0 = _mm256_maddubs_epi16(f0, shift);
      f1 = _mm256_maddubs_epi16(f1, shift);
      f0 = _mm256_packus_epi16(f0, f1);
      f0 = _mm256_permute4x64_epi64(f0, 0xD8);
      f0 = _mm256_shuffle_epi8(f0, shufbidx);
      _mm256_storeu_si256((__m256i *)&r[32 * i], f0);
    }
}


/*************************************************
 * Name:        _gcry_mldsa_avx2_polyw1_pack
 *
 * Description: Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
 *              Input coefficients are assumed to be positive standard representatives.
 *
 * Arguments:   - byte *r: pointer to output byte array with at least
 *                            POLYW1_PACKEDBYTES bytes
 *              - const gcry_mldsa_poly *a: pointer to input polynomial
 **************************************************/
void _gcry_mldsa_avx2_polyw1_pack(gcry_mldsa_param_t *params, byte *r, const gcry_mldsa_poly *restrict a)
{
  if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 88)
    {
      polyw1_pack_88(r, a);
    }
  else
    {
      polyw1_pack_32(r, a);
    }
}


/*************************************************
 * Name:        _gcry_mldsa_avx2_unpack_sk
 *
 * Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * Arguments:   - const byte rho[]: output byte array for rho
 *              - const byte tr[]: output byte array for tr
 *              - const byte key[]: output byte array for key
 *              - const polyveck *t0: pointer to output vector t0
 *              - const polyvecl *s1: pointer to output vector s1
 *              - const polyveck *s2: pointer to output vector s2
 *              - byte sk[]: byte array containing bit-packed sk
 **************************************************/
void _gcry_mldsa_avx2_unpack_sk(gcry_mldsa_param_t *params,
                                byte rho[GCRY_MLDSA_SEEDBYTES],
                                byte tr[GCRY_MLDSA_TRBYTES],
                                byte key[GCRY_MLDSA_SEEDBYTES],
                                byte *t0,
                                byte *s1,
                                byte *s2,
                                const byte *sk)
{
  unsigned int i;

  for (i = 0; i < GCRY_MLDSA_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += GCRY_MLDSA_SEEDBYTES;

  for (i = 0; i < GCRY_MLDSA_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += GCRY_MLDSA_SEEDBYTES;

  for (i = 0; i < GCRY_MLDSA_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += GCRY_MLDSA_TRBYTES;

  for (i = 0; i < params->l; ++i)
    _gcry_mldsa_avx2_polyeta_unpack(
        params, (gcry_mldsa_poly *)&s1[i * sizeof(gcry_mldsa_poly)], sk + i * params->polyeta_packedbytes);
  sk += params->l * params->polyeta_packedbytes;

  for (i = 0; i < params->k; ++i)
    _gcry_mldsa_avx2_polyeta_unpack(
        params, (gcry_mldsa_poly *)&s2[i * sizeof(gcry_mldsa_poly)], sk + i * params->polyeta_packedbytes);
  sk += params->k * params->polyeta_packedbytes;

  for (i = 0; i < params->k; ++i)
    _gcry_mldsa_avx2_polyt0_unpack((gcry_mldsa_poly *)&t0[i * sizeof(gcry_mldsa_poly)],
                                   sk + i * GCRY_MLDSA_POLYT0_PACKEDBYTES);
}
#endif
