#include "mldsa-rounding-avx2.h"
#ifdef USE_AVX2
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "config.h"
#include "mldsa-rejsample-avx2.h"
#include "mldsa-consts-avx2.h"

#define _mm256_blendv_epi32(a, b, mask)                                                                                \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), _mm256_castsi256_ps(b), _mm256_castsi256_ps(mask)))

/*************************************************
 * Name:        power2round
 *
 * Description: For finite field elements a, compute a0, a1 such that
 *              a mod^+ GCRY_MLDSA_Q = a1*2^GCRY_MLDSA_D + a0 with -2^{GCRY_MLDSA_D-1} < a0 <= 2^{GCRY_MLDSA_D-1}.
 *              Assumes a to be positive standard representative.
 *
 * Arguments:   - __m256i *a1: output array of length GCRY_MLDSA_N/8 with high bits
 *              - __m256i *a0: output array of length GCRY_MLDSA_N/8 with low bits a0
 *              - const __m256i *a: input array of length GCRY_MLDSA_N/8
 *
 **************************************************/
void _gcry_mldsa_avx2_power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a)
{
  unsigned int i;
  __m256i f, f0, f1;
  const __m256i mask = _mm256_set1_epi32(-(1 << GCRY_MLDSA_D));
  const __m256i half = _mm256_set1_epi32((1 << (GCRY_MLDSA_D - 1)) - 1);

  for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
    {
      f  = _mm256_load_si256(&a[i]);
      f1 = _mm256_add_epi32(f, half);
      f0 = _mm256_and_si256(f1, mask);
      f1 = _mm256_srli_epi32(f1, GCRY_MLDSA_D);
      f0 = _mm256_sub_epi32(f, f0);
      _mm256_store_si256(&a1[i], f1);
      _mm256_store_si256(&a0[i], f0);
    }
}


static void decompose_avx_32(__m256i *a1, __m256i *a0, const __m256i *a)
{
  const size_t gamma2 = (GCRY_MLDSA_Q - 1) / 32;
  unsigned int i;
  __m256i f, f0, f1;
  const __m256i q     = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
  const __m256i hq    = _mm256_srli_epi32(q, 1);
  const __m256i v     = _mm256_set1_epi32(1025);
  const __m256i alpha = _mm256_set1_epi32(2 * gamma2);
  const __m256i off   = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(512);
  const __m256i mask  = _mm256_set1_epi32(15);

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f  = _mm256_load_si256(&a[i]);
      f1 = _mm256_add_epi32(f, off);
      f1 = _mm256_srli_epi32(f1, 7);
      f1 = _mm256_mulhi_epu16(f1, v);
      f1 = _mm256_mulhrs_epi16(f1, shift);
      f1 = _mm256_and_si256(f1, mask);
      f0 = _mm256_mullo_epi32(f1, alpha);
      f0 = _mm256_sub_epi32(f, f0);
      f  = _mm256_cmpgt_epi32(f0, hq);
      f  = _mm256_and_si256(f, q);
      f0 = _mm256_sub_epi32(f0, f);
      _mm256_store_si256(&a1[i], f1);
      _mm256_store_si256(&a0[i], f0);
    }
}

static void decompose_avx_88(__m256i *a1, __m256i *a0, const __m256i *a)
{
  const size_t gamma2 = (GCRY_MLDSA_Q - 1) / 88;
  unsigned int i;
  __m256i f, f0, f1, t;
  const __m256i q     = _mm256_load_si256(&qdata.vec[_8XQ / 8]);
  const __m256i hq    = _mm256_srli_epi32(q, 1);
  const __m256i v     = _mm256_set1_epi32(11275);
  const __m256i alpha = _mm256_set1_epi32(2 * gamma2);
  const __m256i off   = _mm256_set1_epi32(127);
  const __m256i shift = _mm256_set1_epi32(128);
  const __m256i max   = _mm256_set1_epi32(43);
  const __m256i zero  = _mm256_setzero_si256();

  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f  = _mm256_load_si256(&a[i]);
      f1 = _mm256_add_epi32(f, off);
      f1 = _mm256_srli_epi32(f1, 7);
      f1 = _mm256_mulhi_epu16(f1, v);
      f1 = _mm256_mulhrs_epi16(f1, shift);
      t  = _mm256_sub_epi32(max, f1);
      f1 = _mm256_blendv_epi32(f1, zero, t);
      f0 = _mm256_mullo_epi32(f1, alpha);
      f0 = _mm256_sub_epi32(f, f0);
      f  = _mm256_cmpgt_epi32(f0, hq);
      f  = _mm256_and_si256(f, q);
      f0 = _mm256_sub_epi32(f0, f);
      _mm256_store_si256(&a1[i], f1);
      _mm256_store_si256(&a0[i], f0);
    }
}

/*************************************************
 * Name:        decompose
 *
 * Description: For finite field element a, compute high and low parts a0, a1 such
 *              that a mod^+ GCRY_MLDSA_Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
 *              if a1 = (GCRY_MLDSA_Q-1)/ALPHA where we set a1 = 0 and
 *              -ALPHA/2 <= a0 = a mod GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0. Assumes a to be positive standard
 *              representative.
 *
 * Arguments:   - __m256i *a1: output array of length GCRY_MLDSA_N/8 with high parts
 *              - __m256i *a0: output array of length GCRY_MLDSA_N/8 with low parts a0
 *              - const __m256i *a: input array of length GCRY_MLDSA_N/8
 *
 **************************************************/
void _gcry_mldsa_avx2_decompose_avx(gcry_mldsa_param_t *params, __m256i *a1, __m256i *a0, const __m256i *a)
{
  if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 32)
    {
      decompose_avx_32(a1, a0, a);
    }
  else
    {
      decompose_avx_88(a1, a0, a);
    }
}

/*************************************************
 * Name:        make_hint
 *
 * Description: Compute indices of polynomial coefficients whose low bits
 *              overflow into the high bits.
 *
 * Arguments:   - byte *hint: hint array
 *              - const __m256i *a0: low bits of input elements
 *              - const __m256i *a1: high bits of input elements
 *
 * Returns number of overflowing low bits
 **************************************************/
unsigned int _gcry_mldsa_avx2_make_hint_avx(gcry_mldsa_param_t *params,
                                            byte hint[GCRY_MLDSA_N],
                                            const __m256i *restrict a0,
                                            const __m256i *restrict a1)
{
  unsigned int i, n = 0;
  __m256i f0, f1, g0, g1;
  u32 bad;
  u64 idx;
  const __m256i low  = _mm256_set1_epi32(-params->gamma2);
  const __m256i high = _mm256_set1_epi32(params->gamma2);

  for (i = 0; i < GCRY_MLDSA_N / 8; ++i)
    {
      f0 = _mm256_load_si256(&a0[i]);
      f1 = _mm256_load_si256(&a1[i]);
      g0 = _mm256_abs_epi32(f0);
      g0 = _mm256_cmpgt_epi32(g0, high);
      g1 = _mm256_cmpeq_epi32(f0, low);
      g1 = _mm256_sign_epi32(g1, f1);
      g0 = _mm256_or_si256(g0, g1);

      bad = _mm256_movemask_ps((__m256)g0);
      memcpy(&idx, _gcry_mldsa_avx2_idxlut[bad], 8);
      idx += (u64)0x0808080808080808 * i;
      memcpy(&hint[n], &idx, 8);
      n += _mm_popcnt_u32(bad);
    }

  return n;
}

/*************************************************
 * Name:        use_hint
 *
 * Description: Correct high parts according to hint.
 *
 * Arguments:   - __m256i *b: output array of length GCRY_MLDSA_N/8 with corrected high parts
 *              - const __m256i *a: input array of length GCRY_MLDSA_N/8
 *              - const __m256i *a: input array of length GCRY_MLDSA_N/8 with hint bits
 *
 **************************************************/
void _gcry_mldsa_avx2_use_hint_avx(gcry_mldsa_param_t *params,
                                   __m256i *b,
                                   const __m256i *a,
                                   const __m256i *restrict hint)
{
  unsigned int i;
  __m256i a0[GCRY_MLDSA_N / 8];
  __m256i f, g, h, t;
  const __m256i zero = _mm256_setzero_si256();
  __m256i mask       = _mm256_set1_epi32(15);
  __m256i max        = _mm256_set1_epi32(43);

  _gcry_mldsa_avx2_decompose_avx(params, b, a0, a);
  for (i = 0; i < GCRY_MLDSA_N / 8; i++)
    {
      f = _mm256_load_si256(&a0[i]);
      g = _mm256_load_si256(&b[i]);
      h = _mm256_load_si256(&hint[i]);
      t = _mm256_blendv_epi32(zero, h, f);
      t = _mm256_slli_epi32(t, 1);
      h = _mm256_sub_epi32(h, t);
      g = _mm256_add_epi32(g, h);
      if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 32)
        {
          g = _mm256_and_si256(g, mask);
        }
      else
        {
          g = _mm256_blendv_epi32(g, max, g);
          f = _mm256_cmpgt_epi32(g, max);
          g = _mm256_blendv_epi32(g, zero, f);
        }
      _mm256_store_si256(&b[i], g);
    }
}
#endif