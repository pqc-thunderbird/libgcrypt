#include <config.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-rounding.h"

/*************************************************
 * Name:        _gcry_mldsa_power2round
 *
 * Description: For finite field element a, compute a0, a1 such that
 *              a mod^+ GCRY_MLDSA_Q = a1*2^GCRY_MLDSA_D + a0 with -2^{GCRY_MLDSA_D-1} < a0 <= 2^{GCRY_MLDSA_D-1}.
 *              Assumes a to be standard representative.
 *
 * Arguments:   - s32 a: input element
 *              - s32 *a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
s32 _gcry_mldsa_power2round (s32 *a0, s32 a)
{
  s32 a1;

  a1  = (a + (1 << (GCRY_MLDSA_D - 1)) - 1) >> GCRY_MLDSA_D;
  *a0 = a - (a1 << GCRY_MLDSA_D);
  return a1;
}

/*************************************************
 * Name:        _gcry_mldsa_decompose
 *
 * Description: For finite field element a, compute high and low bits a0, a1 such
 *              that a mod^+ GCRY_MLDSA_Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
 *              if a1 = (GCRY_MLDSA_Q-1)/ALPHA where we set a1 = 0 and
 *              -ALPHA/2 <= a0 = a mod^+ GCRY_MLDSA_Q - GCRY_MLDSA_Q < 0. Assumes a to be standard
 *              representative.
 *
 * Arguments:   - s32 a: input element
 *              - s32 *a0: pointer to output element a0
 *
 * Returns a1.
 **************************************************/
s32 _gcry_mldsa_decompose (gcry_mldsa_param_t *params, s32 *a0, s32 a)
{
  s32 a1;

  a1 = (a + 127) >> 7;
  if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 32)
    {
      a1 = (a1 * 1025 + (1 << 21)) >> 22;
      a1 &= 15;
    }
  else if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 88)
    {
      a1 = (a1 * 11275 + (1 << 23)) >> 24;
      a1 ^= ((43 - a1) >> 31) & a1;
    }

  *a0 = a - a1 * 2 * params->gamma2;
  *a0 -= (((GCRY_MLDSA_Q - 1) / 2 - *a0) >> 31) & GCRY_MLDSA_Q;
  return a1;
}

/*************************************************
 * Name:        _gcry_mldsa_make_hint
 *
 * Description: Compute hint bit indicating whether the low bits of the
 *              input element overflow into the high bits.
 *
 * Arguments:   - s32 a0: low bits of input element
 *              - s32 a1: high bits of input element
 *
 * Returns 1 if overflow.
 **************************************************/
unsigned int _gcry_mldsa_make_hint (gcry_mldsa_param_t *params, s32 a0, s32 a1)
{
  if (a0 > params->gamma2 || a0 < -params->gamma2 || (a0 == -params->gamma2 && a1 != 0))
    return 1;

  return 0;
}

/*************************************************
 * Name:        _gcry_mldsa_use_hint
 *
 * Description: Correct high bits according to hint.
 *
 * Arguments:   - s32 a: input element
 *              - unsigned int hint: hint bit
 *
 * Returns corrected high bits.
 **************************************************/
s32 _gcry_mldsa_use_hint (gcry_mldsa_param_t *params, s32 a, unsigned int hint)
{
  s32 a0, a1;

  a1 = _gcry_mldsa_decompose (params, &a0, a);
  if (hint == 0)
    return a1;

  if (params->gamma2 == (GCRY_MLDSA_Q - 1) / 32)
    {
      if (a0 > 0)
        {
          return (a1 + 1) & 15;
        }
      else
        {
          return (a1 - 1) & 15;
        }
    }
  else
    {
      if (a0 > 0)
        {
          return (a1 == 43) ? 0 : a1 + 1;
        }
      else
        {
          return (a1 == 0) ? 43 : a1 - 1;
        }
    }
}
