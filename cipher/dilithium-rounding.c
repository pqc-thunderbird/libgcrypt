#include <config.h>
#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-rounding.h"

/*************************************************
* Name:        _gcry_dilithium_power2round
*
* Description: For finite field element a, compute a0, a1 such that
*              a mod^+ GCRY_DILITHIUM_Q = a1*2^GCRY_DILITHIUM_D + a0 with -2^{GCRY_DILITHIUM_D-1} < a0 <= 2^{GCRY_DILITHIUM_D-1}.
*              Assumes a to be standard representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t _gcry_dilithium_power2round(int32_t *a0, int32_t a)  {
  int32_t a1;

  a1 = (a + (1 << (GCRY_DILITHIUM_D-1)) - 1) >> GCRY_DILITHIUM_D;
  *a0 = a - (a1 << GCRY_DILITHIUM_D);
  return a1;
}

/*************************************************
* Name:        _gcry_dilithium_decompose
*
* Description: For finite field element a, compute high and low bits a0, a1 such
*              that a mod^+ GCRY_DILITHIUM_Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except
*              if a1 = (GCRY_DILITHIUM_Q-1)/ALPHA where we set a1 = 0 and
*              -ALPHA/2 <= a0 = a mod^+ GCRY_DILITHIUM_Q - GCRY_DILITHIUM_Q < 0. Assumes a to be standard
*              representative.
*
* Arguments:   - int32_t a: input element
*              - int32_t *a0: pointer to output element a0
*
* Returns a1.
**************************************************/
int32_t _gcry_dilithium_decompose(gcry_dilithium_param_t *params, int32_t *a0, int32_t a) {
  int32_t a1;

  a1  = (a + 127) >> 7;
  if(params->gamma2 == (GCRY_DILITHIUM_Q-1)/32) {
    a1  = (a1*1025 + (1 << 21)) >> 22;
    a1 &= 15;
  }
  else if(params->gamma2 == (GCRY_DILITHIUM_Q-1)/88) {
    a1  = (a1*11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
  }

  *a0  = a - a1*2*params->gamma2;
  *a0 -= (((GCRY_DILITHIUM_Q-1)/2 - *a0) >> 31) & GCRY_DILITHIUM_Q;
  return a1;
}

/*************************************************
* Name:        _gcry_dilithium_make_hint
*
* Description: Compute hint bit indicating whether the low bits of the
*              input element overflow into the high bits.
*
* Arguments:   - int32_t a0: low bits of input element
*              - int32_t a1: high bits of input element
*
* Returns 1 if overflow.
**************************************************/
unsigned int _gcry_dilithium_make_hint(gcry_dilithium_param_t *params, int32_t a0, int32_t a1) {
  if(a0 > params->gamma2 || a0 < -params->gamma2 || (a0 == -params->gamma2 && a1 != 0))
    return 1;

  return 0;
}

/*************************************************
* Name:        _gcry_dilithium_use_hint
*
* Description: Correct high bits according to hint.
*
* Arguments:   - int32_t a: input element
*              - unsigned int hint: hint bit
*
* Returns corrected high bits.
**************************************************/
int32_t _gcry_dilithium_use_hint(gcry_dilithium_param_t *params, int32_t a, unsigned int hint) {
  int32_t a0, a1;

  a1 = _gcry_dilithium_decompose(params, &a0, a);
  if(hint == 0)
    return a1;

  if(params->gamma2 == (GCRY_DILITHIUM_Q-1)/32)
  {
    if(a0 > 0) {
      return (a1 + 1) & 15;
    }
    else {
      return (a1 - 1) & 15;
    }
  }
  else if(params->gamma2 == (GCRY_DILITHIUM_Q-1)/88) {
    if(a0 > 0) {
      return (a1 == 43) ?  0 : a1 + 1;
    }
    else {
      return (a1 ==  0) ? 43 : a1 - 1;
    }
  }
}
