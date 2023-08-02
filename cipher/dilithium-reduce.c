#include <config.h>
#include <stdint.h>
#include "dilithium-params.h"
#include "dilithium-reduce.h"

/*************************************************
* Name:        _gcry_dilithium_montgomery_reduce
*
* Description: For finite field element a with -2^{31}GCRY_DILITHIUM_Q <= a <= GCRY_DILITHIUM_Q*2^31,
*              compute r \equiv a*2^{-32} (mod GCRY_DILITHIUM_Q) such that -GCRY_DILITHIUM_Q < r < GCRY_DILITHIUM_Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_dilithium_montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int64_t)(int32_t)a*GCRY_DILITHIUM_QINV;
  t = (a - (int64_t)t*GCRY_DILITHIUM_Q) >> 32;
  return t;
}

/*************************************************
* Name:        _gcry_dilithium_reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod GCRY_DILITHIUM_Q) such that -6283009 <= r <= 6283007.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_dilithium_reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*GCRY_DILITHIUM_Q;
  return t;
}

/*************************************************
* Name:        _gcry_dilithium_caddq
*
* Description: Add GCRY_DILITHIUM_Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_dilithium_caddq(int32_t a) {
  a += (a >> 31) & GCRY_DILITHIUM_Q;
  return a;
}

/*************************************************
* Name:        _gcry_dilithium_freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ GCRY_DILITHIUM_Q.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_dilithium_freeze(int32_t a) {
  a = _gcry_dilithium_reduce32(a);
  a = _gcry_dilithium_caddq(a);
  return a;
}