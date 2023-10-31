#include <config.h>
#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-reduce.h"

/*************************************************
* Name:        _gcry_mldsa_montgomery_reduce
*
* Description: For finite field element a with -2^{31}GCRY_MLDSA_Q <= a <= GCRY_MLDSA_Q*2^31,
*              compute r \equiv a*2^{-32} (mod GCRY_MLDSA_Q) such that -GCRY_MLDSA_Q < r < GCRY_MLDSA_Q.
*
* Arguments:   - int64_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_mldsa_montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int64_t)(int32_t)a*GCRY_MLDSA_QINV;
  t = (a - (int64_t)t*GCRY_MLDSA_Q) >> 32;
  return t;
}

/*************************************************
* Name:        _gcry_mldsa_reduce32
*
* Description: For finite field element a with a <= 2^{31} - 2^{22} - 1,
*              compute r \equiv a (mod GCRY_MLDSA_Q) such that -6283009 <= r <= 6283007.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_mldsa_reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*GCRY_MLDSA_Q;
  return t;
}

/*************************************************
* Name:        _gcry_mldsa_caddq
*
* Description: Add GCRY_MLDSA_Q if input coefficient is negative.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_mldsa_caddq(int32_t a) {
  a += (a >> 31) & GCRY_MLDSA_Q;
  return a;
}

/*************************************************
* Name:        _gcry_mldsa_freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod^+ GCRY_MLDSA_Q.
*
* Arguments:   - int32_t: finite field element a
*
* Returns r.
**************************************************/
int32_t _gcry_mldsa_freeze(int32_t a) {
  a = _gcry_mldsa_reduce32(a);
  a = _gcry_mldsa_caddq(a);
  return a;
}
