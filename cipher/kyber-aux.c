#include <stddef.h>
#include <stdint.h>
#include "kyber-aux.h"
#include "kyber-params.h"


#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16


/*************************************************
 * Name:        _gcry_kyber_montgomery_reduce
 *
 * Description: Montgomery reduction; given a 32-bit integer a, computes
 *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * Arguments:   - int32_t a: input integer to be reduced;
 *                           has to be in {-q2^15,...,q2^15-1}
 *
 * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 **************************************************/
int16_t
_gcry_kyber_montgomery_reduce (int32_t a)
{
  int16_t t;

  t = (int16_t)a * QINV;
  t = (a - (int32_t)t * GCRY_KYBER_Q) >> 16;
  return t;
}

/*************************************************
 * Name:        barrett_reduce
 *
 * Description: Barrett reduction; given a 16-bit integer a, computes
 *              centered representative congruent to a mod q in
 *{-(q-1)/2,...,(q-1)/2}
 *
 * Arguments:   - int16_t a: input integer to be reduced
 *
 * Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
 **************************************************/
int16_t
_gcry_kyber_barrett_reduce (int16_t a)
{
  int16_t t;
  const int16_t v = ((1 << 26) + GCRY_KYBER_Q / 2) / GCRY_KYBER_Q;

  t = ((int32_t)v * a + (1 << 25)) >> 26;
  t *= GCRY_KYBER_Q;
  return a - t;
}
