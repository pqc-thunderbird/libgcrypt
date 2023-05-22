#include <stddef.h>
#include <stdint.h>
#include "kyber_aux.h"
#include "kyber_params.h"


#define MONT -1044 // 2^16 mod q
#define QINV -3327 // q^-1 mod 2^16

int16_t _gcry_kyber_montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);


/*************************************************
 * Name:        verify
 *
 * Description: Compare two arrays for equality in constant time.
 *
 * Arguments:   const uint8_t *a: pointer to first byte array
 *              const uint8_t *b: pointer to second byte array
 *              size_t len:       length of the byte arrays
 *
 * Returns 0 if the byte arrays are equal, 1 otherwise
 **************************************************/
int verify(const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint8_t r = 0;

  for (i = 0; i < len; i++)
    {
      r |= a[i] ^ b[i];
    }

  return (-(uint64_t)r) >> 63;
}

/*************************************************
 * Name:        cmov
 *
 * Description: Copy len bytes from x to r if b is 1;
 *              don't modify x if b is 0. Requires b to be in {0,1};
 *              assumes two's complement representation of negative integers.
 *              Runs in constant time.
 *
 * Arguments:   uint8_t *r:       pointer to output byte array
 *              const uint8_t *x: pointer to input byte array
 *              size_t len:       Amount of bytes to be copied
 *              uint8_t b:        Condition bit; has to be in {0,1}
 **************************************************/
void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
  size_t i;

  b = -b;
  for (i = 0; i < len; i++)
    {
      r[i] ^= b & (r[i] ^ x[i]);
    }
}


/*************************************************
 * Name:        montgomery_reduce
 *
 * Description: Montgomery reduction; given a 32-bit integer a, computes
 *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
 *
 * Arguments:   - int32_t a: input integer to be reduced;
 *                           has to be in {-q2^15,...,q2^15-1}
 *
 * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
 **************************************************/
int16_t montgomery_reduce(int32_t a)
{
  int16_t t;

  t = (int16_t)a * QINV;
  t = (a - (int32_t)t * KYBER_Q) >> 16;
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
int16_t barrett_reduce(int16_t a)
{
  int16_t t;
  const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

  t = ((int32_t)v * a + (1 << 25)) >> 26;
  t *= KYBER_Q;
  return a - t;
}
