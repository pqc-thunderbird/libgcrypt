#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>
#include "mlkem-verify-avx2.h"

/*************************************************
 * Name:        _gcry_mlkem_avx2_verify
 *
 * Description: Compare two arrays for equality in constant time.
 *
 * Arguments:   const uint8_t *a: pointer to first byte array
 *              const uint8_t *b: pointer to second byte array
 *              size_t len: length of the byte arrays
 *
 * Returns 0 if the byte arrays are equal, 1 otherwise
 **************************************************/
int
_gcry_mlkem_avx2_verify (const uint8_t *a, const uint8_t *b, size_t len)
{
  size_t i;
  uint64_t r;
  __m256i f, g, h;

  h = _mm256_setzero_si256 ();
  for (i = 0; i < len / 32; i++)
    {
      f = _mm256_loadu_si256 ((__m256i *)&a[32 * i]);
      g = _mm256_loadu_si256 ((__m256i *)&b[32 * i]);
      f = _mm256_xor_si256 (f, g);
      h = _mm256_or_si256 (h, f);
    }
  r = 1 - _mm256_testz_si256 (h, h);

  a += 32 * i;
  b += 32 * i;
  len -= 32 * i;
  for (i = 0; i < len; i++)
    r |= a[i] ^ b[i];

  r = (-r) >> 63;
  return r;
}
