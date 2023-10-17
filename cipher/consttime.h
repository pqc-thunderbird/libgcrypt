#ifndef CONSTTIME_H
#define CONSTTIME_H

#include <stddef.h>
#include <stdint.h>


/*************************************************
 * Name:        _gcry_consttime_cmov
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
void _gcry_consttime_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);


#endif /* CIPHER_CONSTTIME_H */
