#ifndef GCRYPT_KYBER_NTT_H
#define GCRYPT_KYBER_NTT_H

#include <stdint.h>
#include "kyber-params.h"


void _gcry_kyber_ntt(int16_t poly[256]);

void _gcry_kyber_invntt(int16_t poly[256]);

void _gcry_kyber_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int zeta, int sign);

#endif /* GCRYPT_KYBER_NTT_H */
