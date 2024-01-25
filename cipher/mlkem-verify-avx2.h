#ifndef GCRYPT_MLKEM_VERIFY_AVX2_H
#define GCRYPT_MLKEM_VERIFY_AVX2_H

#include <stddef.h>
#include <stdint.h>

int _gcry_mlkem_avx2_verify (const uint8_t *a, const uint8_t *b, size_t len);

#endif
