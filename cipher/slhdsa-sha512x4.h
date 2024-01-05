#ifndef GCRY_SLHDSA_SHA512X4_H
#define GCRY_SLHDSA_SHA512X4_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"

#ifdef USE_AVX2
#include "immintrin.h"
#include <stdint.h>

typedef struct SHA512state4x
{
  __m256i s[8];
  unsigned char msgblocks[4 * 128];
  int datalen;
  unsigned long long msglen;
} sha512ctx4x;

void sha512_inc_init(uint8_t *state);

void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);

void sha512x4_seeded(unsigned char *out0,
                     unsigned char *out1,
                     unsigned char *out2,
                     unsigned char *out3,
                     const unsigned char *seed,
                     unsigned long long seedlen,
                     const unsigned char *in0,
                     const unsigned char *in1,
                     const unsigned char *in2,
                     const unsigned char *in3,
                     unsigned long long inlen);

#endif
#endif