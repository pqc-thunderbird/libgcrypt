#ifndef GCRY_SLHDSA_SHA512X4_H
#define GCRY_SLHDSA_SHA512X4_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"
#include <stdint.h>

#ifdef USE_AVX2
#include "immintrin.h"

void _gcry_slhdsa_sha512_inc_init(uint8_t *state);

void _gcry_slhdsa_sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);

void _gcry_slhdsa_sha512x4_seeded(unsigned char *out0,
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