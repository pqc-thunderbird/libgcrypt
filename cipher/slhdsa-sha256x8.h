#ifndef GCRY_SLHDSA_SHA256X8_H
#define GCRY_SLHDSA_SHA256X8_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"

#ifdef USE_AVX2
#include "immintrin.h"
#include <stdint.h>


void _gcry_slhdsa_sha256x8_seeded(byte *out0,
                                  byte *out1,
                                  byte *out2,
                                  byte *out3,
                                  byte *out4,
                                  byte *out5,
                                  byte *out6,
                                  byte *out7,
                                  const byte *seed,
                                  unsigned long long seedlen,
                                  const byte *in0,
                                  const byte *in1,
                                  const byte *in2,
                                  const byte *in3,
                                  const byte *in4,
                                  const byte *in5,
                                  const byte *in6,
                                  const byte *in7,
                                  unsigned long long inlen);


void _gcry_slhdsa_sha256_inc_init(byte *state);

void _gcry_slhdsa_sha256_inc_blocks(byte *state, const byte *in, size_t inblocks);

#endif
#endif
