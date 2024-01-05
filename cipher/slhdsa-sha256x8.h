#ifndef GCRY_SLHDSA_SHA256X8_H
#define GCRY_SLHDSA_SHA256X8_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"

#ifdef USE_AVX2
#include "immintrin.h"
#include <stdint.h>


void _gcry_slhdsa_sha256x8_seeded(unsigned char *out0,
                     unsigned char *out1,
                     unsigned char *out2,
                     unsigned char *out3,
                     unsigned char *out4,
                     unsigned char *out5,
                     unsigned char *out6,
                     unsigned char *out7,
                     const unsigned char *seed,
                     unsigned long long seedlen,
                     const unsigned char *in0,
                     const unsigned char *in1,
                     const unsigned char *in2,
                     const unsigned char *in3,
                     const unsigned char *in4,
                     const unsigned char *in5,
                     const unsigned char *in6,
                     const unsigned char *in7,
                     unsigned long long inlen);



void _gcry_slhdsa_sha256_inc_init(uint8_t *state);

void _gcry_slhdsa_sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);

#endif
#endif
