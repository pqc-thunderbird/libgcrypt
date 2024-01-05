#ifndef SLHDSA_FIPS204X4_H
#define SLHDSA_FIPS204X4_H

#include "avx2-immintrin-support.h"
#include <config.h>
#include "types.h"

#ifdef USE_AVX2
#include <immintrin.h>

void _gcry_slhdsa_shake128x4(byte *out0,
                             byte *out1,
                             byte *out2,
                             byte *out3,
                             unsigned long long outlen,
                             byte *in0,
                             byte *in1,
                             byte *in2,
                             byte *in3,
                             unsigned long long inlen);

void _gcry_slhdsa_shake256x4(byte *out0,
                             byte *out1,
                             byte *out2,
                             byte *out3,
                             unsigned long long outlen,
                             byte *in0,
                             byte *in1,
                             byte *in2,
                             byte *in3,
                             unsigned long long inlen);

void _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds(__m256i *states);
#endif
#endif
