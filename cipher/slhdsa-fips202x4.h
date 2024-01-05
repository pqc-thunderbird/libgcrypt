#ifndef SLHDSA_FIPS204X4_H
#define SLHDSA_FIPS204X4_H

#include "avx2-immintrin-support.h"

#ifdef USE_AVX2
#include <immintrin.h>

void _gcry_slhdsa_shake128x4(unsigned char *out0,
                             unsigned char *out1,
                             unsigned char *out2,
                             unsigned char *out3,
                             unsigned long long outlen,
                             unsigned char *in0,
                             unsigned char *in1,
                             unsigned char *in2,
                             unsigned char *in3,
                             unsigned long long inlen);

void _gcry_slhdsa_shake256x4(unsigned char *out0,
                             unsigned char *out1,
                             unsigned char *out2,
                             unsigned char *out3,
                             unsigned long long outlen,
                             unsigned char *in0,
                             unsigned char *in1,
                             unsigned char *in2,
                             unsigned char *in3,
                             unsigned long long inlen);

void _gcry_slhdsa_KeccakP1600times4_PermuteAll_24rounds(__m256i *states);
#endif
#endif
