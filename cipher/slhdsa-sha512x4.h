#ifndef GCRY_SLHDSA_SHA512X4_H
#define GCRY_SLHDSA_SHA512X4_H

#include "avx2-immintrin-support.h"
#include "slhdsa-hash.h"
#include <stdint.h>

#ifdef USE_AVX2
#include "immintrin.h"

void _gcry_slhdsa_sha512_inc_init(byte *state);

void _gcry_slhdsa_sha512_inc_blocks(byte *state, const byte *in, size_t inblocks);

gcry_err_code_t _gcry_slhdsa_sha512x4_seeded(byte *out0,
                                             byte *out1,
                                             byte *out2,
                                             byte *out3,
                                             const byte *seed,
                                             unsigned long long seedlen,
                                             const byte *in0,
                                             const byte *in1,
                                             const byte *in2,
                                             const byte *in3,
                                             unsigned long long inlen);

#endif
#endif