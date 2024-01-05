#ifndef SLHDSA_THASH_H
#define SLHDSA_THASH_H

#include "config.h"
#include "slhdsa-context.h"
#include "types.h"
#include "g10lib.h"
#include "avx2-immintrin-support.h"

gcry_err_code_t _gcry_slhdsa_thash(
    byte *out, const byte *in, unsigned int inblocks, const _gcry_slhdsa_param_t *ctx, u32 addr[8]);


#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_thash_avx2_sha2(byte *out0,
                                             byte *out1,
                                             byte *out2,
                                             byte *out3,
                                             byte *out4,
                                             byte *out5,
                                             byte *out6,
                                             byte *out7,
                                             const byte *in0,
                                             const byte *in1,
                                             const byte *in2,
                                             const byte *in3,
                                             const byte *in4,
                                             const byte *in5,
                                             const byte *in6,
                                             const byte *in7,
                                             unsigned int inblocks,
                                             const _gcry_slhdsa_param_t *ctx,
                                             u32 addrx8[8 * 8]);

gcry_err_code_t _gcry_slhdsa_thash_avx2_shake(byte *out0,
                                              byte *out1,
                                              byte *out2,
                                              byte *out3,
                                              const byte *in0,
                                              const byte *in1,
                                              const byte *in2,
                                              const byte *in3,
                                              unsigned int inblocks,
                                              const _gcry_slhdsa_param_t *ctx,
                                              u32 addrx4[4 * 8]);
#endif

#endif
