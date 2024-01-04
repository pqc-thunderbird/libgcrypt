#ifndef SLHDSA_THASH_AVX2_H
#define SLHDSA_THASH_AVX2_H

#include "config.h"
#include "avx2-immintrin-support.h"
#include "slhdsa-context.h"
#include "types.h"
#include "g10lib.h"

#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_thash_avx2_sha2(unsigned char *out0,
                                             unsigned char *out1,
                                             unsigned char *out2,
                                             unsigned char *out3,
                                             unsigned char *out4,
                                             unsigned char *out5,
                                             unsigned char *out6,
                                             unsigned char *out7,
                                             const unsigned char *in0,
                                             const unsigned char *in1,
                                             const unsigned char *in2,
                                             const unsigned char *in3,
                                             const unsigned char *in4,
                                             const unsigned char *in5,
                                             const unsigned char *in6,
                                             const unsigned char *in7,
                                             unsigned int inblocks,
                                             const _gcry_slhdsa_param_t *ctx,
                                             uint32_t addrx8[8 * 8]);

gcry_err_code_t _gcry_slhdsa_thash_avx2_shake(unsigned char *out0,
                                              unsigned char *out1,
                                              unsigned char *out2,
                                              unsigned char *out3,
                                              const unsigned char *in0,
                                              const unsigned char *in1,
                                              const unsigned char *in2,
                                              const unsigned char *in3,
                                              unsigned int inblocks,
                                              const _gcry_slhdsa_param_t *ctx,
                                              uint32_t addrx4[4 * 8]);
#endif

#endif
