#ifndef SLHDSA_HASH_H
#define SLHDSA_HASH_H

#include "types.h"
#include "avx2-immintrin-support.h"
#include "slhdsa-context.h"

#define SLHDSA_SHA256_BLOCK_BYTES 64
#define SLHDSA_SHA256_OUTPUT_BYTES 32 /* This does not necessarily equal SLHDSA_N */
#define SLHDSA_SHA512_BLOCK_BYTES 128
#define SLHDSA_SHA512_OUTPUT_BYTES 64

gcry_err_code_t _gcry_slhdsa_initialize_hash_function(_gcry_slhdsa_param_t *ctx);

gcry_err_code_t _gcry_slhdsa_prf_addr(unsigned char *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8]);

gcry_err_code_t _gcry_slhdsa_gen_message_random(unsigned char *R,
                                                const unsigned char *sk_prf,
                                                const unsigned char *optrand,
                                                const unsigned char *m,
                                                unsigned long long mlen,
                                                const _gcry_slhdsa_param_t *ctx);

gcry_err_code_t _gcry_slhdsa_hash_message(unsigned char *digest,
                                          u64 *tree,
                                          u32 *leaf_idx,
                                          const unsigned char *R,
                                          const unsigned char *pk,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const _gcry_slhdsa_param_t *ctx);

#ifdef USE_AVX2
void _gcry_slhdsa_prf_avx2_sha2(unsigned char *out0,
                                  unsigned char *out1,
                                  unsigned char *out2,
                                  unsigned char *out3,
                                  unsigned char *out4,
                                  unsigned char *out5,
                                  unsigned char *out6,
                                  unsigned char *out7,
                                  const _gcry_slhdsa_param_t *ctx,
                                  const uint32_t addrx8[8 * 8]);

void _gcry_slhdsa_prf_avx2_shake(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                const _gcry_slhdsa_param_t *ctx,
                const uint32_t addrx4[4*8]);
#endif

#endif
