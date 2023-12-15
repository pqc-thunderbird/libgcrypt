#ifndef SLHDSA_HASH_H
#define SLHDSA_HASH_H

#include "types.h"
#include "avx2-immintrin-support.h"
#include "slhdsa-context.h"

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
void _gcry_slhdsa_prf_addrx8_sha2(unsigned char *out0,
                                  unsigned char *out1,
                                  unsigned char *out2,
                                  unsigned char *out3,
                                  unsigned char *out4,
                                  unsigned char *out5,
                                  unsigned char *out6,
                                  unsigned char *out7,
                                  const _gcry_slhdsa_param_t *ctx,
                                  const uint32_t addrx8[8 * 8]);
#endif

#endif
