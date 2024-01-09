#ifndef SLHDSA_HASH_H
#define SLHDSA_HASH_H

#include "types.h"
#include "avx2-immintrin-support.h"
#include "slhdsa-context.h"

#define SLHDSA_SHA256_BLOCK_BYTES 64
#define SLHDSA_SHA256_OUTPUT_BYTES 32 /* This does not necessarily equal SLHDSA_N */
#define SLHDSA_SHA512_BLOCK_BYTES 128
#define SLHDSA_SHA512_OUTPUT_BYTES 64

gcry_err_code_t _gcry_slhdsa_initialize_hash_function (_gcry_slhdsa_param_t *ctx);

gcry_err_code_t _gcry_slhdsa_prf_addr (byte *out, const _gcry_slhdsa_param_t *ctx, const u32 addr[8]);

gcry_err_code_t _gcry_slhdsa_gen_message_random (byte *R,
                                                 const byte *sk_prf,
                                                 const byte *optrand,
                                                 const byte *m,
                                                 unsigned long long mlen,
                                                 const _gcry_slhdsa_param_t *ctx);

gcry_err_code_t _gcry_slhdsa_hash_message (byte *digest,
                                           u64 *tree,
                                           u32 *leaf_idx,
                                           const byte *R,
                                           const byte *pk,
                                           const byte *m,
                                           unsigned long long mlen,
                                           const _gcry_slhdsa_param_t *ctx);

#ifdef USE_AVX2
gcry_err_code_t _gcry_slhdsa_prf_avx2_sha2 (byte *out0,
                                            byte *out1,
                                            byte *out2,
                                            byte *out3,
                                            byte *out4,
                                            byte *out5,
                                            byte *out6,
                                            byte *out7,
                                            const _gcry_slhdsa_param_t *ctx,
                                            const u32 addrx8[8 * 8]);

void initialize_hash_function_sha_avx2 (_gcry_slhdsa_param_t *ctx);

gcry_err_code_t _gcry_slhdsa_prf_avx2_shake (
    byte *out0, byte *out1, byte *out2, byte *out3, const _gcry_slhdsa_param_t *ctx, const u32 addrx4[4 * 8]);
#endif

#endif
