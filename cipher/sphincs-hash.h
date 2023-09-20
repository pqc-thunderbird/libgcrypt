#ifndef SPX_HASH_H
#define SPX_HASH_H

#include <stdint.h>
#include "sphincs-context.h"
#include "sphincs-params.h"

void _gcry_sphincsplus_initialize_hash_function(_gcry_sphincsplus_param_t *ctx);

void _gcry_sphincsplus_prf_addr(unsigned char *out, const _gcry_sphincsplus_param_t *ctx,
              const uint32_t addr[8]);

void _gcry_sphincsplus_gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const _gcry_sphincsplus_param_t *ctx);

void _gcry_sphincsplus_hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_sphincsplus_param_t *ctx);

#endif
