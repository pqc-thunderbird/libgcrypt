#ifndef SLHDSA_HASH_H
#define SLHDSA_HASH_H

#include <stdint.h>
#include "slhdsa-context.h"
#include "slhdsa-params.h"

void _gcry_slhdsa_initialize_hash_function(_gcry_slhdsa_param_t *ctx);

void _gcry_slhdsa_prf_addr(unsigned char *out, const _gcry_slhdsa_param_t *ctx,
              const uint32_t addr[8]);

void _gcry_slhdsa_gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const _gcry_slhdsa_param_t *ctx);

void _gcry_slhdsa_hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const _gcry_slhdsa_param_t *ctx);

#endif
