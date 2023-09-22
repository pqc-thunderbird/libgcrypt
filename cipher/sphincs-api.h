#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "sphincs-context.h"


/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int _gcry_sphincsplus_seed_keypair(_gcry_sphincsplus_param_t *ctx, unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int _gcry_sphincsplus_keypair(_gcry_sphincsplus_param_t *ctx, unsigned char *pk, unsigned char *sk);

/**
 * Returns an array containing a detached signature.
 */
int _gcry_sphincsplus_signature(_gcry_sphincsplus_param_t *ctx, uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int _gcry_sphincsplus_verify(_gcry_sphincsplus_param_t *ctx, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

#endif
