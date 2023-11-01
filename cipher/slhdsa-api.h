#ifndef SLHDSA_API_H
#define SLHDSA_API_H

#include <stddef.h>
#include "types.h"

#include "slhdsa-context.h"


/*
 * Generates a slhdsa key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int _gcry_slhdsa_seed_keypair(_gcry_slhdsa_param_t *ctx, unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed);

/*
 * Generates a slhdsa key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int _gcry_slhdsa_keypair(_gcry_slhdsa_param_t *ctx, unsigned char *pk, unsigned char *sk);

/**
 * Returns an array containing a detached signature.
 */
int _gcry_slhdsa_signature(_gcry_slhdsa_param_t *ctx, byte *sig, size_t *siglen,
                          const byte *m, size_t mlen, const byte *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int _gcry_slhdsa_verify(_gcry_slhdsa_param_t *ctx, const byte *sig, size_t siglen,
                       const byte *m, size_t mlen, const byte *pk);

#endif
