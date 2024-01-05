#ifndef SLHDSA_API_H
#define SLHDSA_API_H

#include <config.h>

#include <stddef.h>
#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/*
 * Generates a slhdsa key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
gcry_err_code_t _gcry_slhdsa_seed_keypair(_gcry_slhdsa_param_t *ctx,
                                          byte *pk,
                                          byte *sk,
                                          const byte *seed);

/*
 * Generates a slhdsa key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
gcry_err_code_t _gcry_slhdsa_keypair(_gcry_slhdsa_param_t *ctx, byte *pk, byte *sk);

/**
 * Returns an array containing a detached signature.
 */
gcry_err_code_t _gcry_slhdsa_signature(
    _gcry_slhdsa_param_t *ctx, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
gcry_err_code_t _gcry_slhdsa_verify(
    _gcry_slhdsa_param_t *ctx, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);

#endif
