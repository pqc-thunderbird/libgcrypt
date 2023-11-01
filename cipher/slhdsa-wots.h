#ifndef SLHDSA_WOTS_H
#define SLHDSA_WOTS_H

#include <config.h>

#include "types.h"

#include "slhdsa-params.h"
#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
gcry_err_code_t _gcry_slhdsa_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const _gcry_slhdsa_param_t *ctx, u32 addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
void _gcry_slhdsa_chain_lengths(const _gcry_slhdsa_param_t *ctx, unsigned int *lengths, const unsigned char *msg);

#endif
