#ifndef SPX_WOTS_H
#define SPX_WOTS_H

#include <stdint.h>

#include "sphincs-params.h"
#include "sphincs-context.h"

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void _gcry_sphincsplus_wots_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const _gcry_sphincsplus_param_t *ctx, uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
void chain_lengths(const _gcry_sphincsplus_param_t *ctx, unsigned int *lengths, const unsigned char *msg);

#endif
