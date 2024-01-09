#ifndef SLHDSA_FORS_H
#define SLHDSA_FORS_H

#include "config.h"
#include "types.h"

#include "slhdsa-context.h"

#include "g10lib.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SLHDSA_FORS_HEIGHT * SLHDSA_FORS_TREES bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_sign (
    byte *sig, byte *pk, const byte *m, const _gcry_slhdsa_param_t *ctx, const u32 fors_addr[8]);

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SLHDSA_FORS_HEIGHT * SLHDSA_FORS_TREES bits.
 */
gcry_err_code_t _gcry_slhdsa_fors_pk_from_sig (
    byte *pk, const byte *sig, const byte *m, const _gcry_slhdsa_param_t *ctx, const u32 fors_addr[8]);

#endif
