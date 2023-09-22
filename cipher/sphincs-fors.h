#ifndef SPX_FORS_H
#define SPX_FORS_H

#include "config.h"

#include <stdint.h>

#include "sphincs-params.h"
#include "sphincs-context.h"

#include "g10lib.h"

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
gcry_err_code_t _gcry_sphincsplus_fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const _gcry_sphincsplus_param_t* ctx,
               const uint32_t fors_addr[8]);

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
gcry_err_code_t _gcry_sphincsplus_fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const _gcry_sphincsplus_param_t* ctx,
                      const uint32_t fors_addr[8]);

#endif
