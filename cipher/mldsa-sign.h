#ifndef _GCRY_MLDSA_SIGN_H
#define _GCRY_MLDSA_SIGN_H

#include <stddef.h>
#include "types.h"
#include "mldsa-params.h"
#include "mldsa-polyvec.h"
#include "mldsa-poly.h"

void _gcry_mldsa_challenge(gcry_mldsa_poly *c, const byte seed[GCRY_MLDSA_SEEDBYTES]);

gcry_err_code_t _gcry_mldsa_keypair(gcry_mldsa_param_t *params, byte *pk, byte *sk);

gcry_err_code_t _gcry_mldsa_sign(
    gcry_mldsa_param_t *params, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

gcry_err_code_t _gcry_mldsa_verify(
    gcry_mldsa_param_t *params, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);

#endif
