#ifndef _GCRY_MLDSA_AVX2_SIGN_H
#define _GCRY_MLDSA_AVX2_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "mldsa-params.h"
#include "mldsa-polyvec-avx2.h"
#include "mldsa-poly-avx2.h"

gcry_err_code_t _gcry_mldsa_avx2_keypair(gcry_mldsa_param_t *params, byte *pk, byte *sk);

gcry_err_code_t _gcry_mldsa_avx2_sign(
    gcry_mldsa_param_t *params, byte *sig, size_t *siglen, const byte *m, size_t mlen, const byte *sk);

gcry_err_code_t _gcry_mldsa_avx2_verify(
    gcry_mldsa_param_t *params, const byte *sig, size_t siglen, const byte *m, size_t mlen, const byte *pk);

#endif
