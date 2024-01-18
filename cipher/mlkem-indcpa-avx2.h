#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "mlkem-polyvec-avx2.h"
#include "mlkem-params.h"
#include "g10lib.h"

gcry_err_code_t _gcry_mlkem_avx2_gen_matrix (
    gcry_mlkem_poly *a,
    const uint8_t seed[GCRY_MLKEM_SYMBYTES],
    int transposed,
    const gcry_mlkem_param_t *param);

gcry_err_code_t _gcry_mlkem_avx2_indcpa_enc (
    uint8_t *c,
    const uint8_t *m,
    const uint8_t *pk,
    const uint8_t coins[GCRY_MLKEM_SYMBYTES],
    const gcry_mlkem_param_t *param);

gcry_err_code_t _gcry_mlkem_avx2_indcpa_dec (uint8_t *m,
                                             const uint8_t *c,
                                             const uint8_t *sk,
                                             const gcry_mlkem_param_t *param);

gcry_err_code_t _gcry_mlkem_avx2_indcpa_keypair_derand (
    uint8_t *pk,
    uint8_t *sk,
    const uint8_t coins[GCRY_MLKEM_SYMBYTES],
    const gcry_mlkem_param_t *param);

#endif
