#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "mlkem-params.h"
#include "g10lib.h"

gcry_err_code_t _gcry_mlkem_avx2_kem_enc_derand (
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const gcry_mlkem_param_t *param,
    const uint8_t *coins);

gcry_err_code_t _gcry_mlkem_avx2_kem_keypair_derand (
    uint8_t *pk,
    uint8_t *sk,
    const gcry_mlkem_param_t *param,
    const uint8_t *coins);

#endif
