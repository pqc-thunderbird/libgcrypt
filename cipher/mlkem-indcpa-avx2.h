#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-polyvec-avx2.h"
#include "mlkem-params.h"
#include "g10lib.h"

void gen_matrix(polyvec *a, const uint8_t seed[GCRY_MLKEM_SYMBYTES], int transposed, const gcry_mlkem_param_t *param);
void indcpa_keypair(uint8_t *pk,
                    uint8_t *sk);

void indcpa_enc(uint8_t *c,
                const uint8_t *m,
                const uint8_t *pk,
                const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                const gcry_mlkem_param_t *param);

void indcpa_dec(uint8_t *m,
                const uint8_t *c,
                const uint8_t *sk,
                const gcry_mlkem_param_t *param);

gcry_err_code_t indcpa_keypair_derand(uint8_t *pk,
                           uint8_t *sk,
                           const uint8_t coins[GCRY_MLKEM_SYMBYTES],
                           const gcry_mlkem_param_t *param);

#endif
