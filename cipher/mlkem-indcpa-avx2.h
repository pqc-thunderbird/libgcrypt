#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-polyvec-avx2.h"
#include "mlkem-params.h"
#include "g10lib.h"

void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                const gcry_mlkem_param_t *param);

void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                const gcry_mlkem_param_t *param);

gcry_err_code_t indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES],
                           const gcry_mlkem_param_t *param);

#endif
