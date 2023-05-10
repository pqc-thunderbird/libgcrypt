#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "kyber_params.h"
#include "kyber_polyvec.h"

//#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(gcry_kyber_polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
//#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
gcry_error_t indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                    gcry_kyber_param_t* param
                    );

//#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
gcry_error_t indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES],
                gcry_kyber_param_t* param
                );

//#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
gcry_error_t indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                gcry_kyber_param_t* param
                );

#endif
