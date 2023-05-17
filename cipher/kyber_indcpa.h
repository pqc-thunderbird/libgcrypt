#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "kyber_params.h"
#include "kyber_polyvec.h"

//#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(gcry_kyber_polyvec *a, const uint8_t seed[GCRY_KYBER_SYMBYTES], int transposed, gcry_kyber_param_t const* param);
//#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
gcry_error_t indcpa_keypair(uint8_t * pk,
                    uint8_t* sk,
                    gcry_kyber_param_t const* param,
                    uint8_t* coins
                    );

//#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
gcry_error_t indcpa_enc(uint8_t* c,
                const uint8_t* m,
                const uint8_t* pk,
                const uint8_t coins[GCRY_KYBER_SYMBYTES],
                gcry_kyber_param_t const* param
                );

//#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
gcry_error_t indcpa_dec(uint8_t *  m,
                const uint8_t* c,
                const uint8_t* sk,
                gcry_kyber_param_t const* param
                );

#endif
