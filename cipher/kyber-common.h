#ifndef CIPHER_KYBER_COMMON_H
#define CIPHER_KYBER_COMMON_H




#include <stdint.h>
#include "kyber_params.h"

#include <config.h>
#include "g10lib.h"


gcry_err_code_t _gcry_kyber_kem_keypair_derand(uint8_t *pk,
                       uint8_t *sk,
                       gcry_kyber_param_t* param,
                       uint8_t* coins
                       );


gcry_err_code_t _gcry_kyber_kem_keypair(uint8_t *pk, uint8_t *sk, gcry_kyber_param_t* param);


gcry_err_code_t _gcry_kyber_kem_enc_derand(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk,
                   gcry_kyber_param_t* param,
                   uint8_t * coins
                   );

gcry_err_code_t _gcry_kyber_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, gcry_kyber_param_t* param);

gcry_err_code_t _gcry_kyber_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, gcry_kyber_param_t* param);


#endif /* CIPHER_KYBER_COMMON_H */
