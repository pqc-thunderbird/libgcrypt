#ifndef CIPHER_KYBER_COMMON_H
#define CIPHER_KYBER_COMMON_H




#include <stdint.h>
#include "kyber_params.h"

#include <config.h>
#include "g10lib.h"

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES



gcry_err_code_t crypto_kem_keypair_derand(uint8_t *pk,
                       uint8_t *sk,
                       gcry_kyber_param_t* param,
                       uint8_t* coins
                       );


//#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
gcry_err_code_t crypto_kem_keypair(uint8_t *pk, uint8_t *sk, gcry_kyber_param_t* param);


gcry_err_code_t kyber_kem_enc_derand(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk,
                   gcry_kyber_param_t* param,
                   uint8_t * coins
                   );

//#define crypto_kem_enc KYBER_NAMESPACE(enc)
gcry_err_code_t kyber_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, gcry_kyber_param_t* param);

//#define crypto_kem_dec KYBER_NAMESPACE(dec)
gcry_err_code_t crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, gcry_kyber_param_t* param);


#endif /* CIPHER_KYBER_COMMON_H */
