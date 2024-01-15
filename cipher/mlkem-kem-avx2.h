#ifndef KEM_H
#define KEM_H

#include <stdint.h>
#include "mlkem-params-avx2.h"
#include "mlkem-params.h"
#include "g10lib.h"


#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#define CRYPTO_ALGNAME "Kyber512"
#elif (KYBER_K == 3)
#define CRYPTO_ALGNAME "Kyber768"
#elif (KYBER_K == 4)
#define CRYPTO_ALGNAME "Kyber1024"
#endif

gcry_err_code_t _gcry_mlkem_avx2_kem_keypair(uint8_t *pk, uint8_t *sk, const gcry_mlkem_param_t *param);

int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const gcry_mlkem_param_t *param);

int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, const gcry_mlkem_param_t *param);

#endif
