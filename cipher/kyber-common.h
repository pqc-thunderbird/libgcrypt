#ifndef CIPHER_KYBER_COMMON_H
#define CIPHER_KYBER_COMMON_H




#include <stdint.h>
#include "kyber_params.h"

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

typedef enum {
    GCRY_KYBER_512, GCRY_KYBER_768, GCRY_KYBER_1024
} gcry_kyber_param;

//#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

//#define crypto_kem_enc KYBER_NAMESPACE(enc)
int kyber_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

//#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);


#endif /* CIPHER_KYBER_COMMON_H */
