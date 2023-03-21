#ifndef CIPHER_KYBER_COMMON_H
#define CIPHER_KYBER_COMMON_H



#include <stdint.h>

int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk);

#endif /* CIPHER_KYBER_COMMON_H */
