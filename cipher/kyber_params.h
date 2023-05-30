#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

typedef enum
{
  GCRY_KYBER_512,
  GCRY_KYBER_768,
  GCRY_KYBER_1024
} gcry_kyber_param_id;

typedef struct
{
  gcry_kyber_param_id id;
  uint8_t k;
  uint8_t eta1;
  uint16_t polyvec_bytes;
  uint8_t poly_compressed_bytes;
  uint16_t polyvec_compressed_bytes;
  uint16_t public_key_bytes;
  uint16_t indcpa_secret_key_bytes;
  uint16_t secret_key_bytes;
  uint16_t ciphertext_bytes;

} gcry_kyber_param_t;


#define GCRY_KYBER_N 256
#define GCRY_KYBER_Q 3329

#define GCRY_KYBER_SYMBYTES 32 /* size in bytes of hashes, and seeds */
#define GCRY_KYBER_SSBYTES 32  /* size in bytes of shared key */

#define GCRY_KYBER_POLYBYTES 384
#define GCRY_KYBER_POLYVECBYTES (KYBER_K * GCRY_KYBER_POLYBYTES)


#define GCRY_KYBER_ETA1_MAX 3
#define GCRY_KYBER_ETA2 2

#define GCRY_KYBER_INDCPA_MSGBYTES (GCRY_KYBER_SYMBYTES)
#if (GCRY_KYBER_INDCPA_MSGBYTES != GCRY_KYBER_N / 8)
#error "GCRY_KYBER_INDCPA_MSGBYTES must be equal to GCRY_KYBER_N/8 bytes!"
#endif


#define GCRY_SHAKE128_RATE 168
#define GCRY_SHAKE256_RATE 136
#define GCRY_SHA3_256_RATE 136
#define GCRY_SHA3_512_RATE 72

#define GCRY_KYBER_XOF_BLOCKBYTES GCRY_SHAKE128_RATE

#endif
