#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

typedef enum {
    GCRY_KYBER_512, GCRY_KYBER_768, GCRY_KYBER_1024
} gcry_kyber_param_id;

typedef struct
{
    gcry_kyber_param_id id;
    uint8_t k;
    uint8_t eta1;
    uint16_t polyvec_bytes;
    uint8_t  poly_compressed_bytes;
    uint16_t polyvec_compressed_bytes;
    uint16_t public_key_bytes;
    uint16_t indcpa_secret_key_bytes;
    //uint16_t indcpa_bytes;
    uint16_t secret_key_bytes;
    uint16_t ciphertext_bytes;

} gcry_kyber_param_t;

#if 0
#ifndef KYBER_K
#define KYBER_K 3	/* Change this for different security strengths */
#endif

/* Don't change parameters below this line */
#if   (KYBER_K == 2)
#define KYBER_NAMESPACE(s) pqcrystals_kyber512_ref_##s
#elif (KYBER_K == 3)
#define KYBER_NAMESPACE(s) pqcrystals_kyber768_ref_##s
#elif (KYBER_K == 4)
#define KYBER_NAMESPACE(s) pqcrystals_kyber1024_ref_##s
#else
#error "KYBER_K must be in {2,3,4}"
#endif
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define GCRY_KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define GCRY_KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * GCRY_KYBER_POLYBYTES)

#if 0
#if KYBER_K == 2
#define KYBER_ETA1 3
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 3
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#elif KYBER_K == 4
#define KYBER_ETA1 2
#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)
#endif

#endif

#define KYBER_ETA1_MAX 3
#define KYBER_ETA2 2

// keep this:
#define GCRY_KYBER_INDCPA_MSGBYTES       (GCRY_KYBER_SYMBYTES)
#if (GCRY_KYBER_INDCPA_MSGBYTES != KYBER_N/8)
#error "GCRY_KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!"
#endif
#if 0
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + GCRY_KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*GCRY_KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)
#endif

#endif