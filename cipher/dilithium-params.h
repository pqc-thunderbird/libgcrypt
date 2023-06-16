#ifndef _GCRY_DILITHIUM_PARAMS_H
#define _GCRY_DILITHIUM_PARAMS_H

#include <stdint.h>

#define GCRY_DILITHIUM_SEEDBYTES 32
#define GCRY_DILITHIUM_CRHBYTES 64
#define GCRY_DILITHIUM_N 256
#define GCRY_DILITHIUM_Q 8380417
#define GCRY_DILITHIUM_D 13
#define GCRY_DILITHIUM_ROOT_OF_UNITY 1753

#define GCRY_DILITHIUM_POLYT1_PACKEDBYTES  320
#define GCRY_DILITHIUM_POLYT0_PACKEDBYTES  416

// pk size (bytes) * 8
#define GCRY_DILITHIUM2_NBITS (1312 * 8)
#define GCRY_DILITHIUM3_NBITS (1952 * 8)
#define GCRY_DILITHIUM5_NBITS (2592 * 8)
typedef enum {
    GCRY_DILITHIUM2, GCRY_DILITHIUM3, GCRY_DILITHIUM5
} gcry_dilithium_param_id;

typedef struct
{
    gcry_dilithium_param_id id;

    /* parameters */
    unsigned char k;
    unsigned char l;
    unsigned char eta;
    unsigned char tau;
    unsigned char beta;
    uint32_t gamma1;
    int32_t gamma2;
    unsigned char omega;

    /* derived */
    uint16_t polyvech_packedbytes;
    unsigned char polyw1_packedbytes;
    uint16_t polyz_packedbytes;
    uint16_t polyeta_packedbytes;
    uint16_t public_key_bytes;
    uint16_t secret_key_bytes;
    uint16_t signature_bytes;
} gcry_dilithium_param_t;

#endif
