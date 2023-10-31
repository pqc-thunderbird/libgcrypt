#ifndef _GCRY_MLDSA_PARAMS_H
#define _GCRY_MLDSA_PARAMS_H

#include <stdint.h>

#define GCRY_MLDSA_SEEDBYTES 32
#define GCRY_MLDSA_CRHBYTES 64
#define GCRY_MLDSA_N 256
#define GCRY_MLDSA_Q 8380417
#define GCRY_MLDSA_D 13
#define GCRY_MLDSA_ROOT_OF_UNITY 1753

#define GCRY_MLDSA_POLYT1_PACKEDBYTES  320
#define GCRY_MLDSA_POLYT0_PACKEDBYTES  416

// pk size (bytes) * 8
#define GCRY_MLDSA2_NBITS (1312 * 8)
#define GCRY_MLDSA3_NBITS (1952 * 8)
#define GCRY_MLDSA5_NBITS (2592 * 8)
typedef enum {
    GCRY_MLDSA2, GCRY_MLDSA3, GCRY_MLDSA5
} gcry_mldsa_param_id;

typedef struct
{
    gcry_mldsa_param_id id;

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
} gcry_mldsa_param_t;

#endif
