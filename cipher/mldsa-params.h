#ifndef _GCRY_MLDSA_PARAMS_H
#define _GCRY_MLDSA_PARAMS_H

#include "types.h"

#define GCRY_MLDSA_SEEDBYTES 32
#define GCRY_MLDSA_CRHBYTES 64
#define GCRY_MLDSA_N 256
#define GCRY_MLDSA_Q 8380417
#define GCRY_MLDSA_D 13
#define GCRY_MLDSA_ROOT_OF_UNITY 1753

#define GCRY_MLDSA_POLYT1_PACKEDBYTES 320
#define GCRY_MLDSA_POLYT0_PACKEDBYTES 416

/* pk size (bytes) * 8 */
#define GCRY_MLDSA2_NBITS (1312 * 8)
#define GCRY_MLDSA3_NBITS (1952 * 8)
#define GCRY_MLDSA5_NBITS (2592 * 8)
typedef enum
{
  GCRY_MLDSA2,
  GCRY_MLDSA3,
  GCRY_MLDSA5
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
  u32 gamma1;
  s32 gamma2;
  unsigned char omega;

  /* derived */
  u16 polyvech_packedbytes;
  unsigned char polyw1_packedbytes;
  u16 polyz_packedbytes;
  u16 polyeta_packedbytes;
  u16 public_key_bytes;
  u16 secret_key_bytes;
  u16 signature_bytes;
} gcry_mldsa_param_t;

#endif
