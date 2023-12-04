#ifndef PARAMS_H
#define PARAMS_H

#include "mldsa-config-avx2.h"

#define GCRY_MLDSA_SEEDBYTES 32
#define GCRY_MLDSA_CRHBYTES 64
#define GCRY_MLDSA_TRBYTES 64
#define GCRY_MLDSA_N 256
#define GCRY_MLDSA_Q 8380417
#define GCRY_MLDSA_D 13
#define ROOT_OF_UNITY 1753
#define GCRY_MLDSA_POLYT1_PACKEDBYTES  320
#define GCRY_MLDSA_POLYT0_PACKEDBYTES  416


#if DILITHIUM_MODE == 2
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((GCRY_MLDSA_Q-1)/88)
#define OMEGA 80
#define CTILDEBYTES 32

#elif DILITHIUM_MODE == 3
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((GCRY_MLDSA_Q-1)/32)
#define OMEGA 55
#define CTILDEBYTES 48

#elif DILITHIUM_MODE == 5
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 120
#define GAMMA1 (1 << 19)
#define GAMMA2 ((GCRY_MLDSA_Q-1)/32)
#define OMEGA 75
#define CTILDEBYTES 64

#endif

#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (GCRY_MLDSA_Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (GCRY_MLDSA_Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (GCRY_MLDSA_SEEDBYTES + K*GCRY_MLDSA_POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (2*GCRY_MLDSA_SEEDBYTES \
                               + GCRY_MLDSA_TRBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*GCRY_MLDSA_POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
