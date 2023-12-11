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


#define L 4 // TODO: Assembler
#define ETA 2

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#endif
