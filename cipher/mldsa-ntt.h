#ifndef _GCRY_MLDSA_NTT_H
#define _GCRY_MLDSA_NTT_H

#include "types.h"
#include "mldsa-params.h"

void _gcry_mldsa_ntt(s32 a[GCRY_MLDSA_N]);

void _gcry_mldsa_invntt_tomont(s32 a[GCRY_MLDSA_N]);

#endif
