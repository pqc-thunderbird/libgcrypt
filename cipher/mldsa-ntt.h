#ifndef _GCRY_MLDSA_NTT_H
#define _GCRY_MLDSA_NTT_H

#include <stdint.h>
#include "mldsa-params.h"

void _gcry_mldsa_ntt(int32_t a[GCRY_MLDSA_N]);

void _gcry_mldsa_invntt_tomont(int32_t a[GCRY_MLDSA_N]);

#endif
